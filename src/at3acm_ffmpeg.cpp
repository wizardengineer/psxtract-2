// ATRAC3 to WAV conversion using the ffmpeg API (POSIX builds).
// Links against libavformat, libavcodec, libswresample, libavutil.

#include "at3acm.h"

extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswresample/swresample.h>
#include <libavutil/channel_layout.h>
}

#include <cstdio>
#include <cstdint>
#include <cstring>

void findAt3Driver(LPHACMDRIVERID lpHadid) {
    if (!lpHadid) return;
    const AVCodec* c = avcodec_find_decoder(AV_CODEC_ID_ATRAC3);
    if (!c) c = avcodec_find_decoder(AV_CODEC_ID_ATRAC3P);
    *lpHadid = c ? (HACMDRIVERID)1 : nullptr;
}

bool isAtrac3CodecAvailable() {
    return avcodec_find_decoder(AV_CODEC_ID_ATRAC3) != nullptr
        || avcodec_find_decoder(AV_CODEC_ID_ATRAC3P) != nullptr;
}

// Write a 44-byte WAV header for 16-bit stereo 44100 Hz PCM.
static void write_wav_header(FILE* f, uint32_t data_size) {
    uint32_t file_size    = 36 + data_size;
    uint32_t fmt_size     = 16;
    uint16_t audio_fmt    = 1;       // PCM
    uint16_t channels     = 2;
    uint32_t sample_rate  = 44100;
    uint32_t byte_rate    = 44100 * 4;
    uint16_t block_align  = 4;
    uint16_t bits         = 16;

    fwrite("RIFF", 1, 4, f);
    fwrite(&file_size, 4, 1, f);
    fwrite("WAVE", 1, 4, f);
    fwrite("fmt ", 1, 4, f);
    fwrite(&fmt_size, 4, 1, f);
    fwrite(&audio_fmt, 2, 1, f);
    fwrite(&channels, 2, 1, f);
    fwrite(&sample_rate, 4, 1, f);
    fwrite(&byte_rate, 4, 1, f);
    fwrite(&block_align, 2, 1, f);
    fwrite(&bits, 2, 1, f);
    fwrite("data", 1, 4, f);
    fwrite(&data_size, 4, 1, f);
}

int convertAt3ToWav(const char* input, const char* output,
                    HACMDRIVERID at3hadid) {
    (void)at3hadid;

    AVFormatContext* fmt_ctx = nullptr;
    AVCodecContext*  dec_ctx = nullptr;
    SwrContext*      swr     = nullptr;
    AVPacket*        pkt     = nullptr;
    AVFrame*         frame   = nullptr;
    FILE*            wav     = nullptr;
    uint8_t*         buf     = nullptr;
    int              buf_cap = 0;
    uint32_t         pcm_bytes = 0;
    int              stream_idx = -1;
    int              rc = 1;           // assume failure

    // --- open input ---
    if (avformat_open_input(&fmt_ctx, input, nullptr, nullptr) < 0)
        goto done;
    if (avformat_find_stream_info(fmt_ctx, nullptr) < 0)
        goto done;

    stream_idx = av_find_best_stream(
        fmt_ctx, AVMEDIA_TYPE_AUDIO, -1, -1, nullptr, 0);
    if (stream_idx < 0) goto done;

    // --- open decoder ---
    {
        AVCodecParameters* par = fmt_ctx->streams[stream_idx]->codecpar;
        const AVCodec* codec = avcodec_find_decoder(par->codec_id);
        if (!codec) goto done;
        dec_ctx = avcodec_alloc_context3(codec);
        if (!dec_ctx) goto done;
        if (avcodec_parameters_to_context(dec_ctx, par) < 0) goto done;
        if (avcodec_open2(dec_ctx, codec, nullptr) < 0) goto done;
    }

    // --- set up resampler -> 44100 Hz, stereo, s16le ---
    {
        AVChannelLayout out_ch = AV_CHANNEL_LAYOUT_STEREO;
        if (swr_alloc_set_opts2(&swr,
                &out_ch,           AV_SAMPLE_FMT_S16, 44100,
                &dec_ctx->ch_layout, dec_ctx->sample_fmt,
                dec_ctx->sample_rate,
                0, nullptr) < 0)
            goto done;
    }
    if (swr_init(swr) < 0) goto done;

    // --- open output WAV (placeholder header, updated at end) ---
    wav = fopen(output, "wb");
    if (!wav) goto done;
    write_wav_header(wav, 0);

    pkt   = av_packet_alloc();
    frame = av_frame_alloc();
    if (!pkt || !frame) goto done;

    // --- decode / resample / write loop ---
    while (av_read_frame(fmt_ctx, pkt) >= 0) {
        if (pkt->stream_index != stream_idx) {
            av_packet_unref(pkt);
            continue;
        }
        avcodec_send_packet(dec_ctx, pkt);
        av_packet_unref(pkt);

        while (avcodec_receive_frame(dec_ctx, frame) >= 0) {
            int max_out = swr_get_out_samples(swr, frame->nb_samples);
            int need = max_out * 4;          // stereo 16-bit = 4 B/sample
            if (need > buf_cap) {
                av_freep(&buf);
                buf = (uint8_t*)av_malloc(need);
                if (!buf) goto done;
                buf_cap = need;
            }
            int n = swr_convert(swr, &buf, max_out,
                (const uint8_t**)frame->extended_data, frame->nb_samples);
            if (n > 0) {
                int bytes = n * 4;
                fwrite(buf, 1, bytes, wav);
                pcm_bytes += bytes;
            }
        }
    }

    // flush decoder
    avcodec_send_packet(dec_ctx, nullptr);
    while (avcodec_receive_frame(dec_ctx, frame) >= 0) {
        int max_out = swr_get_out_samples(swr, frame->nb_samples);
        int need = max_out * 4;
        if (need > buf_cap) {
            av_freep(&buf);
            buf = (uint8_t*)av_malloc(need);
            if (!buf) goto done;
            buf_cap = need;
        }
        int n = swr_convert(swr, &buf, max_out,
            (const uint8_t**)frame->extended_data, frame->nb_samples);
        if (n > 0) {
            int bytes = n * 4;
            fwrite(buf, 1, bytes, wav);
            pcm_bytes += bytes;
        }
    }

    // flush resampler
    {
        int remain = swr_get_out_samples(swr, 0);
        if (remain > 0) {
            int need = remain * 4;
            if (need > buf_cap) {
                av_freep(&buf);
                buf = (uint8_t*)av_malloc(need);
                if (!buf) goto done;
                buf_cap = need;
            }
            int n = swr_convert(swr, &buf, remain, nullptr, 0);
            if (n > 0) {
                int bytes = n * 4;
                fwrite(buf, 1, bytes, wav);
                pcm_bytes += bytes;
            }
        }
    }

    // rewrite header with actual data size
    fseek(wav, 0, SEEK_SET);
    write_wav_header(wav, pcm_bytes);
    rc = 0;

done:
    av_freep(&buf);
    av_frame_free(&frame);
    av_packet_free(&pkt);
    swr_free(&swr);
    avcodec_free_context(&dec_ctx);
    if (fmt_ctx) avformat_close_input(&fmt_ctx);
    if (wav) fclose(wav);
    return rc;
}
