#pragma once

#ifdef _WIN32

#include <windows.h>
#include <mmreg.h>
#include <mmsystem.h>
#include <msacm.h>

// Function to find ATRAC3 driver
void findAt3Driver(LPHACMDRIVERID lpHadid);

// Function to check if ATRAC3 driver is available
bool isAtrac3CodecAvailable();

// Function to convert ATRAC3 to WAV using ACM with pre-found driver
int convertAt3ToWav(const char* input, const char* output, HACMDRIVERID at3hadid);

#else // POSIX — use ffmpeg for ATRAC3 decoding

#include <cstdio>
#include <cstdlib>
#include <cstring>

typedef void* HACMDRIVERID;
typedef HACMDRIVERID* LPHACMDRIVERID;

static inline bool ffmpeg_available() {
    FILE* fp = popen("ffmpeg -version 2>/dev/null", "r");
    if (!fp) return false;
    char buf[128];
    bool found = (fgets(buf, sizeof(buf), fp) != nullptr);
    pclose(fp);
    return found;
}

static inline void findAt3Driver(LPHACMDRIVERID lpHadid) {
    if (lpHadid)
        *lpHadid = ffmpeg_available() ? (HACMDRIVERID)(void*)1 : nullptr;
}

static inline bool isAtrac3CodecAvailable() {
    return ffmpeg_available();
}

static inline int convertAt3ToWav(
    const char* input, const char* output, HACMDRIVERID at3hadid
) {
    (void)at3hadid;
    char cmd[1024];
    snprintf(
        cmd, sizeof(cmd),
        "ffmpeg -y -i \"%s\" -acodec pcm_s16le -ar 44100 -ac 2 \"%s\""
        " 2>/dev/null",
        input, output
    );
    int ret = system(cmd);
    return (ret == 0) ? 0 : 1;
}

#endif
