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

#else // POSIX

typedef void* HACMDRIVERID;
typedef HACMDRIVERID* LPHACMDRIVERID;

#ifdef HAVE_FFMPEG
// Implemented in at3acm_ffmpeg.cpp (links against libav*)
void findAt3Driver(LPHACMDRIVERID lpHadid);
bool isAtrac3CodecAvailable();
int convertAt3ToWav(const char* input, const char* output, HACMDRIVERID at3hadid);
#else
// Stubs — built without ffmpeg, no audio conversion available
static inline void findAt3Driver(LPHACMDRIVERID lpHadid) {
    if (lpHadid) *lpHadid = nullptr;
}
static inline bool isAtrac3CodecAvailable() { return false; }
static inline int convertAt3ToWav(const char* input, const char* output,
                                  HACMDRIVERID at3hadid) {
    (void)input; (void)output; (void)at3hadid;
    return -1;
}
#endif

#endif
