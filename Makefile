# Makefile for psxtract
# Supports native builds on macOS/Linux and cross-compilation for Windows

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME_S),Windows)
  BUILD_PLATFORM := windows
else ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
  BUILD_PLATFORM := windows
else ifeq ($(findstring MSYS,$(UNAME_S)),MSYS)
  BUILD_PLATFORM := windows
else
  BUILD_PLATFORM := posix
endif

SRCDIR = src
OBJDIR = obj

# Common C source files (portable)
C_SOURCES = $(SRCDIR)/libkirk/AES.c $(SRCDIR)/libkirk/amctrl.c $(SRCDIR)/libkirk/bn.c $(SRCDIR)/libkirk/DES.c $(SRCDIR)/libkirk/ec.c $(SRCDIR)/libkirk/kirk_engine.c $(SRCDIR)/libkirk/SHA1.c

ifeq ($(BUILD_PLATFORM),posix)
  # --- Native POSIX build (macOS / Linux) ---
  CC = cc
  CXX = c++
  TARGET = psxtract

  CXXFLAGS = -std=c++11 -O2 -Wall -D_CRT_SECURE_NO_WARNINGS -DPOSIX_BUILD
  CFLAGS = -O2 -Wall -DPOSIX_BUILD
  LDFLAGS =
  LIBS =

  # Detect ffmpeg development libraries via pkg-config
  FFMPEG_CFLAGS := $(shell pkg-config --cflags libavformat libavcodec libswresample libavutil 2>/dev/null)
  FFMPEG_LIBS   := $(shell pkg-config --libs   libavformat libavcodec libswresample libavutil 2>/dev/null)

  # Exclude gui.cpp and at3acm.cpp; include gui_cli_stubs.cpp instead
  CPP_SOURCES = $(SRCDIR)/psxtract.cpp $(SRCDIR)/crypto.cpp $(SRCDIR)/cdrom.cpp $(SRCDIR)/lz.cpp $(SRCDIR)/utils.cpp $(SRCDIR)/md5_verify.cpp $(SRCDIR)/cue_resources.cpp $(SRCDIR)/gui_cli_stubs.cpp

  ifneq ($(FFMPEG_LIBS),)
    CXXFLAGS += $(FFMPEG_CFLAGS) -DHAVE_FFMPEG
    LIBS     += $(FFMPEG_LIBS)
    CPP_SOURCES += $(SRCDIR)/at3acm_ffmpeg.cpp
  endif

  CPP_OBJECTS = $(CPP_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
  C_OBJECTS = $(C_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
  OBJECTS = $(CPP_OBJECTS) $(C_OBJECTS)

else
  # --- Windows cross-compilation (MinGW) ---
  CC = i686-w64-mingw32-gcc
  CXX = i686-w64-mingw32-g++
  WINDRES = i686-w64-mingw32-windres
  TARGET = psxtract.exe

  CXXFLAGS = -std=c++11 -O2 -Wall -D_CRT_SECURE_NO_WARNINGS
  CFLAGS = -O2 -Wall
  LDFLAGS = -static-libgcc -static-libstdc++
  LIBS = -lkernel32 -luser32 -ladvapi32 -lmsacm32 -lgdi32 -lcomctl32 -lcomdlg32 -lshell32 -lole32 -lshlwapi

  CPP_SOURCES = $(SRCDIR)/psxtract.cpp $(SRCDIR)/crypto.cpp $(SRCDIR)/cdrom.cpp $(SRCDIR)/lz.cpp $(SRCDIR)/utils.cpp $(SRCDIR)/md5_verify.cpp $(SRCDIR)/at3acm.cpp $(SRCDIR)/gui.cpp $(SRCDIR)/cue_resources.cpp

  CPP_OBJECTS = $(CPP_SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
  C_OBJECTS = $(C_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
  RESOURCE_OBJECTS = $(OBJDIR)/psxtract_resources.o $(OBJDIR)/atrac3_resources.o
  OBJECTS = $(CPP_OBJECTS) $(C_OBJECTS) $(RESOURCE_OBJECTS)
endif

# Create obj directory structure
OBJDIRS = $(OBJDIR) $(OBJDIR)/libkirk

all: $(TARGET)

$(TARGET): $(OBJDIRS) $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "Build complete: $(TARGET)"

# Create directories
$(OBJDIRS):
	mkdir -p $@

# Compile C++ files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile C files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Windows resource compilation (only used for Windows builds)
$(OBJDIR)/psxtract_resources.o: src/psxtract.rc
	$(WINDRES) $< -o $@

$(OBJDIR)/atrac3_resources.o: src/atrac3_resources.rc
	$(WINDRES) $< -o $@

# Explicit Windows cross-compile target
windows:
	$(MAKE) BUILD_PLATFORM=windows

clean:
	rm -rf $(OBJDIR) psxtract psxtract.exe

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/ 2>/dev/null || echo "Note: Could not install to /usr/local/bin (may need sudo)"

release: $(TARGET)
	@echo "Creating release package..."
	mkdir -p release/psxtract-2
	cp $(TARGET) release/psxtract-2/
	cp -r cue release/psxtract-2/ 2>/dev/null || true
	cp README.md release/psxtract-2/ 2>/dev/null || true
	cp LICENSE release/psxtract-2/ 2>/dev/null || true
	cd release && zip -r ../psxtract-2.zip psxtract-2 && cd ..
	rm -rf release
	@echo "Release package created: psxtract-2.zip"
	@echo "Contents:"
	@unzip -l psxtract-2.zip

.PHONY: all clean install release windows
