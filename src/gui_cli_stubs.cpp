// CLI stubs for GUI functions on POSIX platforms.
// Provides simple console-based alternatives to the Win32 GUI.

#include "gui.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static bool g_guiMode = false;
static FILE* g_logFile = NULL;

void setGUIMode(bool enabled) {
    g_guiMode = enabled;
}

bool isGUIMode() {
    return g_guiMode;
}

int gui_printf_impl(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (g_guiMode && g_logFile) {
        fprintf(g_logFile, "%s", buffer);
        fflush(g_logFile);
    } else {
        fprintf(stdout, "%s", buffer);
        fflush(stdout);
    }

    return result;
}

int gui_log_printf(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    fprintf(stdout, "%s", buffer);
    fflush(stdout);

    return result;
}

bool gui_prompt(const char* message, const char* title) {
    (void)title;
    fprintf(stdout, "%s (y/N): ", message);
    fflush(stdout);

    char input[10];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        char response = input[0];
        return (response == 'y' || response == 'Y');
    }
    return false;
}

int gui_select_option(const char* title, const char* message, const char* options[], int option_count) {
    (void)title;
    fprintf(stdout, "\n%s\n", message);

    for (int i = 0; i < option_count; i++) {
        fprintf(stdout, "  %d) %s\n", i + 1, options[i]);
    }

    fprintf(stdout, "\nEnter your choice (1-%d): ", option_count);
    fflush(stdout);

    int choice = 0;
    char input[16];

    if (fgets(input, sizeof(input), stdin)) {
        choice = atoi(input);
    }

    if (choice < 1 || choice > option_count) {
        fprintf(stdout, "Invalid choice. Using first option: %s\n", options[0]);
        return 0;
    }

    fprintf(stdout, "Selected: %s\n\n", options[choice - 1]);
    return choice - 1;
}

int gui_create_selection_dialog(const char* title, const char* message, const char* options[], int option_count) {
    return gui_select_option(title, message, options, option_count);
}

void openLogFileForWriting(const char* pbpPath) {
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }

    // Extract filename from path
    const char* filename = strrchr(pbpPath, '/');
    if (!filename) {
        filename = strrchr(pbpPath, '\\');
    }
    filename = filename ? filename + 1 : pbpPath;

    // Build log filename: strip extension, add .log
    char logFileName[512];
    strncpy(logFileName, filename, sizeof(logFileName) - 5);
    logFileName[sizeof(logFileName) - 5] = '\0';
    char* dot = strrchr(logFileName, '.');
    if (dot) {
        *dot = '\0';
    }
    strcat(logFileName, ".log");

    g_logFile = fopen(logFileName, "w");
}

int showGUI() {
    fprintf(stderr, "ERROR: GUI mode is not available on this platform.\n");
    fprintf(stderr, "Usage: psxtract [-c] <EBOOT.PBP> [DOCUMENT.DAT] [KEYS.BIN]\n");
    return 1;
}

void logToGUI(const char* message) {
    fprintf(stdout, "%s", message);
    fflush(stdout);
}

void enableExtractButton(bool enabled) {
    (void)enabled;
}

bool extractAndRunAtrac3Installer() {
    return false;
}

void showAtrac3CodecWarning() {
    // No-op on POSIX
}
