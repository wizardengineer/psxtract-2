#include "md5_verify.h"
#include "cue_resources.h"
#include "gui.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#endif


// MD5 hash calculation function
bool calculate_md5(const char* filename, char* md5_string)
{
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[1024];
    DWORD cbRead = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 16;

    hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    while (ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return false;
        }
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return false;
    }

    // Convert to hex string
    for (DWORD i = 0; i < cbHash; i++)
    {
        sprintf(&md5_string[i * 2], "%02x", rgbHash[i]);
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CloseHandle(hFile);

    return true;

#elif defined(__APPLE__)
    FILE* f = fopen(filename, "rb");
    if (!f) {
        return false;
    }

    CC_MD5_CTX ctx;
    CC_MD5_Init(&ctx);

    unsigned char buf[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), f)) > 0) {
        CC_MD5_Update(&ctx, buf, (CC_LONG)bytes_read);
    }
    fclose(f);

    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(digest, &ctx);

    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_string[i * 2], "%02x", digest[i]);
    }

    return true;

#else
    // Linux fallback: use popen with md5sum
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "md5sum '%s'", filename);
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return false;

    char result[256];
    if (fgets(result, sizeof(result), pipe) == NULL) {
        pclose(pipe);
        return false;
    }
    pclose(pipe);

    // md5sum output format: "hash  filename"
    if (strlen(result) >= 32) {
        strncpy(md5_string, result, 32);
        md5_string[32] = '\0';
        return true;
    }
    return false;
#endif
}

// Print MD5 hash of data track (always)
void print_data_track_md5(const char* data_track_file, const char* disc_serial)
{
    // Calculate MD5 of the data track
    char actual_md5[33];
    if (!calculate_md5(data_track_file, actual_md5)) {
        printf("Failed to calculate MD5 for data track: %s\n", data_track_file);
        return;
    }

    printf("Data track MD5 for %s: %s\n", disc_serial, actual_md5);
}

// Verify data track MD5 using prebaked CUE files only
bool verify_data_track_md5_cue(const char* data_track_file, const char* disc_serial)
{
    // Convert disc serial to CUE format (underscore to dash)
    char cue_name[0x20];
    strcpy(cue_name, disc_serial);
    for (int i = 0; cue_name[i]; i++) {
        if (cue_name[i] == '_') {
            cue_name[i] = '-';
        }
    }

    // Calculate actual MD5 of the data track first
    char actual_md5[33];
    if (!calculate_md5(data_track_file, actual_md5)) {
        printf("Failed to calculate MD5 for data track: %s\n", data_track_file);
        return false;
    }

    // Get expected MD5 from prebaked CUE file
    char expected_md5[33];
    if (!extract_cue_md5(cue_name, expected_md5)) {
        printf("Data track MD5 for %s: %s\n", disc_serial, actual_md5);
        printf("No prebaked CUE MD5 found for comparison\n");
        return false;
    }

    // Compare MD5 hashes
    bool match = (strcmp(actual_md5, expected_md5) == 0);

    printf("MD5 verification for %s (prebaked CUE):\n", disc_serial);
    printf("  Expected: %s\n", expected_md5);
    printf("  Actual:   %s\n", actual_md5);
    printf("  Result:   %s\n", match ? "PASS" : "FAIL");

    return match;
}
