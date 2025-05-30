
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOSERVICE
#define NOMCX
#define NOIME

#include <windows.h>

typedef struct LsMappedFileI {
    HANDLE hFile;
    HANDLE hMapping;
    union {
        LARGE_INTEGER s;  // todo: this is being stored twice, is there a better way?
        ULARGE_INTEGER u;
    } size;
} LsMappedFileI;
