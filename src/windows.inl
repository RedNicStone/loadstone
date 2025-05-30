
#pragma once

static size_t lsGetPageSizeI(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    // todo: is si.dwPageSize always the same as si.dwAllocationGranularity? Which one is the page size???
    return (size_t) si.dwPageSize;
}

static void* lsSystemAllocateI(void* pUserData, size_t size) {
    unused(pUserData);
    return malloc(size);
}

static void* lsSystemReallocateI(void* pUserData, void* ptr, size_t size) {
    unused(pUserData);
    return realloc(ptr, size);
}

static void lsSystemFreeI(void* pUserData, void* ptr) {
    unused(pUserData);
    free(ptr);
}

static void* lsSystemAlignedAllocateI(void* userData, size_t size, size_t alignment) {
    unused(userData);
    return _aligned_malloc(size, alignment);
}

static void lsSystemAlignedFreeI(void* userData, void* ptr) {
    unused(userData);
    _aligned_free(ptr);
}

static LsStatus lsUTF8ToWideChar(WCHAR** ppWideChar, const char* pUTF8, const LsAllocationCallbacks* pAllocationCallbacks) {
    PWCHAR empty_wide_char = L"";

    const int wide_char_length = MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, pUTF8, -1, NULL, 0);
    if (wide_char_length == 0) {
        ppWideChar = &empty_wide_char;
        return LS_OK;
    }

    WCHAR* wide_char_data = lsAllocateI(sizeof(WCHAR) * ((size_t) wide_char_length + 4), pAllocationCallbacks);
    if (wide_char_data == NULL) {
        LS_LOG_ERROR("Failed to allocate memory for wide char data");
        return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    int result = MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, pUTF8, -1, wide_char_data, wide_char_length);
    if (result == 0) {
        LS_LOG_ERROR("Failed to convert UTF-8 string to wide char string");
        lsFreeI(wide_char_data, pAllocationCallbacks);
        return LS_ERROR_SYSTEM;
    }

    const int normalized_char_length = NormalizeString(NormalizationC, wide_char_data, wide_char_length, NULL, 0);
    if (normalized_char_length == 0) {
        ppWideChar = &empty_wide_char;
        lsFreeI(wide_char_data, pAllocationCallbacks);
        return LS_OK;
    }

    WCHAR* normalized_char_data;
    if (normalized_char_length > wide_char_length) {
        normalized_char_data = lsAllocateI(sizeof(WCHAR) * ((size_t) normalized_char_length + 4), pAllocationCallbacks);
        if (normalized_char_data == NULL) {
            LS_LOG_ERROR("Failed to allocate memory for normalized wide char string");
            lsFreeI(wide_char_data, pAllocationCallbacks);
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    } else
        normalized_char_data = wide_char_data;

    if (normalized_char_length >= MAX_PATH) {
        normalized_char_data[0] = L'\\';
        normalized_char_data[1] = L'\\';
        normalized_char_data[2] = L'?';
        normalized_char_data[3] = L'\\';

        result = NormalizeString(NormalizationC, wide_char_data, wide_char_length, normalized_char_data + 4, normalized_char_length);
    } else
        result = NormalizeString(NormalizationC, wide_char_data, wide_char_length, normalized_char_data, normalized_char_length);

    if (normalized_char_data != wide_char_data)
        lsFreeI(wide_char_data, pAllocationCallbacks);

    if (result == 0) {
        LS_LOG_ERROR("Failed to normalize wide char string");
        lsFreeI(normalized_char_data, pAllocationCallbacks);
        return LS_ERROR_SYSTEM;
    }

    *ppWideChar = normalized_char_data;
    return LS_OK;
}

static LsStatus lsOpenFileI(LsMappedFileI* pMappedFile, const char* pPath, const LsAllocationCallbacks* pAllocationCallbacks) {
    WCHAR* wide_char_data;
    const LsStatus status = lsUTF8ToWideChar(&wide_char_data, pPath, pAllocationCallbacks);
    if (status != LS_OK)
        return status;

    pMappedFile->hFile = CreateFileW(wide_char_data, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    lsFreeI(wide_char_data, pAllocationCallbacks);
    if (pMappedFile->hFile == INVALID_HANDLE_VALUE) {
        LS_LOG_ERROR("Failed to open file");
        return LS_ERROR_SYSTEM;
    }

    if (!GetFileSizeEx(pMappedFile->hFile, &pMappedFile->size.s)) {
        CloseHandle(pMappedFile->hFile);
        LS_LOG_ERROR("Failed to get file size");
        return LS_ERROR_SYSTEM;
    }

    pMappedFile->hMapping = CreateFileMappingW(pMappedFile->hFile, NULL, PAGE_READONLY, pMappedFile->size.u.HighPart, pMappedFile->size.u.LowPart, NULL);
    if (pMappedFile->hMapping == NULL) {
        CloseHandle(pMappedFile->hFile);
        LS_LOG_ERROR("Failed to create file mapping");
        return LS_ERROR_SYSTEM;
    }

    return LS_OK;
}

static void lsCloseFileI(LsMappedFileI* pMappedFile) {
    if (CloseHandle(pMappedFile->hMapping) != true)
        LS_LOG_ERROR("Failed to close file mapping");

    if (CloseHandle(pMappedFile->hFile) != true)
        LS_LOG_ERROR("Failed to close file");
}

static LsStatus lsGetFileSizeI(size_t* pSize, const LsMappedFileI* pMappedFile) {
    *pSize = pMappedFile->size.u.QuadPart;
    return LS_OK;
}

static LsStatus lsMapFileI(void** pMapping, const LsMappedFileI* pMappedFile, LsAccessMode accessMode, size_t offset, size_t length, void* address) {
    if (pMappedFile) {
        DWORD protect = 0;
        if (accessMode & LS_ACCESS_READ)
            protect |= FILE_MAP_READ;
        if (accessMode & LS_ACCESS_WRITE)
            protect |= FILE_MAP_WRITE;
        if (accessMode & LS_ACCESS_EXECUTE)
            protect |= FILE_MAP_EXECUTE;

        ULARGE_INTEGER offset_integer;
        offset_integer.QuadPart = offset;

        *pMapping = MapViewOfFileEx(pMappedFile->hMapping, protect, offset_integer.u.HighPart, offset_integer.u.LowPart, length, address);
        if (*pMapping == NULL) {
            LS_LOG_ERROR("Failed to map file");
            return LS_ERROR_SYSTEM;
        }
    } else {
        DWORD protect;
        switch (accessMode) {
            case LS_ACCESS_NONE:
                protect = PAGE_NOACCESS;
                break;
            case LS_ACCESS_READ:
                protect = PAGE_READONLY;
                break;
            case LS_ACCESS_WRITE:
            case LS_ACCESS_READ_WRITE:
                protect = PAGE_READWRITE;
                break;
            case LS_ACCESS_EXECUTE:
            case LS_ACCESS_READ_EXECUTE:
                protect = PAGE_EXECUTE_READ;
                break;
            case LS_ACCESS_WRITE_EXECUTE:
            case LS_ACCESS_ALL:
                protect = PAGE_EXECUTE_READWRITE;
                break;
            default:
                return LS_ERROR_INVALID_ARGUMENT;
        }

        *pMapping = VirtualAlloc(address, length, MEM_COMMIT | MEM_RESERVE, protect);
        if (*pMapping == NULL) {
            LS_LOG_ERROR("Failed to reserve virual memory");
            return LS_ERROR_SYSTEM;
        }
    }

    return LS_OK;
}

static void lsUnmapFileI(void* mapping, const LsMappedFileI* pMappedFile, size_t length) {
    if (pMappedFile) {
        if (UnmapViewOfFile(mapping) != true)
            LS_LOG_ERROR("Failed to unmap file");
    } else {
        if (VirtualFree(mapping, length, MEM_DECOMMIT) != true)
            LS_LOG_ERROR("Failed to decommit virtual memory");
    }
}

static LsStatus lsProtectPageI(void* pAddress, size_t length, LsAccessMode accessMode) {
    DWORD protect;
    switch (accessMode) {
        case LS_ACCESS_NONE:
            protect = PAGE_NOACCESS;
            break;
        case LS_ACCESS_READ:
            protect = PAGE_READONLY;
            break;
        case LS_ACCESS_WRITE:
        case LS_ACCESS_READ_WRITE:
            protect = PAGE_READWRITE;
            break;
        case LS_ACCESS_EXECUTE:
        case LS_ACCESS_READ_EXECUTE:
            protect = PAGE_EXECUTE_READ;
            break;
        case LS_ACCESS_WRITE_EXECUTE:
        case LS_ACCESS_ALL:
            protect = PAGE_EXECUTE_READWRITE;
            break;
        default:
            return LS_ERROR_INVALID_ARGUMENT;
    }

    DWORD oldProtect;
    const BOOL result = VirtualProtect(pAddress, length, protect, &oldProtect);
    if (result == false) {
        LS_LOG_ERROR("Failed to change page protection");
        return LS_ERROR_SYSTEM;
    }
    return LS_OK;
}

static LsStatus lsInitializeDebugSupportI(LsDebugSupport debugSupport) {
    if (debugSupport == LS_DEBUG_SUPPORT_DISABLE)
        return LS_OK;

    return LS_ERROR_FEATURE_NOT_SUPPORTED;
}

static LsStatus lsDebugSupportAnnounceLoadI(LsObject object) {
    unused(object);
    return LS_OK;
}

static void lsDebugSupportAnnounceLoadedI(LsObject object) {
    unused(object);
}

static void lsDebugSupportAnnounceUnloadI(LsObject object) {
    unused(object);
}
