
#pragma once

static size_t lsGetPageSizeI(void);
static void* lsSystemAllocateI(void* pUserData, size_t size);
static void* lsSystemReallocateI(void* pUserData, void* ptr, size_t size);
static void lsSystemFreeI(void* pUserData, void* ptr);
static void* lsSystemAlignedAllocateI(void* userData, size_t size, size_t alignment);
static void lsSystemAlignedFreeI(void* userData, void* ptr);

typedef enum {
    LS_ACCESS_NONE          = 0x0,
    LS_ACCESS_READ          = 0x1,
    LS_ACCESS_WRITE         = 0x2,
    LS_ACCESS_EXECUTE       = 0x4,
    LS_ACCESS_READ_WRITE    = LS_ACCESS_READ  | LS_ACCESS_WRITE,
    LS_ACCESS_READ_EXECUTE  = LS_ACCESS_READ  | LS_ACCESS_EXECUTE,
    LS_ACCESS_WRITE_EXECUTE = LS_ACCESS_WRITE | LS_ACCESS_EXECUTE,
    LS_ACCESS_ALL           = LS_ACCESS_READ  | LS_ACCESS_EXECUTE | LS_ACCESS_WRITE,
} LsAccessMode;

static LsStatus lsOpenFileI(LsMappedFileI* pMappedFile, const char* pPath, const LsAllocationCallbacks* pAllocationCallbacks);
static void lsCloseFileI(LsMappedFileI* pMappedFile);
static LsStatus lsGetFileSizeI(size_t* pSize, const LsMappedFileI* pMappedFile);
static LsStatus lsMapFileI(void** pMapping, const LsMappedFileI* pMappedFile, LsAccessMode accessMode, size_t offset, size_t length, void* address);
static void lsUnmapFileI(void* mapping, const LsMappedFileI* pMappedFile, size_t length);
static LsStatus lsProtectPageI(void* pAddress, size_t length, LsAccessMode accessMode);

static LsStatus lsInitializeDebugSupportI(LsDebugSupport debugSupport);
static LsStatus lsDebugSupportAnnounceLoadI(LsObject object);
static void lsDebugSupportAnnounceLoadedI(LsObject object);
static void lsDebugSupportAnnounceUnloadI(LsObject object);
