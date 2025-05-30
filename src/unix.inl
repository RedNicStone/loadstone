
#pragma once

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

static size_t lsGetPageSizeI(void) {
    return (size_t) sysconf(_SC_PAGE_SIZE);
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
    void* ptr = NULL;
    const int result = posix_memalign(&ptr, alignment, size);
    return result < 0 ? NULL : ptr;
}

static void lsSystemAlignedFreeI(void* userData, void* ptr) {
    unused(userData);
    free(ptr);
}

static LsStatus lsOpenFileI(LsMappedFileI* pMappedFile, const char* pPath, const LsAllocationCallbacks* pAllocationCallbacks) {
    unused(pAllocationCallbacks);
    *pMappedFile = open(pPath, O_RDONLY);
    if (*pMappedFile < 0) {
        LS_LOG_ERROR("Failed to open file");
        return LS_ERROR_SYSTEM;
    }

    return LS_OK;
}

static void lsCloseFileI(LsMappedFileI* pMappedFile) {
    if (close(*pMappedFile) < 0)
        LS_LOG_ERROR("Failed to close file");
}

static LsStatus lsGetFileSizeI(size_t* pSize, const LsMappedFileI* pMappedFile) {
    struct stat file_stat;
    if (fstat(*pMappedFile, &file_stat) < 0) {
        LS_LOG_ERROR("Failed to get file size");
        return LS_ERROR_SYSTEM;
    }

    *pSize = (size_t) file_stat.st_size;
    return LS_OK;
}

static LsStatus lsMapFileI(void** pMapping, const LsMappedFileI* pMappedFile, LsAccessMode accessMode, size_t offset, size_t length, void* address) {
    int access = 0;
    if (accessMode & LS_ACCESS_READ)
        access |= PROT_READ;
    if (accessMode & LS_ACCESS_WRITE)
        access |= PROT_WRITE;
    if (accessMode & LS_ACCESS_EXECUTE)
        access |= PROT_EXEC;

    int flags = MAP_PRIVATE | MAP_FILE;
    if (address != NULL)
        flags |= MAP_FIXED;

    if (pMappedFile == NULL) {
        flags |= MAP_ANONYMOUS;
        *pMapping = mmap(address, length, access, flags, -1, 0);
    } else {
        *pMapping = mmap(address, length, access, flags, *pMappedFile, (off_t) offset);
    }

    if (*pMapping == MAP_FAILED) {
        LS_LOG_ERROR("Failed to map file");
        return LS_ERROR_SYSTEM;
    }

    return LS_OK;
}

static void lsUnmapFileI(void* mapping, const LsMappedFileI* pMappedFile, size_t length) {
    unused(pMappedFile);
    munmap(mapping, length);
}

static LsStatus lsProtectPageI(void* pAddress, size_t length, LsAccessMode accessMode) {
    int access = 0;
    if (accessMode & LS_ACCESS_READ)
        access |= PROT_READ;
    if (accessMode & LS_ACCESS_WRITE)
        access |= PROT_WRITE;
    if (accessMode & LS_ACCESS_EXECUTE)
        access |= PROT_EXEC;

    if (mprotect(pAddress, length, access) < 0) {
        LS_LOG_ERROR("Failed to change page protection");
        return LS_ERROR_SYSTEM;
    }

    return LS_OK;
}

static LsStatus lsInitializeDebugSupportI(LsDebugSupport debugSupport) {
    if (debugSupport == LS_DEBUG_SUPPORT_DISABLE)
        return LS_OK;

    if (gGnuRDebug == NULL) {
        gGnuRDebug = dlsym(RTLD_DEFAULT, GNU_R_DEBUG_NAME);
        if (!gGnuRDebug) {
            LS_LOG_ERROR("Failed to load symbol '" GNU_R_DEBUG_NAME "' from GNU debug support library");
            return LS_ERROR_INTERNAL;
        }

        if (gGnuRDebug->r_brk == 0) {
            LS_LOG_ERROR("GNU debug support library has not yet been initialized."
                                             "Please load any dynamic library, either trough the interpreter or dlopen(), before opening an object");
            return LS_ERROR_INTERNAL;
        }

        if (gGnuRDebug->r_version == 0) {
            LS_LOG_ERROR("GNU debug support library uses unrecognized protocol version");
            return LS_ERROR_INTERNAL;
        }
    }

    if (gGnuDebugState == NULL) {
        union {
            void* obj;
            void (*func)(void);
        } u;

        u.obj = dlsym(RTLD_DEFAULT, GNU_DEBUG_STATE_NAME);
        if (!u.obj)
            u.obj = (void*) gGnuRDebug->r_brk;

        gGnuDebugState = u.func;

        if (!gGnuDebugState) {
            LS_LOG_ERROR("Failed to load symbol '" GNU_DEBUG_STATE_NAME "' from GNU debug support library");
            return LS_ERROR_INTERNAL;
        }
    }

    return LS_OK;
}

static LsStatus lsDebugSupportAnnounceLoadI(LsObject object) {
    struct link_map* map = lsAllocateI(sizeof(struct link_map), &object->allocationCallbacks);
    if (map == NULL) {
        LS_LOG_ERROR("Could not allocate memory for link map");
        return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    map->l_addr = object->pLoadAddress;
    map->l_name = (char*)(uintptr_t) object->objectInfo.pPath;
    map->l_ld   = (ElfW(Dyn)*)(object->pLoadAddress + object->dynamic_info_segment->p_vaddr);
    map->l_next = gGnuRDebug->r_map;
    map->l_prev = NULL;

    if (gGnuRDebug->r_map != NULL)
        gGnuRDebug->r_map->l_prev = map;

    gGnuRDebug->r_state = RT_ADD;
    gGnuRDebug->r_map = map;
    gGnuDebugState();

    return LS_OK;
}

static void lsDebugSupportAnnounceLoadedI(LsObject object) {
    unused(object);

    gGnuRDebug->r_state = RT_CONSISTENT;
    gGnuDebugState();
}

static void lsDebugSupportAnnounceUnloadI(LsObject object) {
    struct link_map* map = gGnuRDebug->r_map;
    while (true) {
        if (map->l_addr == object->pLoadAddress)
            break;

        map = map->l_next;
        if (map == NULL) {
            LS_LOG_ERROR("Could not find object in the list of loaded objects");
            return;
        }
    }

    if (map->l_prev != NULL)
        map->l_prev->l_next = map->l_next;

    if (map->l_next != NULL)
        map->l_next->l_prev = map->l_prev;

    if (gGnuRDebug->r_map == map)
        gGnuRDebug->r_map = map->l_next;

    lsFreeI(map, &object->allocationCallbacks);

    gGnuRDebug->r_state = RT_DELETE;
    gGnuDebugState();
}
