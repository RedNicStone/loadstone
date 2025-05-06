
#include "loadstone.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

#define ENABLE_LOGGING_ALL

#if defined(ENABLE_LOGGING_ALL)
#define ENABLE_LOGGING_INFO
#define ENABLE_LOGGING_WARNING
#define ENABLE_LOGGING_ERROR
#endif

#if defined(ENABLE_LOGGING_INFO) || defined(ENABLE_LOGGING_WARNING) || defined(ENABLE_LOGGING_ERROR)
#define ENABLE_LOGGING
#endif

#ifdef ENABLE_LOGGING
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#endif

#if defined(__LP64__) || defined(_LP64)
# define ELFCLASS_BITS 64
#elif
# define ELFCLASS_BITS 32
#endif

#if ELFCLASS_BITS == 64
# define ElfW_CLASS ELFCLASS64
# define ElfW_R_SYM  ELF64_R_SYM
# define ElfW_R_TYPE ELF64_R_TYPE
# define ElfW_R_INFO ELF64_R_INFO
# define ElfW_ST_VISIBILITY ELF64_ST_VISIBILITY
# define ElfW_ST_BIND ELF64_ST_BIND
# define ELF_WIDTH_PREFIX Elf64_
# define ELF_MACRO_WIDTH_PREFIX ELF64_
#else
# define ElfW_CLASS ELFCLASS32
# define ElfW_R_SYM  ELF32_R_SYM
# define ElfW_R_TYPE ELF32_R_TYPE
# define ElfW_R_INFO ELF32_R_INFO
# define ElfW_ST_VISIBILITY ELF32_ST_VISIBILITY
# define ElfW_ST_BIND ELF32_ST_BIND
# define ELF_WIDTH_PREFIX Elf32_
# define ELF_MACRO_WIDTH_PREFIX ELF32_
#endif

#define CAT(a,b) a##b
#define XCAT(a,b) CAT(a,b)
#define ElfMW(type) XCAT(ELF_MACRO_WIDTH_PREFIX, type)

// Likely defined in <link.h> already
#if !defined(ElfW)
#define ElfW(type) XCAT(ELF_WIDTH_PREFIX, type)
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define unused(x)       do { (void)(x); } while (0)


static ElfW(Addr) align_down(ElfW(Addr) value, ElfW(Addr) alignment) {
    return value & ~(alignment - 1);
}

static ElfW(Addr) align_up(ElfW(Addr) value, ElfW(Addr) alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}


static long lsGetPageSizeI(void) {
    return sysconf(_SC_PAGE_SIZE);
}
static unsigned long gPageSize;
static uint32_t gOpenHandles = 0;

#define GNU_R_DEBUG_NAME     "_r_debug"
#define GNU_DEBUG_STATE_NAME "_dl_debug_state"

static struct r_debug* gGnuRDebug;
static void (*gGnuDebugState)(void);

#if defined(ENABLE_LOGGING)
static void lsLogMessageI(LsSeverity severity, const char* pMessage);
static void lsLogMessageFormattedI(const LsAllocationCallbacks* pAllocationCallbacks, LsSeverity severity, const char* pFormat, ...);
#endif

#if defined(ENABLE_LOGGING) && defined(ENABLE_LOGGING_INFO)
#define LS_LOG_INFO(message) lsLogMessageI(LS_SEVERITY_INFO, message)
#define LS_LOG_INFO_F(callbacks, message, ...) lsLogMessageFormattedI(callbacks, LS_SEVERITY_INFO, message, __VA_ARGS__)
#else
#define LS_LOG_INFO(message)
#define LS_LOG_INFO_F(callbacks, message, ...)
#endif

#if defined(ENABLE_LOGGING) && defined(ENABLE_LOGGING_WARNING)
#define LS_LOG_WARNING(message) lsLogMessageI(LS_SEVERITY_WARNING, message)
#define LS_LOG_WARNING_F(callbacks, message, ...) lsLogMessageFormattedI(callbacks, LS_SEVERITY_WARNING, message, __VA_ARGS__)
#else
#define LS_LOG_WARNING(message)
#define LS_LOG_WARNING_F(callbacks, message, ...)
#endif

#if defined(ENABLE_LOGGING) && defined(ENABLE_LOGGING_ERROR)
#define LS_LOG_ERROR(message) lsLogMessageI(LS_SEVERITY_ERROR, message)
#define LS_LOG_ERROR_F(callbacks, message, ...) lsLogMessageFormattedI(callbacks, LS_SEVERITY_ERROR, message, __VA_ARGS__)
#else
#define LS_LOG_ERROR(message)
#define LS_LOG_ERROR_F(callbacks, message, ...)
#endif

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
    const int result = posix_memalign(ptr, alignment, size);
    return result < 0 ? NULL : ptr;
}

static void lsSystemAlignedFreeI(void* userData, void* ptr) {
    unused(userData);
    free(ptr);
}

static LsAllocationCallbacks gDefaultAllocationCallbacks = {
    .pUserData = NULL,
    .pfnAllocation = lsSystemAllocateI,
    .pfnReallocation = lsSystemReallocateI,
    .pfnFree = lsSystemFreeI,
    .pfnAlignedAllocation = lsSystemAlignedAllocateI,
    .pfnAlignedFree = lsSystemAlignedFreeI,
};

static void* lsAllocateI(size_t size, const LsAllocationCallbacks* pAllocationCallbacks) {
    void* ptr = pAllocationCallbacks->pfnAllocation(pAllocationCallbacks->pUserData, size);

    if (ptr == NULL) {
        LS_LOG_ERROR("Failed to allocate memory");
        return NULL;
    }

    return ptr;
}

// Disabled to pass pedantic checks
#if 0
static void* lsReallocateI(void* ptr, size_t size, const LsAllocationCallbacks* pAllocationCallbacks) {
    void* new_ptr = pAllocationCallbacks->pfnReallocation(pAllocationCallbacks->pUserData, ptr, size);

    if (ptr == NULL) {
        LS_LOG_ERROR("Failed to reallocate memory");
        return NULL;
    }

    return new_ptr;
}
#endif

static void lsFreeI(void* ptr, const LsAllocationCallbacks* pAllocationCallbacks) {
    pAllocationCallbacks->pfnFree(pAllocationCallbacks->pUserData, ptr);
}

static void* lsAlignedAllocateI(size_t size, size_t alignment, const LsAllocationCallbacks* pAllocationCallbacks) {
    void* ptr = pAllocationCallbacks->pfnAlignedAllocation(pAllocationCallbacks->pUserData, size, alignment);

    if (ptr == NULL) {
        LS_LOG_ERROR("Failed to allocate aligned memory");
        return NULL;
    }

    return ptr;
}

static void lsAlignedFreeI(void* pPtr, const LsAllocationCallbacks* pAllocationCallbacks) {
    pAllocationCallbacks->pfnAlignedFree(pAllocationCallbacks->pUserData, pPtr);
}

LsMessageCallbacks gMessageCallback = { NULL, NULL };

void lsSetMessageCallback(const LsMessageCallbacks* pCallback) {
    if (pCallback) {
        gMessageCallback = *pCallback;
        return;
    }

    gMessageCallback.pUserData = NULL;
    gMessageCallback.pfnMessage = NULL;
}

static const char* const lsSeverityStrings[LS_SEVERITY_COUNT] = {
    "INFO",
    "WARNING",
    "ERROR",
};

const char* lsSeverityToString(LsSeverity severity) {
    return lsSeverityStrings[severity];
}

#if defined(ENABLE_LOGGING)
static void lsLogMessageI(LsSeverity severity, const char* pMessage) {
    if (gMessageCallback.pfnMessage)
        gMessageCallback.pfnMessage(gMessageCallback.pUserData, severity, pMessage);
}

static void lsLogMessageFormattedI(const LsAllocationCallbacks* pAllocationCallbacks, LsSeverity severity, const char* pFormat, ...) {
    if (!gMessageCallback.pfnMessage)
        return;

    va_list args;
    va_start(args, pFormat);

#define LOG_FORMATTED_BUFFER_LENGTH 128

    char buffer[LOG_FORMATTED_BUFFER_LENGTH];
    const int32_t length = vsnprintf(buffer, sizeof(buffer), pFormat, args);
    if (length < 0)
        return;

    if (length < LOG_FORMATTED_BUFFER_LENGTH) {
        gMessageCallback.pfnMessage(gMessageCallback.pUserData, severity, buffer);
        va_end(args);
        return;
    }

    char* large_buffer = lsAllocateI((size_t) length, pAllocationCallbacks);
    if (large_buffer == NULL)
        gMessageCallback.pfnMessage(gMessageCallback.pUserData, severity, "Failed to allocate memory for message");

    vsnprintf(large_buffer, (size_t) length + 1, pFormat, args);
    gMessageCallback.pfnMessage(gMessageCallback.pUserData, severity, large_buffer);
    lsFreeI(large_buffer, pAllocationCallbacks);
    va_end(args);
}
#endif

static enum {
    UNINITIALIZED = 0,
    INITIALIZED = 1,
} gState = UNINITIALIZED;

static LsStatus lsInitializeI(LsDebugSupport debugSupport) {
    ++gOpenHandles;
    if (gState == INITIALIZED)
        return LS_OK;

    gState = INITIALIZED;
    long page_size = lsGetPageSizeI();
    if (page_size < 0)
        return LS_ERROR_INTERNAL;  // Do we need error handling here? I mean, if we fail here the user probably has bigger problems :D.

    gPageSize = (unsigned long) page_size;

    if (debugSupport == LS_DEBUG_SUPPORT_ENABLE_GNU) {

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
    }
    return LS_OK;
}

static void lsDeinitializeI(void) {
    --gOpenHandles;

    if (gOpenHandles == 0 && gState == INITIALIZED)
        gState = UNINITIALIZED;
}

typedef ElfW(Xword) RelType;

enum {
    REL     = DT_REL,
    RELA    = DT_RELA,
    RELR    = DT_RELR
};

typedef struct DtRel {
    ElfW(Rel)* rel;
    uint64_t rel_count;
} DtRel;

typedef struct DtRela {
    ElfW(Rela)* rela;
    uint64_t rela_count;
} DtRela;

typedef struct DtRelr {
    ElfW(Relr)* relr;
    uint64_t relr_count;
} DtRelr;

typedef struct DtJmprel {
    ElfW(Addr) ptr;
    uint64_t size;
    RelType type;
} DtJmprel;

typedef struct dt_preinit_array {
    ElfW(Addr)* ptr;
    uint64_t count;
} dt_preinit_array;

typedef struct dt_init_array {
    ElfW(Addr)* ptr;
    uint64_t count;
} dt_init_array;

typedef struct dt_fini_array {
    ElfW(Addr)* ptr;
    uint64_t count;
} dt_fini_array;

typedef uint8_t hash_table_type;

enum {
    NONE,
    PLAIN,
    GNU
};

typedef struct LsObject_T {
    ElfW(Addr) pFileData;
    size_t fileSize;
    int fileDescriptor;
    LsDebugSupport debugSupport;

    LsObjectInfo objectInfo;
    LsAllocationCallbacks allocationCallbacks;

    ElfW(Addr) pLoadAddress;

    hash_table_type symbolTableHashType;
    char* dtStrTab;
    ElfW(Word)* dtHash;
    ElfW(Sym)* dtSymTabBegin;
    ElfW(Sym)* dtSymTabEnd;

    const ElfW(Phdr)* dynamic_info_segment;
    ElfW(Phdr)* program_header;

    ElfW(Addr) load_segment_count;
    ElfW(Addr) load_segment_begin;
    ElfW(Addr) load_segment_end;

    ElfW(Addr) relocation_address;
    ElfW(Addr) relocation_length;

    ElfW(Nhdr)* note_segment_begin;
    ElfW(Nhdr)* note_segment_end;

    DtRel* dt_rel;
    size_t dt_rel_count;

    DtRela* dt_rela;
    size_t dt_rela_count;

    DtRelr* dt_relr;
    size_t dt_relr_count;

    DtJmprel* dt_jmprel_ptr;
    size_t dt_jmprel_count;

    dt_preinit_array* dt_preinit_array_ptr;
    size_t dt_preinit_array_count;
    ElfW(Addr) dt_preinit;

    dt_init_array* dt_init_array_ptr;
    size_t dt_init_array_count;
    ElfW(Addr) dt_init;

    dt_fini_array* dt_fini_array_ptr;
    size_t dt_fini_array_count;
    ElfW(Addr) dt_fini;

    ElfW(Addr)* dt_pltgot;

    size_t commonSymbolCount;
    void** commonSymbolAddresses;

    int dt_textrel;
    int dt_flags;

    bool program_header_on_heap;
} LsObject_T;

static void lsInitializeObjectI(LsObject object) {
    object->pFileData               = 0;
    object->fileSize                = 0;
    object->fileDescriptor          = -1;

    object->objectInfo.pLoadAddress = NULL;
    object->objectInfo.pPath        = NULL;
    object->objectInfo.pSoname      = NULL;
    object->objectInfo.pRPath       = NULL;
    object->objectInfo.pRunPath     = NULL;
    object->objectInfo.pNeededNames = NULL;
    object->objectInfo.neededCount  = 0;

    object->pLoadAddress            = 0;

    object->symbolTableHashType     = NONE;
    object->dtStrTab                = NULL;
    object->dtHash                  = NULL;
    object->dtSymTabBegin           = NULL;
    object->dtSymTabEnd             = NULL;

    object->dynamic_info_segment    = NULL;
    object->program_header          = NULL;
    object->load_segment_count      = 0;
    object->load_segment_begin      = INTPTR_MAX;
    object->load_segment_end        = 0;
    object->relocation_address      = 0;
    object->relocation_length       = 0;
    object->note_segment_begin      = 0;
    object->note_segment_end        = 0;


    object->dt_pltgot               = NULL;

    object->dt_textrel              = 0;
    object->dt_flags                = 0;

    object->dt_init                 = 0;
    object->dt_fini                 = 0;

    object->dt_rel_count            = 0;
    object->dt_rela_count           = 0;
    object->dt_relr_count           = 0;
    object->dt_jmprel_count         = 0;
    object->dt_preinit_array_count  = 0;
    object->dt_init_array_count     = 0;
    object->dt_fini_array_count     = 0;

    object->dt_rel                  = NULL;
    object->dt_rela                 = NULL;
    object->dt_relr                 = NULL;
    object->dt_jmprel_ptr           = NULL;
    object->dt_preinit_array_ptr    = NULL;
    object->dt_init_array_ptr       = NULL;
    object->dt_fini_array_ptr       = NULL;

    object->commonSymbolCount       = 0;
    object->commonSymbolAddresses   = NULL;
}

LsStatus lsOpenObjectFromMemory(
    const void* pElf,
    size_t elfSize,
    LsDebugSupport debugSupport,
    LsObject* pObject,
    const LsAllocationCallbacks* pAllocationCallbacks) {
    const LsStatus status = lsInitializeI(debugSupport);
    if (status != LS_OK)
        return status;

    if (pAllocationCallbacks == NULL)
        pAllocationCallbacks = &gDefaultAllocationCallbacks;

    LsObject_T* object = lsAllocateI(sizeof(LsObject_T), pAllocationCallbacks);
    if (unlikely(object == NULL)) {
        LS_LOG_ERROR("lsOpenObject: Failed to allocate memory");
        return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    lsInitializeObjectI(object);

    object->pFileData = (ElfW(Addr)) pElf;
    object->fileSize = elfSize;
    object->fileDescriptor = -1;

    object->allocationCallbacks.pUserData       = pAllocationCallbacks->pUserData;
    object->allocationCallbacks.pfnAllocation   = pAllocationCallbacks->pfnAllocation;
    object->allocationCallbacks.pfnReallocation = pAllocationCallbacks->pfnReallocation;
    object->allocationCallbacks.pfnFree         = pAllocationCallbacks->pfnFree;

    *pObject = object;
    return LS_OK;
}

LsStatus lsOpenObjectFromFile(
    const char* pPath,
    LsDebugSupport debugSupport,
    LsObject* pObject,
    const LsAllocationCallbacks* pAllocationCallbacks) {
    const LsStatus status = lsInitializeI(debugSupport);
    if (status != LS_OK)
        return status;

    if (pAllocationCallbacks == NULL)
        pAllocationCallbacks = &gDefaultAllocationCallbacks;

    char* pFileName = lsAllocateI(strlen(pPath) + 1, pAllocationCallbacks);
    if (unlikely(pFileName == NULL)) {
        LS_LOG_ERROR("lsOpenObjectFromFile: Failed to allocate memory for file name");
        return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    strcpy(pFileName, pPath);

    LsObject_T* object = lsAllocateI(sizeof(struct LsObject_T), pAllocationCallbacks);
    if (unlikely(object == NULL)) {
        LS_LOG_ERROR_F(&object->allocationCallbacks, "lsOpenObjectFromFile: Failed to allocate memory: %s", strerror(errno));
        lsFreeI(pFileName, pAllocationCallbacks);
        return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    lsInitializeObjectI(object);
    object->objectInfo.pPath = pFileName;

    object->fileDescriptor = open(pPath, O_RDONLY);
    if (unlikely(object->fileDescriptor < 0)) {
        LS_LOG_ERROR_F(&object->allocationCallbacks, "lsOpenObjectFromFile: Failed to open file: %s", strerror(errno));
        lsFreeI(object, pAllocationCallbacks);
        return LS_ERROR_FILE_ACTION_FAILED;
    }

    struct stat elf_stat;
    if (unlikely(fstat(object->fileDescriptor, &elf_stat) < 0) || elf_stat.st_size < 0) {
        LS_LOG_ERROR_F(&object->allocationCallbacks, "lsOpenObjectFromFile: Failed to stat file: %s", strerror(errno));
        lsFreeI(object, pAllocationCallbacks);
        return LS_ERROR_FILE_ACTION_FAILED;
    }

    void* pFileData = mmap(NULL, (size_t) elf_stat.st_size, PROT_READ, MAP_PRIVATE, object->fileDescriptor, 0);
    if (unlikely(pFileData == MAP_FAILED)) {
        LS_LOG_ERROR_F(&object->allocationCallbacks, "lsOpenObjectFromFile: Failed to map file: %s", strerror(errno));
        lsFreeI(object, pAllocationCallbacks);
        return LS_ERROR_MEMORY_MAP_FAILED;
    }

    object->pFileData = (ElfW(Addr)) pFileData;
    object->fileSize = (size_t) elf_stat.st_size;
    object->debugSupport = debugSupport;

    object->allocationCallbacks.pUserData       = pAllocationCallbacks->pUserData;
    object->allocationCallbacks.pfnAllocation   = pAllocationCallbacks->pfnAllocation;
    object->allocationCallbacks.pfnReallocation = pAllocationCallbacks->pfnReallocation;
    object->allocationCallbacks.pfnFree         = pAllocationCallbacks->pfnFree;

    *pObject = object;
    return LS_OK;
}

void lsCloseObject(LsObject object) {
    LsObject_T* pObject = object;

    if (pObject->fileDescriptor >= 0) {
        munmap((void*) pObject->pFileData, pObject->fileSize);
        close(pObject->fileDescriptor);
    }

    if (pObject->objectInfo.pPath != NULL)
        lsFreeI((void*)(uintptr_t) pObject->objectInfo.pPath, &pObject->allocationCallbacks);

    if (pObject->commonSymbolAddresses != NULL) {
        for (size_t i = 0; i < pObject->commonSymbolCount; i++)
            lsAlignedFreeI(pObject->commonSymbolAddresses[i], &pObject->allocationCallbacks);
    }

    lsFreeI(pObject, &pObject->allocationCallbacks);
    lsDeinitializeI();
}

//############################//
//     ELF Object Loading     //
//############################//

static LsStatus lsValidateHeaderI(LsObject object) {
    const ElfW(Ehdr)* elf_header = (ElfW(Ehdr)*) object->pFileData;
    if (unlikely(
        elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header->e_ident[EI_MAG3] != ELFMAG3)) {
        LS_LOG_ERROR("Invalid ELF file signature");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_ident[EI_CLASS] != ELFCLASS64)) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported architecture");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_ident[EI_DATA] == ELFDATA2MSB)) {
        LS_LOG_ERROR("Refusing to parse big-endian ELF file");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_ident[EI_VERSION] != EV_CURRENT)) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported version");
        return LS_ERROR_OBJECT_INVALID;
    }

    /*
    // todo: which OSABIs are supported?
    if (unlikely(elf_header->e_ident[EI_OSABI] != ELFOSABI_SYSV)) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported OS ABI");
        return LS_ERROR_OBJECT_INVALID;
    }
    */

    switch (elf_header->e_type) {
        case ET_DYN:
            break;
        case ET_EXEC:
            LS_LOG_WARNING("Elf is an executable file. Executable support is experimental");
            break;
        default:
            LS_LOG_ERROR("ELF file is not of supported type");
            return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_machine != EM_X86_64)) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported machine architecture");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_version != EV_CURRENT)) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported version");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(elf_header->e_phentsize != sizeof(ElfW(Phdr)))) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported program header size");
        return LS_ERROR_OBJECT_INVALID;
    }

    return LS_OK;
}

static LsStatus lsParseSegmentsI(LsObject object) {
    const ElfW(Ehdr)* elf_header        = (ElfW(Ehdr)*) object->pFileData;

    if (unlikely(elf_header->e_phentsize != sizeof(ElfW(Phdr)))) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported program header size");
        return LS_ERROR_OBJECT_INVALID;
    }

    const ElfW(Half)  seg_num           = elf_header->e_phnum;

    const ElfW(Phdr)* elf_segment_begin = (ElfW(Phdr)*)(object->pFileData + elf_header->e_phoff);
    const ElfW(Phdr)* elf_segment_end   = elf_segment_begin + seg_num;

    for (const ElfW(Phdr)* seg = elf_segment_begin; seg < elf_segment_end; ++seg) {
        switch (seg->p_type) {
            case PT_DYNAMIC:
                /*
                 * PT_DYNAMIC specifies the dynamic linking information.
                 */

                // Debuginfo only files may have an empty dynamic segment.
                // We check if the dynamic segment is empty, and if so, we skip it.
                if (seg->p_filesz > 0) {
                    if (object->dynamic_info_segment) {
                        LS_LOG_WARNING("Multiple dynamic linking information segments found, using first one");
                        break;
                    }

                    object->dynamic_info_segment = seg;
                }
                break;

            case PT_LOAD:
                /*
                 * PT_LOAD specifies the memory region of the program being loaded.
                 * We will simply validate the segment and count how many loadable segments we have and how much memory we need to allocate.
                 */

                // Check if the segment is properly aligned relative to the system page size.
                // We will not attempt to load segments that are not page-aligned
                if (unlikely((seg->p_align & (gPageSize - 1)) != 0)) {
                    LS_LOG_ERROR("ELF program load command alignment is not page-aligned");
                    return LS_ERROR_OBJECT_INVALID;
                }

                // Check if the segment address/offset is properly aligned.
                // Rule: The p_vaddr (virtual address where the segment should be loaded in memory)
                //       and p_offset (offset of the segment in the file) must be congruent modulo the page size.
                if (unlikely(((seg->p_vaddr - seg->p_offset) & (seg->p_align - 1)) != 0)) {
                    LS_LOG_ERROR("ELF program load command address/offset not properly aligned");
                    return LS_ERROR_OBJECT_INVALID;
                }

                const ElfW(Addr) seg_begin = align_down(seg->p_vaddr, gPageSize);
                if (object->load_segment_begin > seg_begin)
                    object->load_segment_begin = seg_begin;

                object->load_segment_count++;

                const ElfW(Addr) seg_end = align_up(seg->p_vaddr + seg->p_memsz, gPageSize);
                if (object->load_segment_end < seg_end)
                    object->load_segment_end = seg_end;

                break;

            case PT_PHDR:
                /*
                 * PT_PHDR specifies the program header table location.
                 */

                    if (object->program_header) {
                        LS_LOG_WARNING("Multiple program header table segments found, using first one");
                        break;
                    }

            object->program_header = (ElfW(Phdr)*) seg->p_vaddr;
                break;

            case PT_TLS:
                // todo: Implement thread-local storage
                break;

            case PT_GNU_STACK:
                /*
                 * PT_GNU_STACK specifies the stack flags.
                 * We check if the stack permissions match the expected permissions since we cannot update them at this point.
                 */

                if (seg->p_flags != (PF_R | PF_W)) {
                    LS_LOG_ERROR("ELF program load command stack permissions do not match expected permissions");
                    return LS_ERROR_OBJECT_INVALID;
                }
                break;

            case PT_GNU_RELRO:
                /*
                 * PT_GNU_RELRO specifies the relocation range.
                 * We store the addresses and length to later update the relocation table.
                 */

                object->relocation_address = seg->p_vaddr;
                object->relocation_length  = seg->p_filesz;
                break;

            case PT_NOTE:
                /*
                 * PT_NOTE specifies the note segment.
                 * We will store it for later use.
                 */

                object->note_segment_begin = (ElfW(Nhdr)*) seg->p_vaddr;
                object->note_segment_end   = (ElfW(Nhdr)*) (seg->p_vaddr + seg->p_filesz);
                break;

            default:
                break;
        }
    }

    if (unlikely(object->load_segment_count == 0)) {
        LS_LOG_ERROR("No loadable segments found");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (unlikely(object->dynamic_info_segment == NULL)) {
        // Todo: Should this be an error? It's not fatal, but some things like the debugger may misbehave
        LS_LOG_WARNING("No dynamic linking information found");
    }

    if (object->program_header == NULL) {
        // Allocate memory for the program header
        object->program_header = lsAllocateI(sizeof(ElfW(Phdr)) * seg_num, &object->allocationCallbacks);
        memcpy(object->program_header, elf_segment_begin, elf_header->e_phoff);

        object->program_header_on_heap = true;
    }

    return LS_OK;
}

static int lsConvertProtectionFlags(ElfW(Word) flags) {
    int protection = 0;
    if (flags & PF_R)
        protection |= PROT_READ;
    if (flags & PF_W)
        protection |= PROT_WRITE;
    if (flags & PF_X)
        protection |= PROT_EXEC;

    if (protection & PROT_WRITE && protection & PROT_EXEC) {
        LS_LOG_WARNING("Segment is both writable and executable, marking it as non-executable and continuing");
        protection &= ~PROT_EXEC;
    }

    return protection;
}

/// Loads ELF segments into memory.
/// This function is heavily based on '_dl_map_segments' from the GNU C Library for compatibility reasons.
static LsStatus lsLoadSegmentsI(LsObject object) {
    const ElfW(Addr)  map_length    = object->load_segment_end - object->load_segment_begin;

    LS_LOG_INFO_F(&object->allocationCallbacks, "Identified %llu loadable segments", object->load_segment_count);
    LS_LOG_INFO_F(&object->allocationCallbacks, "Loading ELF from 0x%llx to 0x%llx", object->load_segment_begin, object->load_segment_end);

    const ElfW(Ehdr)* elf_header    = (ElfW(Ehdr)*) object->pFileData;
    const ElfW(Phdr)* elf_segment   = (ElfW(Phdr)*)(object->pFileData + elf_header->e_phoff);

    void* base_pointer = NULL;

    for (ElfW(Addr) i = 0; i < object->load_segment_count; ++i) {
        while (elf_segment->p_type != PT_LOAD) elf_segment++;

        // Start of data pages, relative to the load address
        const ElfW(Addr) data_page_begin    = align_down(elf_segment->p_vaddr, gPageSize);
        // End of data, relative to the load address
        const ElfW(Addr) data_end           = elf_segment->p_vaddr + elf_segment->p_filesz;
        // End of data pages, relative to the load address
        const ElfW(Addr) data_page_end      = align_up(data_end, gPageSize);

        if (data_page_end <= data_page_begin) {
            LS_LOG_ERROR("Relocatable segment has zero size");
            return LS_ERROR_OBJECT_INVALID;
        }

        LS_LOG_INFO_F(&object->allocationCallbacks, "Loading ELF segment %i from 0x%llx to 0x%llx", i, elf_segment->p_vaddr, elf_segment->p_vaddr + elf_segment->p_memsz);

        const int protection_flags = lsConvertProtectionFlags(elf_segment->p_flags);

        void* map_address;
        size_t segment_size;
        int mmap_flags = MAP_PRIVATE | MAP_FILE;
        const off_t offset = (off_t) align_down(elf_segment->p_offset, gPageSize);
        if (unlikely(base_pointer == NULL)) {
            // For the initial segment, we will map enough memory for the entire object
            map_address  = NULL;
            segment_size = map_length;
        } else {
            // For later segments, we will override the initial segment mapping
            map_address  = (char*) base_pointer + data_page_begin;
            segment_size = data_page_end - data_page_begin;
            mmap_flags |= MAP_FIXED;
        }

        void* segment_pointer =
            mmap(map_address,
                 segment_size,
                 protection_flags,
                 mmap_flags,
                 object->fileDescriptor,
                  offset);

        if (unlikely(segment_pointer == MAP_FAILED)) {
            LS_LOG_ERROR_F(&object->allocationCallbacks, "Cannot memory map ELF segment %i, error: %s", i, strerror(errno));
            return LS_ERROR_MEMORY_MAP_FAILED;
        }

        if (unlikely(base_pointer == NULL)) {
            // This is the first segment, write the base pointer
            base_pointer = segment_pointer;
            object->pLoadAddress = (ElfW(Addr)) base_pointer;
            object->objectInfo.pLoadAddress = base_pointer;
        }

        // End of zeroed data, relative to the load address
        const ElfW(Addr) zero_end = elf_segment->p_vaddr + elf_segment->p_memsz;

        if (zero_end > data_end) {
            // Start of zeroed data, relative to the load address
            const ElfW(Addr) zero_begin = data_end;
            // Start of zero-initialized page range
            ElfW(Addr) zero_page_begin = align_up(zero_begin, gPageSize);

            if (zero_end < zero_page_begin)
                zero_page_begin = zero_end;

            // Zero the last part in the last data page of the segment
            if (zero_page_begin > zero_begin) {
                void* zero_section_pointer = (char*) base_pointer + align_down(zero_begin, gPageSize);
                // Check if the segment is writable
                if ((protection_flags & PROT_WRITE) == 0)
                    // Dang, nab it. We will have to mark it as writable briefly.
                    if (unlikely(mprotect(zero_section_pointer,
                                 gPageSize,
                                 protection_flags | PROT_WRITE) == -1)){
                        LS_LOG_ERROR_F(&object->allocationCallbacks, "Cannot memory protect ELF section for zeroing, error: %s", strerror(errno));
                        return LS_ERROR_MEMORY_MAP_FAILED;
                    }

                // Zero the section
                memset((char*) base_pointer + zero_begin, '\0', zero_page_begin - zero_begin);

                LS_LOG_INFO_F(&object->allocationCallbacks, "Zeroed out ELF segment %i from 0x%llx to 0x%llx", i, zero_begin, zero_page_begin);

                if ((protection_flags & PROT_WRITE) == 0)
                    // Revert to the original protection flags
                    // We will assume that this cannot fail, since we just changed the protection flags
                    if (unlikely(mprotect(zero_section_pointer,
                                 gPageSize,
                                 protection_flags) == -1)) {
                        LS_LOG_ERROR_F(&object->allocationCallbacks, "Cannot memory protect ELF section after zeroing, error: %s", strerror(errno));
                        return LS_ERROR_MEMORY_MAP_FAILED;
                    }
            }

            // Fill the remaining space with zeroed pages
            if (zero_end > zero_page_begin) {
                const void* zero_section_pointer =
                    mmap((char*) base_pointer + zero_page_begin,
                         zero_end - zero_page_begin,
                         protection_flags,
                         MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                         -1,
                         0);

                LS_LOG_INFO_F(&object->allocationCallbacks, "Padded out ELF segment %i from 0x%llx to 0x%llx", i, zero_page_begin, zero_end);

                if (unlikely(zero_section_pointer == MAP_FAILED)) {
                    LS_LOG_ERROR_F(&object->allocationCallbacks, "Cannot memory map zeroed ELF segment pages, error: %s", strerror(errno));
                    return LS_ERROR_MEMORY_MAP_FAILED;
                }
            }
        }

        elf_segment++;
    }

    if (!object->program_header_on_heap) {
        // We have a program header in one of the segments, we will adjust the pointer
        object->program_header = (ElfW(Phdr)*)((ElfW(Addr)) object->program_header + object->pLoadAddress);
    }

    return LS_OK;
}

#if 0
static LsStatus lsParseSectionsI(LsObject object, LsLoadInfo* object) {
    const ElfW(Ehdr)* elf_header        = (ElfW(Ehdr)*) object->pFileData;

    if (unlikely(elf_header->e_shentsize != sizeof(ElfW(Shdr)))) {
        LS_LOG_ERROR("Refusing to parse ELF file with unsupported section header size");
        return LS_ERROR_OBJECT_INVALID;
    }

    const ElfW(Half)  sec_num           = elf_header->e_shnum;
    const ElfW(Shdr)* section_begin     = (ElfW(Shdr)*)(object->pFileData + elf_header->e_shoff);
    const ElfW(Shdr)* section_end       = section_begin + sec_num;

    object->symbol_table_hash_type   = none;
    object->section_dynsym           = NULL;
    object->section_symtab           = NULL;
    object->section_strtab           = NULL;
    object->section_rel              = NULL;
    object->section_rela             = NULL;
    object->section_hash             = NULL;
    object->section_preinit_array    = NULL;
    object->section_init_array       = NULL;
    object->section_fini_array       = NULL;

    for (const ElfW(Shdr)* section = section_begin; section < section_end; ++section) {
        switch (section->sh_type) {
            case SHT_DYNSYM:
                object->section_dynsym = section;
                break;
            case SHT_SYMTAB:
                object->section_symtab = section;
                break;
            case SHT_STRTAB:
                object->section_strtab = section;
                break;
            case SHT_REL:
                object->section_rel = section;
                break;
            case SHT_RELA:
                object->section_rela = section;
                break;
            case SHT_HASH:
                object->symbol_table_hash_type = plain;
                object->section_hash = section;
                break;
            case SHT_GNU_HASH:
                object->symbol_table_hash_type = gnu;
                object->section_hash = section;
                break;
            case SHT_PREINIT_ARRAY:
                object->section_preinit_array = section;
                break;
            case SHT_INIT_ARRAY:
                object->section_init_array = section;
                break;
            case SHT_FINI_ARRAY:
                object->section_fini_array = section;
                break;
            default:
                break;
        }
    }

    return LS_OK;
}
#endif

#define DT_GNU_HASH_LOCAL DT_NUM
#define DT_NUM_LOCAL (DT_NUM + 1)

static const Elf64_Sxword unique_dynamic_tags[] = {
    DT_RPATH, DT_RUNPATH, DT_SONAME, DT_SYMTAB, DT_STRTAB, DT_SYMENT, DT_PLTGOT, DT_HASH, DT_GNU_HASH_LOCAL, DT_TEXTREL, DT_DEBUG, DT_FLAGS
};

#if defined(ENABLE_LOGGING) && defined(ENABLE_LOGGING_WARNING)
static const char* dynamic_tag_names[DT_NUM_LOCAL] = {
    [DT_NULL]               = "DT_NULL",
    [DT_NEEDED]             = "DT_NEEDED",
    [DT_PLTRELSZ]           = "DT_PLTRELSZ",
    [DT_PLTGOT]             = "DT_PLTGOT",
    [DT_HASH]               = "DT_HASH",
    [DT_STRTAB]             = "DT_STRTAB",
    [DT_SYMTAB]             = "DT_SYMTAB",
    [DT_RELA]               = "DT_RELA",
    [DT_RELASZ]             = "DT_RELASZ",
    [DT_RELAENT]            = "DT_RELAENT",
    [DT_STRSZ]              = "DT_STRSZ",
    [DT_SYMENT]             = "DT_SYMENT",
    [DT_INIT]               = "DT_INIT",
    [DT_FINI]               = "DT_FINI",
    [DT_SONAME]             = "DT_SONAME",
    [DT_RPATH]              = "DT_RPATH",
    [DT_SYMBOLIC]           = "DT_SYMBOLIC",
    [DT_REL]                = "DT_REL",
    [DT_RELSZ]              = "DT_RELSZ",
    [DT_RELENT]             = "DT_RELENT",
    [DT_PLTREL]             = "DT_PLTREL",
    [DT_DEBUG]              = "DT_DEBUG",
    [DT_TEXTREL]            = "DT_TEXTREL",
    [DT_JMPREL]             = "DT_JMPREL",
    [DT_BIND_NOW]           = "DT_BIND_NOW",
    [DT_INIT_ARRAY]         = "DT_INIT_ARRAY",
    [DT_FINI_ARRAY]         = "DT_FINI_ARRAY",
    [DT_INIT_ARRAYSZ]       = "DT_INIT_ARRAYSZ",
    [DT_FINI_ARRAYSZ]       = "DT_FINI_ARRAYSZ",
    [DT_RUNPATH]            = "DT_RUNPATH",
    [DT_FLAGS]              = "DT_FLAGS",
    [DT_PREINIT_ARRAY]      = "DT_PREINIT_ARRAY",
    [DT_PREINIT_ARRAYSZ]    = "DT_PREINIT_ARRAYSZ",
    [DT_SYMTAB_SHNDX]       = "DT_SYMTAB_SHNDX",
    [DT_RELRSZ]             = "DT_RELRSZ",
    [DT_RELR]               = "DT_RELR",
    [DT_RELRENT]            = "DT_RELRENT",
    [DT_GNU_HASH_LOCAL]     = "DT_GNU_HASH",
};
#endif

static LsStatus lsParseDynamicSegmentI(LsObject object) {
    if (object->dynamic_info_segment == NULL)
        return LS_OK;

    const ElfW(Dyn)* dynamic_info_begin = (ElfW(Dyn)*)(object->pLoadAddress + object->dynamic_info_segment->p_vaddr);
    const ElfW(Dyn)* dynamic_info_end   = (ElfW(Dyn)*)((ElfW(Addr)) dynamic_info_begin + object->dynamic_info_segment->p_memsz);

    const ElfW(Addr) elf_range = object->load_segment_end - object->load_segment_begin + object->pLoadAddress;
    if (unlikely((ElfW(Addr)) dynamic_info_end >= elf_range)) {
        LS_LOG_ERROR("ELF file contains dynamic information that extends beyond the ELF file");
        return LS_ERROR_OBJECT_INVALID;
    }

    uint64_t entry_count[DT_NUM_LOCAL] = { 0 };

    for (const ElfW(Dyn)* dynamic_info = dynamic_info_begin; dynamic_info < dynamic_info_end; ++dynamic_info) {
        switch (dynamic_info->d_tag) {
            case DT_GNU_HASH:
                entry_count[DT_GNU_HASH_LOCAL]++;
                continue;
            case DT_NULL:
                break;
            case DT_STRTAB:
                // We extract DT_STRTAB early since we need it to resolve pointers
                object->dtStrTab = (char*) object->pLoadAddress + dynamic_info->d_un.d_ptr;

            /* fall through */
            default:
                if (unlikely(dynamic_info->d_tag > DT_NUM_LOCAL)) {
                    LS_LOG_WARNING_F(&object->allocationCallbacks, "ELF file contains unknown dynamic tag %llx", dynamic_info->d_tag);
                    continue;
                }

                entry_count[dynamic_info->d_tag]++;
                continue;
        }
        break;
    }

    for (const Elf64_Sxword* unique_tag = unique_dynamic_tags;
        unique_tag < unique_dynamic_tags + sizeof(unique_dynamic_tags) / sizeof(Elf64_Sxword);
        ++unique_tag) {
        if (entry_count[*unique_tag] > 1) {
            LS_LOG_WARNING_F(&object->allocationCallbacks, "ELF file contains multiple entries for dynamic tag %s", dynamic_tag_names[*unique_tag]);
        }
    }

    if (entry_count[DT_STRTAB] == 0 &&
        (entry_count[DT_NEEDED] || entry_count[DT_SONAME] || entry_count[DT_RPATH] || entry_count[DT_RUNPATH] || entry_count[DT_SYMTAB])) {
        LS_LOG_ERROR("ELF file does not contain DT_STRTAB but its referenced by other dynamic segments");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (entry_count[DT_SYMTAB] == 0 &&
        (entry_count[DT_HASH] || entry_count[DT_GNU_HASH_LOCAL] || entry_count[DT_STRTAB])) {
        LS_LOG_ERROR("ELF file does not contain DT_SYMTAB but its referenced by other dynamic segments");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (entry_count[DT_SYMENT] == 0 && entry_count[DT_SYMTAB]) {
        LS_LOG_ERROR("ELF file does not contain DT_SYMENT but its referenced by DT_SYMTAB");
        return LS_ERROR_OBJECT_INVALID;
    }

    /*
     * todo: having not relocatable sections whilst having a PLTREL section seems to still be valid, should this be removed?
    if (entry_count[DT_REL] + entry_count[DT_RELA] + entry_count[DT_RELR] == 0 &&
        (entry_count[DT_JMPREL] || entry_count[DT_PLTREL])) {
        LS_LOG_ERROR("ELF file does not contain DT_REL, DT_RELA or DT_RELR but its referenced by other dynamic segments");
        return LS_ERROR_OBJECT_INVALID;
    }
    */

    if (entry_count[DT_PLTREL] == 0 && entry_count[DT_JMPREL]) {
        LS_LOG_ERROR("ELF file does not contain DT_PLTREL but its referenced by DT_JMPREL");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (entry_count[DT_PLTGOT] == 0 && entry_count[DT_JMPREL]) {
        LS_LOG_ERROR("ELF file does not contain DL_PLTGOT but its referenced by DT_JMPREL");
        return LS_ERROR_OBJECT_INVALID;
    }

    if (entry_count[DT_NEEDED]) {
        object->objectInfo.pNeededNames = lsAllocateI(sizeof(char*) * entry_count[DT_NEEDED], &object->allocationCallbacks);
        if (unlikely(object->objectInfo.pNeededNames == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    if (entry_count[DT_HASH]) {
        object->symbolTableHashType = PLAIN;
        if (entry_count[DT_GNU_HASH_LOCAL]) {
            LS_LOG_WARNING("ELF file contains both DT_GNU_HASH and DT_HASH, using DT_GNU_HASH");
            object->symbolTableHashType = GNU;
        }
    } else if (entry_count[DT_GNU_HASH_LOCAL])
        object->symbolTableHashType = GNU;
    else {
        LS_LOG_WARNING("ELF file contains no hash table, using none. This may cause performance issues");
    }

    if (entry_count[DT_REL]) {
        if (entry_count[DT_RELSZ]  != entry_count[DT_REL]  || entry_count[DT_RELENT]  != entry_count[DT_REL]) {
            LS_LOG_ERROR("ELF file contains multiple relocatable segments, but the number of relocatable entity size or count doesn't match");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_rel = lsAllocateI(sizeof(DtRel) * entry_count[DT_REL], &object->allocationCallbacks);
        if (unlikely(object->dt_rel == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_rel_count = entry_count[DT_REL];
    }

    if (entry_count[DT_RELA]) {
        if (entry_count[DT_RELASZ] != entry_count[DT_RELA] || entry_count[DT_RELAENT] != entry_count[DT_RELA]) {
            LS_LOG_ERROR("ELF file contains multiple relocatable segments, but the number of relocatable entity size or count doesn't match");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_rela = lsAllocateI(sizeof(DtRela) * entry_count[DT_RELA], &object->allocationCallbacks);
        if (unlikely(object->dt_rela == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_rela_count = entry_count[DT_RELA];
    }

    if (entry_count[DT_RELR]) {
        if (entry_count[DT_RELRSZ] != entry_count[DT_RELR] || entry_count[DT_RELRENT] != entry_count[DT_RELR]) {
            LS_LOG_ERROR("ELF file contains multiple relocatable segments, but the number of relocatable entity size or count doesn't match");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_relr = lsAllocateI(sizeof(DtRelr) * entry_count[DT_RELR], &object->allocationCallbacks);
        if (unlikely(object->dt_relr == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_relr_count = entry_count[DT_RELR];
    }

    if (entry_count[DT_JMPREL]) {
        if (entry_count[DT_PLTRELSZ] != entry_count[DT_JMPREL]) {
            LS_LOG_ERROR("DT_JMPREL count does not match DT_PLTRELSZ count");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_jmprel_ptr = lsAllocateI(sizeof(DtJmprel) * entry_count[DT_JMPREL], &object->allocationCallbacks);
        if (unlikely(object->dt_jmprel_ptr == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_jmprel_count = entry_count[DT_JMPREL];
    }

    if (entry_count[DT_PREINIT_ARRAY]) {
        if (entry_count[DT_PREINIT_ARRAYSZ] != entry_count[DT_PREINIT_ARRAY]) {
            LS_LOG_ERROR("DT_PREINIT_ARRAY count does not match DT_PREINIT_ARRAYSZ count");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_preinit_array_ptr = lsAllocateI(sizeof(dt_preinit_array) * entry_count[DT_PREINIT_ARRAY], &object->allocationCallbacks);
        if (unlikely(object->dt_preinit_array_ptr == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_preinit_array_count = entry_count[DT_PREINIT_ARRAY];
    }

    if (entry_count[DT_INIT_ARRAY]) {
        if (entry_count[DT_INIT_ARRAYSZ] != entry_count[DT_INIT_ARRAY]) {
            LS_LOG_ERROR("DT_INIT_ARRAY count does not match DT_INIT_ARRAYSZ count");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_init_array_ptr = lsAllocateI(sizeof(dt_init_array) * entry_count[DT_INIT_ARRAY], &object->allocationCallbacks);
        if (unlikely(object->dt_init_array_ptr == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_init_array_count = entry_count[DT_INIT_ARRAY];
    }

    if (entry_count[DT_FINI_ARRAY]) {
        if (entry_count[DT_FINI_ARRAYSZ] != entry_count[DT_FINI_ARRAY]) {
            LS_LOG_ERROR("DT_FINI_ARRAY count does not match DT_FINI_ARRAYSZ count");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dt_fini_array_count = entry_count[DT_FINI_ARRAY];
        object->dt_fini_array_ptr = lsAllocateI(sizeof(dt_fini_array) * entry_count[DT_FINI_ARRAY], &object->allocationCallbacks);
        if (unlikely(object->dt_fini_array_ptr == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;

        object->dt_fini_array_count = entry_count[DT_FINI_ARRAY];
    }

    uint64_t i_rel_ptr             = 0;
    uint64_t i_rel_count           = 0;
    uint64_t i_rela_ptr            = 0;
    uint64_t i_rela_count          = 0;
    uint64_t i_relr_ptr            = 0;
    uint64_t i_relr_count          = 0;
    uint64_t i_jmprel_ptr          = 0;
    uint64_t i_jmprel_count        = 0;
    uint64_t i_jmprel_type         = 0;
    uint64_t i_preinit_array_ptr   = 0;
    uint64_t i_preinit_array_count = 0;
    uint64_t i_init_array_ptr      = 0;
    uint64_t i_init_array_count    = 0;
    uint64_t i_fini_array_ptr      = 0;
    uint64_t i_fini_array_count    = 0;

    for (const ElfW(Dyn)* dynamic_info = dynamic_info_begin; dynamic_info < dynamic_info_end; ++dynamic_info) {
        switch (dynamic_info->d_tag) {
            // Shared library tags
            case DT_NEEDED: {
                char* needed = object->dtStrTab + dynamic_info->d_un.d_val;
                if (unlikely((ElfW(Addr)) needed > elf_range)) {
                    LS_LOG_ERROR("DT_NEEDED points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }
                object->objectInfo.pNeededNames[object->objectInfo.neededCount++] = needed;
                break;
            }
            case DT_SONAME: {
                char* soname = object->dtStrTab + dynamic_info->d_un.d_val;
                if (unlikely((ElfW(Addr)) soname > elf_range)) {
                    LS_LOG_ERROR("DT_SONAME points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }
                object->objectInfo.pSoname = soname;
                break;
            }
            case DT_RPATH: {
                char* rpath = object->dtStrTab + dynamic_info->d_un.d_val;
                if (unlikely((ElfW(Addr)) rpath > elf_range)) {
                    LS_LOG_ERROR("DT_RPATH points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }
                object->objectInfo.pRPath = rpath;
                break;
            }
            case DT_RUNPATH: {
                char* run_path = object->dtStrTab + dynamic_info->d_un.d_val;
                if (unlikely((ElfW(Addr)) run_path > elf_range)) {
                    LS_LOG_ERROR("DT_RUNPATH points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }
                object->objectInfo.pRunPath = run_path;
                break;
            }

            // Symbol resolution tags
            case DT_HASH: {
                if (object->symbolTableHashType == GNU)
                    break;

                const ElfW(Addr) hash = object->pLoadAddress + dynamic_info->d_un.d_ptr;
                if (unlikely(hash > elf_range)) {
                    LS_LOG_ERROR("DT_HASH points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }

                object->dtHash = (ElfW(Word)*) hash;
                break;
            }
            case DT_GNU_HASH: {
                const ElfW(Addr) hash = object->pLoadAddress + dynamic_info->d_un.d_ptr;
                if (unlikely(hash > elf_range)) {
                    LS_LOG_ERROR("DT_GNU_HASH points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }

                object->dtHash = (ElfW(Word)*) hash;
                break;
            }
            case DT_SYMTAB: {
                const ElfW(Addr) sym_tab = object->pLoadAddress + dynamic_info->d_un.d_ptr;
                if (unlikely(sym_tab > elf_range)) {
                    LS_LOG_ERROR("DT_SYMTAB points outside of the ELF file");
                    return LS_ERROR_OBJECT_INVALID;
                }

                object->dtSymTabBegin = (ElfW(Sym)*) sym_tab;
                break;
            }
            case DT_SYMENT:
                if (dynamic_info->d_un.d_val != sizeof(ElfW(Sym))) {
                    LS_LOG_ERROR("DT_SYMENT does not match size of ElfW(Sym)");
                    return LS_ERROR_OBJECT_INVALID;
                }
                break;

            // Relocation tags
            case DT_REL:
                object->dt_rel[i_rel_ptr++].rel = (ElfW(Rel)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_RELSZ:
                object->dt_rel[i_rel_count++].rel_count = dynamic_info->d_un.d_val / sizeof(ElfW(Rel));
                break;
            case DT_RELENT:
                if (dynamic_info->d_un.d_val != sizeof(ElfW(Rel))) {
                    LS_LOG_ERROR("DT_RELENT does not match size of ElfW(Rel) in DT_REL");
                    return LS_ERROR_OBJECT_INVALID;
                }
                break;
            case DT_RELA:
                object->dt_rela[i_rela_ptr++].rela = (ElfW(Rela)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_RELASZ:
                object->dt_rela[i_rela_count++].rela_count = dynamic_info->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_RELAENT:
                if (dynamic_info->d_un.d_val != sizeof(ElfW(Rela))) {
                    LS_LOG_ERROR("DT_RELAENT does not match size of ElfW(Rela)");
                    return LS_ERROR_OBJECT_INVALID;
                }
                break;
            case DT_RELR:
                object->dt_relr[i_relr_ptr++].relr = (ElfW(Relr)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_RELRSZ:
                object->dt_relr[i_relr_count++].relr_count = dynamic_info->d_un.d_val / sizeof(ElfW(Relr));
                break;
            case DT_RELRENT:
                if (dynamic_info->d_un.d_val != sizeof(ElfW(Relr))) {
                    LS_LOG_ERROR("DT_RELRENT does not match size of ElfW(Relr)");
                    return LS_ERROR_OBJECT_INVALID;
                }
                break;

            // Memory, PLS, and GOT tags
            case DT_JMPREL: {
                object->dt_jmprel_ptr[i_jmprel_ptr++].ptr = object->pLoadAddress + dynamic_info->d_un.d_ptr;
                break;
            }
            case DT_PLTRELSZ:
                object->dt_jmprel_ptr[i_jmprel_count++].size = dynamic_info->d_un.d_val;
                break;
            case DT_PLTREL:
                object->dt_jmprel_ptr[i_jmprel_type++].type = dynamic_info->d_un.d_val;
                break;

            // Init and de-init related tags
            case DT_PREINIT_ARRAY:
                object->dt_preinit_array_ptr[i_preinit_array_ptr++].ptr = (ElfW(Addr)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                object->dt_preinit_array_ptr[i_preinit_array_count++].count = dynamic_info->d_un.d_val / sizeof(ElfW(Addr));
                break;
            case DT_INIT_ARRAY:
                object->dt_init_array_ptr[i_init_array_ptr++].ptr = (ElfW(Addr)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                object->dt_init_array_ptr[i_init_array_count++].count = dynamic_info->d_un.d_val / sizeof(ElfW(Addr));
                break;
            case DT_FINI_ARRAY:
                object->dt_fini_array_ptr[i_fini_array_ptr++].ptr = (ElfW(Addr)*)(object->pLoadAddress + dynamic_info->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                object->dt_fini_array_ptr[i_fini_array_count++].count = dynamic_info->d_un.d_val / sizeof(ElfW(Addr));
                break;

            case DT_TEXTREL:
                // todo: ask the user if text relocations are allowed
            case DT_SYMBOLIC:
                // todo: Respect DT_SYMBOLIC symbol order
            default:
                break;
        }
    }

    if (unlikely(object->dtSymTabBegin != NULL && object->dtHash == NULL)) {
        if (unlikely((ElfW(Addr)) object->dtStrTab <= (ElfW(Addr)) object->dtSymTabBegin)) {
            LS_LOG_ERROR("DT_STRTAB occurs before DT_SYMTAB in memory, cannot deduce symbol count");
            return LS_ERROR_OBJECT_INVALID;
        }

        object->dtSymTabEnd = (ElfW(Sym)*)((ElfW(Addr)) object->dtStrTab - (ElfW(Addr)) object->dtSymTabBegin);
    }

    for (uint64_t i = 0; i < object->dt_rel_count; ++i) {
        if (unlikely((ElfW(Addr)) object->dt_rel[i].rel >= elf_range)) {
            LS_LOG_ERROR("DT_REL array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely((ElfW(Addr))(object->dt_rel[i].rel + object->dt_rel[i].rel_count) >= elf_range)) {
            LS_LOG_ERROR("DT_REL array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    for (uint64_t i = 0; i < object->dt_rela_count; ++i) {
        if (unlikely((ElfW(Addr)) object->dt_rela[i].rela >= elf_range)) {
            LS_LOG_ERROR("DT_RELA array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely((ElfW(Addr))(object->dt_rela[i].rela + object->dt_rela[i].rela_count) >= elf_range)) {
            LS_LOG_ERROR("DT_RELA array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    for (uint64_t i = 0; i < object->dt_relr_count; ++i) {
        if (unlikely((ElfW(Addr)) object->dt_relr[i].relr >= elf_range)) {
            LS_LOG_ERROR("DT_RELR array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely((ElfW(Addr))(object->dt_relr[i].relr + object->dt_relr[i].relr_count) >= elf_range)) {
            LS_LOG_ERROR("DT_RELR array extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    for (uint64_t i = 0; i < object->dt_jmprel_count; ++i) {
        if (unlikely(object->dt_jmprel_ptr[i].ptr >= elf_range)) {
            LS_LOG_ERROR("DT_JMPREL points outside of the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely(object->dt_jmprel_ptr[i].ptr + object->dt_jmprel_ptr[i].size >= elf_range)) {
            LS_LOG_ERROR("DT_JMPREL extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    for (uint64_t i = 0; i < object->dt_init_array_count; ++i) {
        if (unlikely((ElfW(Addr)) object->dt_init_array_ptr[i].ptr >= elf_range)) {
            LS_LOG_ERROR("DT_INIT_ARRAY points outside of the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely((ElfW(Addr))(object->dt_init_array_ptr[i].ptr + object->dt_init_array_ptr[i].count) >= elf_range)) {
            LS_LOG_ERROR("DT_INIT_ARRAY extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    for (uint64_t i = 0; i < object->dt_fini_array_count; ++i) {
        if (unlikely((ElfW(Addr)) object->dt_fini_array_ptr[i].ptr >= elf_range)) {
            LS_LOG_ERROR("DT_FINI_ARRAY points outside of the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }

        if (unlikely((ElfW(Addr))(object->dt_fini_array_ptr[i].ptr + object->dt_fini_array_ptr[i].count) >= elf_range)) {
            LS_LOG_ERROR("DT_FINI_ARRAY extends beyond the ELF file");
            return LS_ERROR_OBJECT_INVALID;
        }
    }

    return LS_OK;
}

const LsObjectInfo* lsGetObjectInfo(LsObject object) {
    if (unlikely(!object))
        return NULL;

    return &object->objectInfo;
}

static size_t lsGetCommonSymbolCountI(LsObject object) {
    size_t count = 0;
    for (ElfW(Sym)* symbol = object->dtSymTabBegin; symbol < object->dtSymTabEnd; ++symbol) {
        if (symbol->st_shndx == SHN_COMMON)
            ++count;
    }
    return count;
}

/// Implements the PJW hash algorithm by Peter J. Weinberger
/// \param name String to hash
/// \return String hash in range [0, size of unsigned long)
static uint_fast32_t lsPlainHashStringI(const char* name) {
    uint_fast32_t h = 0;

    while (*name) {
        h = (h << 4) + (uint_fast32_t) *name++;
        const uint_fast32_t g = h & 0xf0000000;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }

    return h;
}

/// Implements the DJB2 hash algorithm by Dan Bernstein
/// \param name String to hash
/// \return String hash in range [0, size of unsigned long)
static uint_fast32_t lsGnuHashStringI(const char* name) {
    uint_fast32_t h = 5381;

    for (; *name; name++)
        h = (h << 5) + h + (uint8_t) *name;

    return h;
}

// todo: make the following three functions memory-safe by checking against the ELF file bounds
static ElfW(Sym)* lsGetSymbolAddressNoneI(LsObject object, const char* pSymbolName) {
    for (ElfW(Sym)* symbol = object->dtSymTabBegin; symbol < object->dtSymTabEnd; ++symbol) {
        const char* symbol_name = &object->dtStrTab[symbol->st_name];

        if (strcmp(symbol_name, pSymbolName) == 0)
            return symbol;
    }

    return NULL;
}

static ElfW(Sym)* lsGetSymbolAddressPlainI(LsObject object, const char* pSymbolName) {
    const ElfW(Word) hash = (ElfW(Word)) lsPlainHashStringI(pSymbolName);

    const ElfW(Word) bucket_count   = object->dtHash[0];
    const ElfW(Word)* bucket_begin  = &object->dtHash[2];
    const ElfW(Word)* chain_begin   = &object->dtHash[2 + bucket_count];

    const ElfW(Word) bucket = hash % bucket_count;

    for (ElfW(Word) i = bucket_begin[bucket]; i != STN_UNDEF; i = chain_begin[i]) {
        ElfW(Sym)* symbol = &object->dtSymTabBegin[i];
        const char* symbol_name = &object->dtStrTab[symbol->st_name];

        if (strcmp(symbol_name, pSymbolName) == 0)
            return symbol;
    }

    return NULL;
}

static ElfW(Sym)* lsGetSymbolAddressGnuI(LsObject object, const char* pSymbolName) {
    typedef ElfW(Addr) bloom_el_t;
    const ElfW(Word) name_hash      = (ElfW(Word)) lsGnuHashStringI(pSymbolName);

    const ElfW(Word) n_buckets      = object->dtHash[0];
    const ElfW(Word) sym_offset     = object->dtHash[1];
    const ElfW(Word) bloom_size     = object->dtHash[2];
    const ElfW(Word) bloom_shift    = object->dtHash[3];
    const bloom_el_t* bloom         = (const bloom_el_t*) &object->dtHash[4];
    const ElfW(Word)* buckets       = (const ElfW(Word)*) &bloom[bloom_size];
    const ElfW(Word)* chain         = &buckets[n_buckets];

    const bloom_el_t word = bloom[name_hash / ELFCLASS_BITS % bloom_size];
    const bloom_el_t mask = 0
                          | (bloom_el_t)1 <<  name_hash                 % ELFCLASS_BITS
                          | (bloom_el_t)1 << (name_hash >> bloom_shift) % ELFCLASS_BITS;

    /* If at least one bit is not set, a symbol is surely missing. */
    if ((word & mask) != mask)
        return NULL;

    ElfW(Word) sym_ix = buckets[name_hash % n_buckets];
    if (sym_ix < sym_offset)
        return NULL;

    /* Loop through the chain. */
    while (true) {
        ElfW(Sym) *symbol = &object->dtSymTabBegin[sym_ix];
        const char *symbol_name = &object->dtStrTab[symbol->st_name];
        const ElfW(Word) hash = chain[sym_ix - sym_offset];

        if ((name_hash|1) == (hash|1) && strcmp(pSymbolName, symbol_name) == 0)
            return symbol;

        /* The Chain ends with an element with the lowest bit set to 1. */
        if (hash & 1)
            break;

        sym_ix++;
    }

    return NULL;
}

void* lsGetSymbolAddress(LsObject object, const char* pSymbolName) {
    if (unlikely(object->dtHash == NULL))
        return NULL;

    const ElfW(Sym)* symbol = NULL;
    switch (object->symbolTableHashType) {
        case NONE:
            symbol = lsGetSymbolAddressNoneI(object, pSymbolName);
            break;
        case PLAIN:
            symbol = lsGetSymbolAddressPlainI(object, pSymbolName);
            break;
        case GNU:
            symbol = lsGetSymbolAddressGnuI(object, pSymbolName);
            break;
        default:
            return NULL;
    }

    if (symbol == NULL)
        return NULL;

    return (void*)(object->pLoadAddress + symbol->st_value);
}

static LsStatus lsResolveSymbolI(LsObject object, const LsObjectResolveCallbacks* pCallbacks, const ElfW(Sym)* symbol, void** pSymbolAddress) {
    switch (symbol->st_shndx) {
        case SHN_UNDEF: {
            const char* pSymbolName = &object->dtStrTab[symbol->st_name];
            return pCallbacks->pfnResolveSymbol(pCallbacks->pUserData, object, pSymbolName, pSymbolAddress);
        }

        case SHN_ABS:
            *pSymbolAddress = (void*) symbol->st_value;
            return LS_OK;

        case SHN_COMMON: {
            // Allocate memory for a common symbol:
            // symbol->st_value;     Alignment requirement
            // symbol->st_size;      Size of the symbol

            *pSymbolAddress = lsAlignedAllocateI(symbol->st_size, symbol->st_value, &object->allocationCallbacks);

            if (unlikely(!*pSymbolAddress))
                return LS_ERROR_MEMORY_ALLOCATION_FAILED;

            object->commonSymbolAddresses[object->commonSymbolCount++] = *pSymbolAddress;

            return LS_OK;
        }

        default:
            *pSymbolAddress = (char*) object->pLoadAddress + symbol->st_value;
            return LS_OK;
    }
}

// Resolver for indirect functions
static ElfW(Addr) lsIFuncResolverI(const ElfW(Addr) resolver_address) {
    typedef ElfW(Addr)(*ifunc_resolver_t)(void);
    const ifunc_resolver_t fn = (ifunc_resolver_t) resolver_address;
    // todo: use a user-provided callback, we don't want to execute untrusted code
    return fn();
}

static LsStatus lsResolveRelocationTypeI(LsObject object, const LsObjectResolveCallbacks* pCallbacks, const ElfW(Xword) type, const ElfW(Sym)* symbol, const ElfW(Addr) offset, const ElfW(Sxword) addend, const ElfW(Addr) relocation_address) {
    // "resolved_address" => Resolved address of the relocation
    ElfW(Addr) resolved_address = 0;
    LsStatus status = LS_OK;

    switch (type) {
        // ------------------------------------------------------------------------
        // Absolute relocations: S + A
        //   S = symbol to resolve
        //   A = addend
        // ------------------------------------------------------------------------
        case R_X86_64_64:   // word64
        case R_X86_64_32:   // word32
        case R_X86_64_32S:  // word32 (signed)
        case R_X86_64_16:   // word16
        case R_X86_64_8:    // word8
            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &resolved_address);
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            break;

        // ------------------------------------------------------------------------
        // PC-relative relocations: S + A - P
        //   P = load address of the symbol
        // ------------------------------------------------------------------------
        case R_X86_64_PC64:  // word64
        case R_X86_64_PC32:  // word32
        case R_X86_64_PC16:  // word16
        case R_X86_64_PC8:   // word8
            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &resolved_address);
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            resolved_address -= offset;
            break;

        // ------------------------------------------------------------------------
        // PLT32: L + A - P
        //   L = the address of the PLT entry for this symbol
        // ------------------------------------------------------------------------
        case R_X86_64_PLT32: {
            resolved_address  = (ElfW(Addr)) object->dt_pltgot;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            resolved_address -= offset;
            break;
        }

        // ------------------------------------------------------------------------
        // Global offset table-based relocations: G + A
        //   G = offset (or address) of GOT entry for symbol
        // ------------------------------------------------------------------------
        case R_X86_64_GOT32: {
            if (unlikely(object->dt_pltgot == NULL))
                return LS_ERROR_OBJECT_INVALID;

            resolved_address  = offset;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            break;
        }

        // ------------------------------------------------------------------------
        // Global offset table-based relocations: GOT + A - P
        //   GOT = Global offset table address
        // ------------------------------------------------------------------------
        case R_X86_64_GOTPC32: {
            if (unlikely(object->dt_pltgot == NULL))
                return LS_ERROR_OBJECT_INVALID;

            resolved_address  = (ElfW(Addr)) object->dt_pltgot;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            resolved_address -= offset;
            break;
        }

        // ------------------------------------------------------------------------
        // Global offset table-based relocations: G + GOT + A - P
        //   G = offset (or address) of GOT entry for symbol
        // ------------------------------------------------------------------------
        case R_X86_64_GOTPCREL: {
            if (unlikely(object->dt_pltgot == NULL))
                return LS_ERROR_OBJECT_INVALID;

            // todo: symbol should be of type R_X86_64_GLOB_DAT
            uint64_t symbol_address;
            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &symbol_address);
            resolved_address  = symbol_address;
            resolved_address += (ElfW(Addr)) object->dt_pltgot;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            resolved_address -= offset;
            break;
        }

        // ------------------------------------------------------------------------
        // Global offset table-based relocations: S + A - GOT
        // ------------------------------------------------------------------------
        case R_X86_64_GOTOFF64:
            if (unlikely(object->dt_pltgot == NULL))
                return LS_ERROR_OBJECT_INVALID;

            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &resolved_address);
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            resolved_address -= (ElfW(Addr)) object->dt_pltgot;
            break;

        // ------------------------------------------------------------------------
        // SIZE relocations: Z + A
        //   Z = size of the symbol
        // ------------------------------------------------------------------------
        case R_X86_64_SIZE64:
        case R_X86_64_SIZE32:
            resolved_address  = symbol->st_size;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            break;

        // ------------------------------------------------------------------------
        // GLOB_DAT / JUMP_SLOT: S
        // ------------------------------------------------------------------------
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &resolved_address);
            break;

        // ------------------------------------------------------------------------
        // RELATIVE: B + A
        //   B = base address (pLoadAddress)
        // ------------------------------------------------------------------------
        case R_X86_64_RELATIVE:
            resolved_address  = object->pLoadAddress;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            break;

        // ------------------------------------------------------------------------
        // IRELATIVE: indirect (B + A)
        //   Like RELATIVE, but the result is the address of a resolver function
        //   that must be called to get the final pointer. Used for IFUNC.
        // ------------------------------------------------------------------------
        case R_X86_64_IRELATIVE: {
            // "B + A"
            const ElfW(Addr) resolver_address = (ElfW(Addr)) ((ElfW(Sxword)) object->pLoadAddress + addend);
            // Call the ifunc resolver to get the real target address:
            resolved_address = lsIFuncResolverI(resolver_address);
            break;
        }

        // ------------------------------------------------------------------------
        // RELATIVE64: B + A
        // ------------------------------------------------------------------------
        case R_X86_64_RELATIVE64:
            resolved_address  = object->pLoadAddress;
            resolved_address = (ElfW(Addr)) ((ElfW(Sxword)) resolved_address + addend);
            break;

        // ------------------------------------------------------------------------
        // COPY: special "copy" relocation for global data
        //   S = symbol to copy value from
        // ------------------------------------------------------------------------
        case R_X86_64_COPY: {
            status = lsResolveSymbolI(object, pCallbacks, symbol, (void**) &resolved_address);
            if (unlikely(status != LS_OK))
                return status;

            memcpy((void*) relocation_address,
                   (void*) resolved_address,
                   symbol->st_size);

            return LS_OK;
        }

        // NONE: no relocation
        case R_X86_64_NONE:
            return LS_OK;

        // TLS relocations
        case R_X86_64_DTPMOD64:
        case R_X86_64_DTPOFF64:
        case R_X86_64_TPOFF64:
        case R_X86_64_TLSGD:
        case R_X86_64_TLSLD:
        case R_X86_64_DTPOFF32:
        case R_X86_64_GOTTPOFF:
        case R_X86_64_TPOFF32:

        // TLS descriptor relocations
        case R_X86_64_GOTPC32_TLSDESC:
        case R_X86_64_TLSDESC_CALL:
        case R_X86_64_TLSDESC:
            LS_LOG_WARNING_F(&object->allocationCallbacks, "TLS relocations not implemented: type=%d", type);
            return LS_OK;
            //return LS_ERROR_OBJECT_INVALID;

        // “relocation compression” or “relocation relax” types
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
            LS_LOG_WARNING_F(&object->allocationCallbacks, "Relocation relaxation or specialized TLS desc not implemented: type=%d", type);
            return LS_OK;
            //return LS_ERROR_OBJECT_INVALID;

        // Default fallback
        default:
            LS_LOG_WARNING_F(&object->allocationCallbacks, "Unknown or unhandled relocation type: %d", type);
            return LS_OK;
            //return LS_ERROR_OBJECT_INVALID;
    }

    switch (status) {
        case LS_OK:
            break;
        case LS_ERROR_SYMBOL_NOT_FOUND:
            if (ElfW_ST_BIND(symbol->st_info) != STB_WEAK)
                return status;
            break;
        default:
            return status;
    }

    // todo: check if symbol is within the bounds of the object

    switch (type) {
        case R_X86_64_64:
        case R_X86_64_PC64:
        case R_X86_64_RELATIVE64:
        case R_X86_64_GOTOFF64:
        case R_X86_64_SIZE64:
            *(uint64_t*)   relocation_address = (uint64_t) resolved_address;
            break;

        case R_X86_64_32:
        case R_X86_64_32S:
        case R_X86_64_PC32:
        case R_X86_64_PLT32:
        case R_X86_64_GOT32:
        case R_X86_64_GOTPC32:
        case R_X86_64_GOTPCREL:
        case R_X86_64_SIZE32:
            *(uint32_t*)   relocation_address = (uint32_t) resolved_address;
            break;

        case R_X86_64_16:
        case R_X86_64_PC16:
            *(uint16_t*)   relocation_address = (uint16_t) resolved_address;
            break;

        case R_X86_64_8:
        case R_X86_64_PC8:
            *(uint8_t*)    relocation_address = (uint8_t) resolved_address;
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_RELATIVE:
        case R_X86_64_IRELATIVE:
            *(ElfW(Addr)*) relocation_address = resolved_address;
            break;

        default:
            LS_LOG_ERROR("Unhandled relocation size");
            return LS_ERROR_INTERNAL;
    }

    return LS_OK;
}

static LsStatus lsProcessRelocationRelI(LsObject object, const LsObjectResolveCallbacks* pCallbacks, const ElfW(Rel)* relocation) {
    const ElfW(Sym)* symbol = object->dtSymTabBegin + ElfMW(R_SYM)(relocation->r_info);
    const ElfW(Xword) type  = ElfMW(R_TYPE)(relocation->r_info);

    const ElfW(Addr) relocation_address = object->pLoadAddress + relocation->r_offset;
    const ElfW(Sxword) addend = *(ElfW(Sxword)*) relocation_address;
    // todo: range check

    return lsResolveRelocationTypeI(object, pCallbacks, type, symbol, relocation->r_offset, addend, relocation_address);
}

static LsStatus lsProcessRelocationRelaI(LsObject object, const LsObjectResolveCallbacks* pCallbacks, const ElfW(Rela)* relocation) {
    const ElfW(Sym)* symbol = object->dtSymTabBegin + ElfMW(R_SYM)(relocation->r_info);
    const ElfW(Xword) type  = ElfMW(R_TYPE)(relocation->r_info);

    const ElfW(Addr) relocation_address = object->pLoadAddress + relocation->r_offset;

    return lsResolveRelocationTypeI(object, pCallbacks, type, symbol, relocation->r_offset, relocation->r_addend, relocation_address);
}

static LsStatus lsProcessRelocationRelrI(LsObject object, const LsObjectResolveCallbacks* pCallbacks, const ElfW(Relr)* relocation, ElfW(Addr)** where) {
    // todo: we are making the assumption here that the .rela.dyn section is placed in an odd location which technically is not required by the ELF spec
    // todo: range check

    unused(pCallbacks);

    // Taken from: https://maskray.me/blog/2021-10-31-relative-relocations-and-relr
    ElfW(Relr) entry = *relocation;
    if ((entry & 1) == 0) {
        *where = (ElfW(Addr)*) (object->pLoadAddress + entry);
        *(*where)++ += object->pLoadAddress;
    } else {
        for (uint64_t i = 0; (entry >>= 1) != 0; i++)
            if ((entry & 1) != 0)
                (*where)[i] += object->pLoadAddress;

        *where += CHAR_BIT * sizeof(ElfW(Relr)) - 1;
    }

    return LS_OK;
}

static LsStatus lsProcessRelocationsI(LsObject object, const LsObjectResolveCallbacks* pCallbacks) {
    {
        const DtRel* relocation_table_begin = object->dt_rel;
        const DtRel* relocation_table_end   = relocation_table_begin + object->dt_rel_count;

        for (const DtRel* relocation_table = relocation_table_begin; relocation_table < relocation_table_end; ++relocation_table) {
            const ElfW(Addr) relocation_count = relocation_table->rel_count;
            const ElfW(Rel)* relocation_begin = relocation_table->rel;
            const ElfW(Rel)* relocation_end   = relocation_begin + relocation_count;

            for (const ElfW(Rel)* relocation = relocation_begin; relocation < relocation_end; ++relocation) {
                const LsStatus status = lsProcessRelocationRelI(object, pCallbacks, relocation);
                if (unlikely(status != LS_OK))
                    return status;

                // todo: better error handling
            }
        }
    }

    {
        const DtRela* relocation_table_begin    = object->dt_rela;
        const DtRela* relocation_table_end      = relocation_table_begin + object->dt_rela_count;

        for (const DtRela* relocation_table     = relocation_table_begin; relocation_table < relocation_table_end; ++relocation_table) {
            const ElfW(Addr) relocation_count   = relocation_table->rela_count;
            const ElfW(Rela)* relocation_begin  = relocation_table->rela;
            const ElfW(Rela)* relocation_end    = relocation_begin + relocation_count;

            for (const ElfW(Rela)* relocation = relocation_begin; relocation < relocation_end; ++relocation) {
                const LsStatus status = lsProcessRelocationRelaI(object, pCallbacks, relocation);
                if (unlikely(status != LS_OK))
                    return status;
            }
        }
    }

    {
        const DtRelr* relocation_table_begin    = object->dt_relr;
        const DtRelr* relocation_table_end      = relocation_table_begin + object->dt_relr_count;

        for (const DtRelr*    relocation_table  = relocation_table_begin; relocation_table < relocation_table_end; ++relocation_table) {
            const ElfW(Addr)  relocation_count  = relocation_table->relr_count;
            const ElfW(Relr)* relocation_begin  = relocation_table->relr;
            const ElfW(Relr)* relocation_end    = relocation_begin + relocation_count;

            ElfW(Addr)* where;
            for (const ElfW(Relr)* relocation = relocation_begin; relocation < relocation_end; ++relocation) {
                const LsStatus status = lsProcessRelocationRelrI(object, pCallbacks, relocation, &where);
                if (unlikely(status != LS_OK))
                    return status;
            }
        }
    }

    {
        const DtJmprel* jmprel_table_begin  = object->dt_jmprel_ptr;
        const DtJmprel* jmprel_table_end    = jmprel_table_begin + object->dt_jmprel_count;

        for (const DtJmprel* jmprel_table   = jmprel_table_begin; jmprel_table < jmprel_table_end; ++jmprel_table) {
            const ElfW(Addr) jmprel_size    = jmprel_table->size;
            const ElfW(Addr) jmprel_begin   = jmprel_table->ptr;
            const ElfW(Addr) jmprel_end     = jmprel_begin + jmprel_size;

            switch (jmprel_table->type) {
                case REL: {
                    for (const ElfW(Rel)* relocation = (ElfW(Rel)*) jmprel_begin; relocation < (ElfW(Rel)*) jmprel_end; relocation++) {
                        const LsStatus status = lsProcessRelocationRelI(object, pCallbacks, relocation);
                        if (unlikely(status != LS_OK))
                            return status;
                    }
                    break;
                }
                case RELA: {
                    for (const ElfW(Rela)* relocation = (ElfW(Rela)*) jmprel_begin; relocation < (ElfW(Rela)*) jmprel_end; relocation++) {
                        const LsStatus status = lsProcessRelocationRelaI(object, pCallbacks, relocation);
                        if (unlikely(status != LS_OK))
                            return status;
                    }
                    break;
                }
                case RELR: {
                    ElfW(Addr)* where;
                    for (const ElfW(Relr)* relocation = (ElfW(Relr)*) jmprel_begin; relocation < (ElfW(Relr)*) jmprel_end; relocation++) {
                        const LsStatus status = lsProcessRelocationRelrI(object, pCallbacks, relocation, &where);
                        if (unlikely(status != LS_OK))
                            return status;
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }

    return LS_OK;
}

static LsStatus lsDefaultResolveSymbolCallback(void* pUserData, LsObject object, const char* pSymbolName, void** pSymbolAddress) {
    unused(pUserData);

    *pSymbolAddress = lsGetSymbolAddress(object, pSymbolName);
    if (*pSymbolAddress == NULL)
        return LS_ERROR_SYMBOL_NOT_FOUND;

    return LS_OK;
}

static LsStatus lsDefaultLoadNeededCallback(void* pUserData, LsObject object, const char* pNeededName) {
    unused(pUserData);
    unused(object);
    unused(pNeededName);

    return LS_ERROR_FEATURE_NOT_SUPPORTED;
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

static LsObjectLoadCallbacks gDefaultLoadCallbacks = {
    NULL,
    lsDefaultLoadNeededCallback
};

LsStatus lsLoadObject(LsObject object, const LsObjectLoadCallbacks* pLoadCallbacks) {
    LsStatus status = lsValidateHeaderI(object);
    if (status != LS_OK)
        return status;

    LsObjectLoadCallbacks loadCallbacks;
    if (pLoadCallbacks != NULL) {
        loadCallbacks = *pLoadCallbacks;
        if (loadCallbacks.pfnLoadNeeded == NULL)
            loadCallbacks.pfnLoadNeeded = gDefaultLoadCallbacks.pfnLoadNeeded;
    } else
        loadCallbacks = gDefaultLoadCallbacks;

    status = lsParseSegmentsI(object);
    if (status != LS_OK)
        return status;

    status = lsLoadSegmentsI(object);
    if (status != LS_OK)
        return status;

    status = lsParseDynamicSegmentI(object);
    if (status != LS_OK)
        return status;

    for (uint64_t i = 0; i < object->objectInfo.neededCount; ++i) {
        const char* loaded_name = object->objectInfo.pNeededNames[i];

        status = loadCallbacks.pfnLoadNeeded(loadCallbacks.pUserData, object, loaded_name);
        if (status != LS_OK)
            return status;
    }

    return LS_OK;
}

static LsObjectResolveCallbacks gDefaultResolveCallbacks = {
    NULL,
    lsDefaultResolveSymbolCallback
};

LsStatus lsResolveObject(LsObject object, const LsObjectResolveCallbacks* pResolveCallbacks) {
    LsObjectResolveCallbacks resolveCallbacks;
    if (pResolveCallbacks != NULL) {
        resolveCallbacks = *pResolveCallbacks;
        if (resolveCallbacks.pfnResolveSymbol == NULL)
            resolveCallbacks.pfnResolveSymbol = gDefaultResolveCallbacks.pfnResolveSymbol;
    } else
        resolveCallbacks = gDefaultResolveCallbacks;

    const size_t symbol_count = lsGetCommonSymbolCountI(object);
    if (symbol_count > 0) {
        object->commonSymbolAddresses = lsAllocateI(sizeof(void*) * symbol_count, &object->allocationCallbacks);
        if (unlikely(object->commonSymbolAddresses == NULL))
            return LS_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    const LsStatus status = lsProcessRelocationsI(object, &resolveCallbacks);
    return status;
}


//############################//
//        INI and FINI        //
//############################//

static void lsCallObjectFunctionInitI(LsObject object, const LsObjectInitializeCallbacks* pFunctionCallbacks, ElfW(Addr) function_address) {
    if (function_address == 0)
        return;

    pFunctionCallbacks->pfnCallObjectFunction(pFunctionCallbacks->pUserData, object, (void*) function_address);
}

static void lsCallInitializersI(LsObject object, const LsObjectInitializeCallbacks* pInitializeCallbacks) {
    for (uint32_t preinit_array_index = 0; preinit_array_index < object->dt_preinit_array_count; ++preinit_array_index) {
        const ElfW(Addr)* preinit_array_begin = object->dt_preinit_array_ptr[preinit_array_index].ptr;
        const ElfW(Addr)* preinit_array_end = preinit_array_begin + object->dt_preinit_array_ptr[preinit_array_index].count;

        for (const ElfW(Addr)* preinit_array_ptr = preinit_array_begin; preinit_array_ptr < preinit_array_end; ++preinit_array_ptr) {
            if (*preinit_array_ptr == 0)
                continue;

            lsCallObjectFunctionInitI(object, pInitializeCallbacks, *preinit_array_ptr);
        }
    }

    if (object->dt_init)
        lsCallObjectFunctionInitI(object, pInitializeCallbacks, object->dt_init);

    for (uint32_t init_array_index = 0; init_array_index < object->dt_init_array_count; ++init_array_index) {
        const ElfW(Addr)* init_array_begin = object->dt_init_array_ptr[init_array_index].ptr;
        const ElfW(Addr)* init_array_end = init_array_begin + object->dt_init_array_ptr[init_array_index].count;

        for (const ElfW(Addr)* init_array_ptr = init_array_begin; init_array_ptr < init_array_end; ++init_array_ptr) {
            if (*init_array_ptr == 0)
                continue;

            lsCallObjectFunctionInitI(object, pInitializeCallbacks, *init_array_ptr);
        }
    }
}

static void lsCallObjectFunctionFiniI(LsObject object, const LsObjectFinalizeCallbacks* pFunctionCallbacks, ElfW(Addr) function_address) {
    if (function_address == 0)
        return;

    pFunctionCallbacks->pfnCallObjectFunction(pFunctionCallbacks->pUserData, object, (void*) function_address);
}

static void lsCallFinalizersI(LsObject object, const LsObjectFinalizeCallbacks* pFinalizeCallbacks) {
    for (uint32_t fini_array_index = 0; fini_array_index < object->dt_fini_array_count; ++fini_array_index) {
        const ElfW(Addr)* fini_array_begin = object->dt_fini_array_ptr[fini_array_index].ptr;
        const ElfW(Addr)* fini_array_end = fini_array_begin + object->dt_fini_array_ptr[fini_array_index].count;

        for (const ElfW(Addr)* fini_array_ptr = fini_array_end - 1; fini_array_ptr >= fini_array_begin; --fini_array_ptr) {
            if (*fini_array_ptr == 0)
                continue;

            lsCallObjectFunctionFiniI(object, pFinalizeCallbacks, *fini_array_ptr);
        }
    }

    if (object->dt_fini)
        lsCallObjectFunctionFiniI(object, pFinalizeCallbacks, object->dt_fini);
}

static void lsDefaultCallObjectFunctionCallbackI(void* pUserData, LsObject object, void* pFunction) {
    unused(pUserData);
    unused(object);

    union {
        void* obj;
        void (*func)(void);
    } u;

    u.obj = pFunction;
    u.func();
}

static LsObjectInitializeCallbacks gDefaultInitializeCallback = {
    NULL,
    lsDefaultCallObjectFunctionCallbackI
};

static LsObjectFinalizeCallbacks gDefaultFinalizeCallback = {
    NULL,
    lsDefaultCallObjectFunctionCallbackI
};

LsStatus lsInitializeObject(LsObject object, const LsObjectInitializeCallbacks* pInitializeCallbacks) {
    // We won't announce the load any earlier since the user can drag apart loading and initialization
    // If objects are loaded out of order or dlopen() is called this would confuse the debugger
    if (object->debugSupport == LS_DEBUG_SUPPORT_ENABLE_GNU)
        lsDebugSupportAnnounceLoadI(object);

    if (object->debugSupport == LS_DEBUG_SUPPORT_ENABLE_GNU)
        lsDebugSupportAnnounceLoadedI(object);

    LsObjectInitializeCallbacks initializeCallbacks;
    if (pInitializeCallbacks != NULL) {
        initializeCallbacks = *pInitializeCallbacks;
        if (initializeCallbacks.pfnCallObjectFunction == NULL)
            initializeCallbacks.pfnCallObjectFunction = gDefaultInitializeCallback.pfnCallObjectFunction;
    } else
        initializeCallbacks = gDefaultInitializeCallback;

    lsCallInitializersI(object, &initializeCallbacks);

    return LS_OK;
}

LsStatus lsFinalizeObject(LsObject object, const LsObjectFinalizeCallbacks* pFinalizeCallbacks) {
    if (object->debugSupport == LS_DEBUG_SUPPORT_ENABLE_GNU)
        lsDebugSupportAnnounceUnloadI(object);

    LsObjectFinalizeCallbacks finalizeCallbacks;
    if (pFinalizeCallbacks != NULL) {
        finalizeCallbacks = *pFinalizeCallbacks;
        if (finalizeCallbacks.pfnCallObjectFunction == NULL)
            finalizeCallbacks.pfnCallObjectFunction = gDefaultFinalizeCallback.pfnCallObjectFunction;
    } else
        finalizeCallbacks = gDefaultFinalizeCallback;

    lsCallFinalizersI(object, &finalizeCallbacks);

    return LS_OK;
}
