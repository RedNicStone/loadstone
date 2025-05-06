/// @file loadstone.h
/// @brief Public header for Loadstone, a lightweight, flexible library for loading ELF relocatable files.

#ifndef LOADSTONE_H
#define LOADSTONE_H

#ifdef __cplusplus
#include <cstdint>
#else
#include <stddef.h>
#endif

#ifdef __cplusplus
//extern "C" {
#endif

/// @brief Defines an opaque handle type for an object.
#define LS_HANDLE(object) typedef struct object##_T* object;

/// @brief Opaque handle type for a shared object.
LS_HANDLE(LsObject)

/// @brief Status codes returned by Loadstone API functions.
typedef enum LsStatus {
    LS_OK                             =      0, ///< Operation successful.
    LS_ERROR                          =     -1, ///< General error.

    LS_ERROR_INTERNAL                 = -0x100, ///< Internal error.
    LS_ERROR_INVALID_ARGUMENT         = -0x101, ///< Invalid argument passed.
    LS_ERROR_OBJECT_INVALID           = -0x102, ///< Invalid object handle.
    LS_ERROR_FEATURE_NOT_SUPPORTED    = -0x103, ///< Feature not supported.
    LS_ERROR_SYMBOL_NOT_FOUND         = -0x104, ///< Symbol not found.

    LS_ERROR_SYSTEM                   = -0x200, ///< System-related error.
    LS_ERROR_MEMORY_ALLOCATION_FAILED = -0x201, ///< Memory allocation failure.
    LS_ERROR_FILE_ACTION_FAILED       = -0x202, ///< File operation failed.
    LS_ERROR_MEMORY_MAP_FAILED        = -0x203, ///< Memory mapping failed.
} LsStatus;

/// @brief Severity levels for messages.
typedef enum LsSeverity {
    LS_SEVERITY_INFO    = 0, ///< Informational message.
    LS_SEVERITY_WARNING = 1, ///< Warning message.
    LS_SEVERITY_ERROR   = 2, ///< Error message.
    LS_SEVERITY_COUNT   = 3, ///< Total number of severities.
} LsSeverity;

/// @brief Type of symbol.
typedef enum LsSymbolType {
    LS_SYMBOL_EXTERNAL = 0, ///< External symbol.
    LS_SYMBOL_LOCAL    = 1, ///< Local symbol.
} LsSymbolType;

/// @brief Options for debug support during loading.
/// @details    Debug support involves setting up a debug state and notifying the debugger about the load and unload of the object.
///             This is only supported on GNU systems currently, but should work on both GDB and LLDB.
/// @attention  GNU debug support requires external dynamic linkage against ld-linux.so.2 (typically provided by the C library).
typedef enum LsDebugSupport {
    LS_DEBUG_SUPPORT_DISABLE    = 0, ///< Disable debug support.
    LS_DEBUG_SUPPORT_ENABLE_GNU = 1, ///< Enable GNU debug support.
} LsDebugSupport;

/// @brief Callback for logging messages.
/// @param pUserData        [in] User data passed in LsMessageCallbacks.
/// @param severity         [in] Severity of the message.
/// @param pMessage         [in] Message to log.
typedef void (*LsMessageCallback)(void *pUserData, LsSeverity severity, const char *pMessage);

/// @brief Callback for memory allocation.
/// @param pUserData        [in] User data passed in LsAllocationCallbacks.
/// @param size             [in] Size of the memory to allocate.
/// @return     Pointer to the allocated memory.
///             Returning NULL indicates that the allocation failed.
typedef void * (*LsAllocationFunction)(void *pUserData, size_t size);

/// @brief Callback for memory reallocation.
/// @param pUserData        [in] User data passed in LsReallocationCallbacks.
/// @param ptr              [in] Pointer to the memory to reallocate.
/// @param size             [in] Size of the memory to reallocate.
/// @return     Pointer to the reallocated memory.
///             Returning NULL indicates that the reallocation failed.
typedef void * (*LsReallocationFunction)(void *pUserData, void *ptr, size_t size);

/// @brief Callback for freeing memory.
/// @param pUserData        [in] User data passed in LsFreeCallbacks.
/// @param ptr              [in] Pointer to the memory to free.
typedef void (*LsFreeFunction)(void *pUserData, void *ptr);

/// @brief Callback for aligned memory allocation.
/// @param pUserData        [in] User data passed in LsAllocationCallbacks.
/// @param size             [in] Size of the memory to allocate.
/// @param alignment        [in] Alignment of the memory to allocate.
/// @return     Pointer to the allocated memory, aligned to the specified alignment.
///             Returning NULL indicates that the allocation failed.
typedef void * (*LsAlignedAllocationFunction)(void *pUserData, size_t size, size_t alignment);

/// @brief Callback for freeing aligned memory.
/// @param pUserData        [in] User data passed in LsFreeCallbacks.
/// @param ptr              [in] Pointer to the aligned memory to free.
typedef void (*LsAlignedFreeFunction)(void *pUserData, void *ptr);

/// @brief Callback for loading needed shared objects.
/// @param pUserData        [in] User data passed in LsObjectLoadCallbacks.
/// @param object           [in] Object handle.
/// @param pNeededName      [in] Name of the library to load.
/// @return     Status code of the operation.
///             Returning LS_OK indicates that the library was loaded. Any other value indicates an error.
/// @details    Callback to load a needed object (typically a shared library linked by the object being loaded).
///             Resolving the library name to a full path is the responsibility of the user.
///             If the callback is not provided, the default behavior is to fail the load.
typedef LsStatus (*LsLoadNeededCallback)(void *pUserData, LsObject object, const char *pNeededName);

/// @brief Callback for resolving symbols.
/// @param pUserData        [in] User data passed in LsObjectResolveCallbacks.
/// @param object           [in] Object handle.
/// @param pSymbolName      [in] Name of the symbol to resolve.
/// @param pSymbolAddress   [out] Pointer to the resolved symbol.
/// @return     Status code of the operation.
///             Returning LS_OK indicates that the symbol was resolved. Any other value indicates an error.
/// @details    Callback to perform symbol resolution.
///             If the callback is not provided, the default behavior is to fail the resolution.
typedef LsStatus (*LsResolveSymbolCallback)(void *pUserData, LsObject object, const char *pSymbolName,
                                            void **pSymbolAddress);

/// @brief Callback for calling object functions (e.g., init/fini functions).
/// @param pUserData        [in] User data passed in LsObjectInitializeCallbacks or LsObjectFinalizeCallbacks.
/// @param object           [in] Object handle.
/// @param pFunction        [optional] Pointer to the function to call.
/// @details    This callback is provided to allow sandboxing of function calls.
///             If the callback is not provided, the default behavior is to call the function directly.
typedef void (*LsCallObjectFunction)(void *pUserData, LsObject object, void *pFunction);

/// @brief Message callback information.
typedef struct LsMessageCallbacks {
    void *pUserData;              ///< User data passed to the callback.
    LsMessageCallback pfnMessage; ///< Message callback function.
} LsMessageCallbacks;

/// @brief Memory allocation callback information.
typedef struct LsAllocationCallbacks {
    void *pUserData;                                      ///< User data passed to the allocation callbacks.
    LsAllocationFunction pfnAllocation;                   ///< Allocation callback.
    LsReallocationFunction pfnReallocation;               ///< Reallocation callback.
    LsFreeFunction pfnFree;                               ///< Free callback.
    LsAlignedAllocationFunction pfnAlignedAllocation;     ///< Aligned allocation callback.
    LsAlignedFreeFunction pfnAlignedFree;                 ///< Aligned free callback.
} LsAllocationCallbacks;

/// @brief Callback for loading needed libraries.
typedef struct LsObjectLoadCallbacks {
    void *pUserData;                    ///< User data.
    LsLoadNeededCallback pfnLoadNeeded; ///< Callback to load a needed object.
} LsObjectLoadCallbacks;

/// @brief Callback for resolving symbols.
typedef struct LsObjectResolveCallbacks {
    void *pUserData;                          ///< User data.
    LsResolveSymbolCallback pfnResolveSymbol; ///< Callback to resolve a symbol.
} LsObjectResolveCallbacks;

/// @brief Callback for initializing a shared object.
typedef struct LsObjectInitializeCallbacks {
    void *pUserData;                            ///< User data.
    LsCallObjectFunction pfnCallObjectFunction; ///< Function to call object functions.
} LsObjectInitializeCallbacks;

/// @brief Callback for finalizing a shared object.
typedef struct LsObjectFinalizeCallbacks {
    void *pUserData;                            ///< User data.
    LsCallObjectFunction pfnCallObjectFunction; ///< Function to call object functions.
} LsObjectFinalizeCallbacks;

/// @brief Information about a loaded object.
typedef struct LsObjectInfo {
    void *pLoadAddress;        ///< Base address of loaded object. NULL if not yet loaded.
    const char *pPath;         ///< Path to the file. NULL if loaded from memory.
    const char *pSoname;       ///< SONAME of the object. NULL if not set.
    const char *pRPath;        ///< RPATH of the binary. NULL if not set.
    const char *pRunPath;      ///< RUNPATH of the binary. NULL if not set.
    const char **pNeededNames; ///< Names of needed libraries.
    unsigned int neededCount;  ///< Number of needed libraries.
} LsObjectInfo;

/**
 * @brief Sets the global message callback.
 * @param pCallback         [optional] Pointer to message callbacks structure.
 * @details     The default behaviour is to not log any messages.
 *              If pCallback or pCallback->pfnMessage is NULL, behaviour reverts to the default.
 */
void lsSetMessageCallback(const LsMessageCallbacks *pCallback);

/**
 * @brief Converts a severity value to a string.
 * @param severity          [in] Severity level.
 * @return      String representation, with no decoration and capital letters (e.g., "INFO").
 */
const char *lsSeverityToString(LsSeverity severity);

/**
 * @brief Opens a shared object from memory.
 * @param pElf              [in] Pointer to ELF memory.
 * @param elfSize           [in] Size of ELF memory.
 * @param debugSupport      [in] Debug support options.
 * @param pObject           [out] Output object handle.
 * @param pAllocationCallbacks [optional] Optional memory allocation callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 * @warning    Currently NOT implemented.
 */
LsStatus lsOpenObjectFromMemory(
    const void *pElf,
    size_t elfSize,
    LsDebugSupport debugSupport,
    LsObject *pObject,
    const LsAllocationCallbacks *pAllocationCallbacks
);

/**
 * @brief Opens a shared object from a file path.
 * @param pPath             [in] Path to the ELF file.
 * @param debugSupport      [in] Debug support options.
 * @param pObject           [out] Output object handle.
 * @param pAllocationCallbacks [optional] Optional memory allocation callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 */
LsStatus lsOpenObjectFromFile(
    const char *pPath,
    LsDebugSupport debugSupport,
    LsObject *pObject,
    const LsAllocationCallbacks *pAllocationCallbacks
);

/**
 * @brief Closes a shared object.
 * @param object            [in] Object handle.
 */
void lsCloseObject(LsObject object);

/**
 * @brief Loads dependencies for a shared object.
 * @param object            [in] Object handle.
 * @param pLoadCallbacks    [in] Load callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 */
LsStatus lsLoadObject(LsObject object, const LsObjectLoadCallbacks *pLoadCallbacks);

/**
 * @brief Resolves symbols for a shared object.
 * @param object            [in] Object handle.
 * @param pResolveCallbacks [in] Resolve callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 */
LsStatus lsResolveObject(LsObject object, const LsObjectResolveCallbacks *pResolveCallbacks);

/**
 * @brief Initializes a shared object (calls init functions).
 * @param object            [in] Object handle.
 * @param pInitializeCallbacks [in] Initialization callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 */
LsStatus lsInitializeObject(LsObject object, const LsObjectInitializeCallbacks *pInitializeCallbacks);

/**
 * @brief Finalizes a shared object (calls fini functions).
 * @param object            [in] Object handle.
 * @param pFinalizeCallbacks [in] Finalization callbacks. Set to NULL to use default callbacks.
 * @return     Status code. LT_OK indicates success, any other value indicates an error.
 */
LsStatus lsFinalizeObject(LsObject object, const LsObjectFinalizeCallbacks *pFinalizeCallbacks);

/**
 * @brief Gets information about a loaded object.
 * @param object            [in] Object handle.
 * @return     Const pointer to object info structure. Modifying the returned structure will cause undefined behaviour.
 *             If the object is NULL, the function returns NULL.
 */
const LsObjectInfo *lsGetObjectInfo(LsObject object);

/**
 * @brief Gets the address of a symbol in a shared object.
 * @param object            [in] Object handle.
 * @param pSymbolName       [in] Name of the symbol.
 * @return     Pointer to the symbol, or NULL if not found.
 * @warning    This function signature will likely change in the future to return more information.
 */
void *lsGetSymbolAddress(LsObject object, const char *pSymbolName);

#ifdef __cplusplus
//}
#endif

#endif // LOADSTONE_H
