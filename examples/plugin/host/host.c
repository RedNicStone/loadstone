
#include "host.h"

#include <loadstone.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOSERVICE
#define NOMCX
#define NOIME
#include <windows.h>
#else
#include <unistd.h>
#endif

__attribute__((sysv_abi))
void host_print(const char* pString) {
    fputs(pString, stdout);
}

void message_callback(void* pUserData, LsSeverity severity, const char* pMessage) {
    printf("[HOST] [%s] %s\n", lsSeverityToString(severity), pMessage);
}

typedef struct load_chain {
    LsObject object;
    struct load_chain* pNext;
} load_chain;

load_chain* load_chains = NULL;
char* binary_path = NULL;

LsStatus load_needed_callback(void* pUserData, LsObject object, const char* pNeededName) {
    const char* pPath = "(no object)";
    if (object) {
        const LsObjectInfo* info = lsGetObjectInfo(object);
        if (info->pPath)
            pPath = info->pPath;
        else
            pPath = "(memory loaded)";
    }

    printf("[HOST] Loading %s for %s\n", pNeededName, pPath);

    size_t binary_path_length = strlen(binary_path);
    while (binary_path_length > 0 && binary_path[--binary_path_length - 1] != '/') {}

    const size_t needed_name_length = strlen(pNeededName);
    const size_t needed_path_length = binary_path_length + needed_name_length + 1;
    char* needed_path = malloc(needed_path_length);
    memcpy(needed_path, binary_path, binary_path_length);
    memcpy(needed_path + binary_path_length, pNeededName, needed_name_length + 1);

    printf("[HOST] Using library path: %s\n", needed_path);

    load_chain* pChain = malloc(sizeof(load_chain));
#if !defined(_WIN32) && defined(DEBUG)
    LsDebugSupport debug_support = LS_DEBUG_SUPPORT_ENABLE_GNU;
#else
    LsDebugSupport debug_support = LS_DEBUG_SUPPORT_DISABLE;
#endif
    LsStatus status = lsOpenObjectFromFile(needed_path, debug_support, &pChain->object, NULL);
    if (status != LS_OK) {
        free(pChain);
        return status;
    }
    free(needed_path);

    const LsObjectLoadCallbacks load_callbacks = {
            .pfnLoadNeeded = load_needed_callback,
    };
    status = lsLoadObject(pChain->object, &load_callbacks);
    if (status != LS_OK) {
        lsCloseObject(pChain->object);
        free(pChain);
        return status;
    }

    pChain->pNext = load_chains;
    load_chains = pChain;
    return LS_OK;
}

LsStatus resolve_symbol_callback(void* pUserData, LsObject object, const char* pSymbolName, void** pSymbolAddress) {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        if (pChain->object == object)
            continue;

        const LsObjectInfo* info = lsGetObjectInfo(pChain->object);
        if (info->pLoadAddress) {
            *pSymbolAddress = lsGetSymbolAddress(pChain->object, pSymbolName);
            if (*pSymbolAddress)
                return LS_OK;
        }
    }

    const char* host_print_name = "host_print";
    if (strcmp(pSymbolName, host_print_name) == 0) {
        *pSymbolAddress = host_print;
        return LS_OK;
    }

    return LS_ERROR_SYMBOL_NOT_FOUND;
}

LsStatus resolve_plugins() {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        const LsObjectResolveCallbacks resolve_callbacks = {
                .pfnResolveSymbol = resolve_symbol_callback,
        };
        const LsStatus status = lsResolveObject(pChain->object, &resolve_callbacks);
        if (status != LS_OK)
            return status;
    }
    return LS_OK;
}

LsStatus initialize_plugins() {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        const LsStatus status = lsInitializeObject(pChain->object, NULL);
        if (status != LS_OK)
            return status;
    }
    return LS_OK;
}

void call_plugins() {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        const char* pInitFuncName = "initialize";
        void* symbol = lsGetSymbolAddress(pChain->object, pInitFuncName);
        if (!symbol)
            continue;

        typedef void (*init_func)() __attribute__((sysv_abi));
        init_func init = symbol;
        init();
    }
}

LsStatus finalize_plugins() {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        const LsStatus status = lsFinalizeObject(pChain->object, NULL);
        if (status != LS_OK)
            return status;
    }
    return LS_OK;
}

void unload_plugins() {
    for (const load_chain* pChain = load_chains; pChain; pChain = pChain->pNext) {
        lsCloseObject(pChain->object);
    }
}

int main(int argc, char** argv) {
    puts("[HOST] Loading plugins");

#if defined(_WIN32)
    DWORD size = 512;

    for(;;) {
        binary_path = (char *)malloc(size);
        if (!binary_path) {
            perror("Failed to allocate memory for binary path");
            return -1;
        }
        const DWORD res = GetModuleFileName(NULL, binary_path, size);
        if (res > 0 && res < size)
            break;
        free(binary_path);
        if (res != size) {
            perror("Failed to get path to executable");
            return -1;
        }
        size *= 2;
    }
#else
    binary_path = realpath("/proc/self/exe", NULL);
    if (!binary_path) {
        puts("Failed to get path to executable");
        return 1;
    }
#endif

    const LsMessageCallbacks message_callbacks = { .pfnMessage = message_callback };
    lsSetMessageCallback(&message_callbacks);

    LsStatus status = load_needed_callback(NULL, NULL, "plugin-bar.so");
    if (status != LS_OK)
        return 1;

    status = resolve_plugins();
    if (status != LS_OK)
        return 1;

    status = initialize_plugins();
    if (status != LS_OK)
        return 1;

    printf("[HOST] Plugins loaded\n");
    call_plugins();
    printf("[HOST] Entrypoints called, closing\n");

    status = finalize_plugins();
    if (status != LS_OK)
        return 1;

    unload_plugins();
    printf("[HOST] Plugins unloaded\n");

    free(binary_path);

    return 0;
}
