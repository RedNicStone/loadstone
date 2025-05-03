
#include "host.h"

#include <loadstone.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void host_printf(const char* pFormat, ...) {
    va_list args;
    va_start(args, pFormat);
    vprintf(pFormat, args);
    va_end(args);
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
    LsStatus status = lsOpenObjectFromFile(needed_path, LS_DEBUG_SUPPORT_ENABLE_GNU, &pChain->object, NULL);
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

    const char* host_printf_name = "host_printf";
    if (strcmp(pSymbolName, host_printf_name) == 0) {
        *pSymbolAddress = host_printf;
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

        typedef void (*init_func)();
        const init_func init = symbol;
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
    if (argc < 1) {
        return 1;
    }

    binary_path = argv[0];

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

    return 0;
}
