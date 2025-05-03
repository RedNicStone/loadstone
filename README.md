# Loadstone: A Flexible ELF Relocatable Loader

**Loadstone** is a lightweight, flexible library for loading ELF relocatable files, giving developers more control than traditional dynamic loading mechanisms like `dlopen` and `dlsym`. It is designed to empower developers with fine-grained handling of symbol resolution, library loading, and cross-platform portability.

---

## Features

- Customizable symbol and library resolution.
- Cross-platform ELF loading (Unix and **Windows support in development**).
- Support for memory-backed ELF loading (no file required).
- Partial library loading and hot-reloading.
- Sandbox-friendly architecture for isolating untrusted plugins.
- Ansi compliant C99 codebase.

---

## Applications

### 1. Plugin Systems with Complex Dependency Resolution

Typical plugin systems use `dlopen` and `dlsym` to load compiled modules. This works well when plugins only depend on the host application. However, when plugins have interdependencies, things get complicated:

- Dynamically linked plugins must manage strict path resolutions, often conflicting with application layouts.
- Manually passing function pointers between plugins becomes messy and error-prone.

**Loadstone** addresses these issues by allowing **user-defined callbacks** for library and symbol resolution. This enables structured, controlled plugin ecosystems where complex dependencies can be resolved easily and safely.

---

### 2. Cross-Platform ELF Binaries

Unlike `glibc` or `musl`, **Loadstone** is not bound to Unix platforms. Windows support is actively being developed, with future expansion to embedded platforms in mind.

By abstracting platform-specific functions into optional modules, the **same ELF binary** can be loaded across multiple systems (as long as the architecture and ABI matches). This dramatically simplifies distribution—one binary per architecture, regardless of operating system.

---

### 3. Secure, Out-of-Process Library Virtualization

In situations where plugins should not be fully trusted, **Loadstone** offers a foundation for sandboxing:

- Libraries can be loaded into isolated processes.
- System calls can be restricted using mechanisms like `seccomp`.
- External symbols can be resolved to IPC stubs that securely forward calls to the host.

Shared memory strategies (such as reserving a static heap buffer) can allow pointer passing between processes. Alternatively, plugin ABIs can be designed to avoid unsafe pointer sharing altogether.

---

### 4. Loading Libraries Directly from Memory

**Loadstone** allows libraries to be loaded entirely from memory, without needing a file system backing. This is ideal for:

- Decompressing or decrypting binaries before loading.
- Loading signed or verified modules.
- Reducing disk I/O or working in read-only environments.

**Note**: The loaded binary must stay mapped in memory, which could increase RAM usage.

---

### 5. Partial Loading and Hot-Reloading

With **Loadstone**, libraries can be reloaded, re-resolved, and selectively loaded during runtime:

- **Partial Loading**: Not all symbols need to be resolved at load time. Missing symbols can default to `NULL`, allowing optional features or degraded modes.
- **Hot-Reloading**: Libraries and their dependencies can be swapped out while the application is running. This is ideal for rapid iteration, live updates, and development workflows—for example, reloading a game plugin without restarting the game and losing state.

---

## Why Loadstone?

Traditional dynamic linking solutions are rigid. **Loadstone** puts the developer back in control, enabling custom and creative workflows without being tied to the operating system's dynamic linker behavior. Whether you're building a robust plugin system, securing untrusted modules, or creating cross-platform applications, **Loadstone** provides the flexibility you need.

## Roadmap

- ✅ ELF library loading.
- ✅ Unix/Linux support.
- 🚧 Extended callbacks and default behaviors.
- 🚧 Improved memory safety.
- 🚧 In-memory library loading.
- 🚧 Windows support.
- ⏳ Embedded/RTOS compatibility exploration.
- ⏳ Additional sandboxing utilities.
- ⏳ TLS support.

## License

Loadstone is licensed under the MIT License.  
You are free to use, modify, and distribute it in your own projects, whether open-source or proprietary.  
See [LICENSE](./LICENSE) for the full text.

## Getting Started

### Installation

#### Build from source (CMake)

```bash
# Clone
git clone https://github.com/your‑org/loadstone.git
cd loadstone

# Configure & compile (Release build)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target loadstone
```

This produces the Loadstone static/shared library (`libloadstone.a` / `libloadstone.so` or `loadstone.lib` / `loadstone.dll` on Windows) inside the **build** directory.

> **Tip:** Package managers (vcpkg, Conan, AUR, etc.) are planned but not yet available.

#### Linking in your project

```bash
gcc example.c -I/path/to/loadstone/include -L/path/to/build -lloadstone -o example
```

- Add `#include "loadstone.h"` in your source.
- Ensure the runtime linker can locate `libloadstone.so` (e.g., via `LD_LIBRARY_PATH` or `rpath`).

---

### Minimal “hello‑plugin” example

Below is a small C program that loads an ELF shared object from disk, resolves a symbol named `plugin_entry`, calls it, and then shuts everything down. *No custom callbacks* are provided — we rely on Loadstone’s built‑in defaults.

```c
#include "loadstone.h"
#include <stdio.h>

/* Signature of the symbol we expect inside the plugin */
typedef void (*PluginEntry)(void);

int main(void)
{
    const char *path = "./plugin.so";   /* the ELF .so we want to load */
    LsObject    obj  = NULL;

    /* 1. Open (but not yet loaded/resolved) */
    if (lsOpenSharedObjectFromFile(path, LS_DEBUG_SUPPORT_ENABLE_GNU, &obj, /*allocators*/ NULL) != LS_OK)
    {
        fprintf(stderr, "Loadstone: failed to open %s
", path);
        return 1;
    }

    /* 2. Load dependencies + relocations */
    if (lsLoadSharedObject(obj, /*load callbacks*/ NULL) != LS_OK)
    {
        fprintf(stderr, "Loadstone: load failed
");
        return 1;
    }

    /* 3. Resolve symbols (dlsym‑equivalent) */
    if (lsResolveSharedObject(obj, /*resolve callbacks*/ NULL) != LS_OK)
    {
        fprintf(stderr, "Loadstone: resolve failed
");
        return 1;
    }

    /* 4. (Optional) run .init / constructor functions */
    lsInitializeSharedObject(obj, /*init callbacks*/ NULL);

    /* 5. Fetch a symbol and call it */
    PluginEntry entry = (PluginEntry) lsGetSymbolAddress(obj, "plugin_entry");
    if (entry)
        entry();
    else
        fprintf(stderr, "symbol 'plugin_entry' not found!
");

    /* 6. (Optional) run .fini / destructor functions */
    lsFinalizeSharedObject(obj, /*fini callbacks*/ NULL);

    /* 7. Close */
    lsCloseSharedObject(obj);
    return 0;
}
```

Compile & run:

```bash
gcc main.c -I./include -L./build -lloadstone -o main
./main
```

---

## Contributing

Contributions, feedback, and discussions are very welcome!

Contributions to the following goals would be especially welcome:
- Support for TLS (thread-local storage).
- Support and testing for Windows platforms.
- Design and implementation of sandboxing utilities.

---

## Support

For questions, issues, or feature requests, feel free to open a GitHub issue.

---

**Loadstone**: load your libraries your way.

