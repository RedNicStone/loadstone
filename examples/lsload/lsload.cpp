
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstdint>
#include <string_view>
#include <array>
#include <span>
#include <vector>
#include <fstream>
#include <optional>
#include <ranges>
#include <iostream>
#include <functional>
#include <stack>
#include <algorithm>

#include "dlfcn.h"

#include <loadstone.h>

/////////////////////////
// ld.so cache parsing //
/////////////////////////


// Cache file structure

struct FileEntry {
    /* This is 1 for an ELF library. */
    int32_t  flags;

    /* String table indices. */
    uint32_t key, value;

    /* Required OS version (unused). */
    uint32_t os_version;

    /* Hwcap entry. */
    uint64_t hardware_capabilities;
};

enum class cache_flags : uint8_t {
    /* No endianness information available.  An old ldconfig version
       without endianness support wrote the file. */
    endian_unset = 0,

    /* Cache is invalid and should be ignored. */
    endian_invalid = 1,

    /* Cache format is little endian. */
    endian_little = 2,

    /* Cache format is big endian. */
    endian_big = 3,
};

constexpr std::string_view cache_magic   = "glibc-ld.so.cache";
constexpr std::string_view cache_version = "1.1";

struct CacheFile {
    std::array<char, cache_magic.size()> magic;
    std::array<char, cache_version.size()> version;

    uint32_t file_count;
    uint32_t strings_count;

    uint8_t  flags;
    uint8_t  unused_1[3];

    uint32_t extension_offset;
    uint32_t unused_2[3];
};


// Cache memory structure and loading

struct CacheStringRef {
    uint32_t offset;

    std::string_view operator()(std::span<const char> strings) const {
        if (offset + 1 >= strings.size()) [[unlikely]]
            throw std::out_of_range("Cache string reference out of range");

        return { &strings[offset] };
    }
};

struct CacheMemory {
    std::vector<char> strings;
    std::unordered_map<std::string_view, CacheStringRef> entry_map;

    void load_from_file(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) [[unlikely]]
            throw std::runtime_error("Failed to open cache file");

        CacheFile file_header{};
        file.read(reinterpret_cast<char*>(&file_header), sizeof(file_header));

        const std::string_view magic { file_header.magic.begin(), file_header.magic.size() };
        const std::string_view version { file_header.version.begin(), file_header.version.size() };

        uint32_t string_offset = sizeof(file_header) + file_header.file_count * sizeof(FileEntry);

        entry_map.reserve(file_header.file_count);
        std::vector<FileEntry> file_entries(file_header.file_count);
        file.read(reinterpret_cast<char*>(file_entries.data()),
            static_cast<std::streamsize>(file_header.file_count * sizeof(FileEntry)));

        if (file.bad()) [[unlikely]]
            throw std::runtime_error("Invalid cache file");

        if (file.bad() ||
            magic != cache_magic ||
            version != cache_version) [[unlikely]]
            throw std::runtime_error("Invalid cache file");

        strings.resize(file_header.strings_count);
        file.read(strings.data(), file_header.strings_count);

        if (file.bad()) [[unlikely]]
            throw std::runtime_error("Invalid cache file");

        for (const auto& file_entry : file_entries) {
            auto key = CacheStringRef(file_entry.key - string_offset)(strings);
            entry_map.emplace(key, CacheStringRef(file_entry.value - string_offset));
        }
    }

    std::optional<std::string_view> operator[](std::string_view key) const {
        const auto it = entry_map.find(key);
        if (it == entry_map.end()) [[unlikely]]
            return std::nullopt;

        return it->second(strings);
    }
};


/////////////////////////////
// library path resolution //
/////////////////////////////

std::vector<std::filesystem::path> split_paths(const std::string_view& str) {
    auto to_path = [](auto&& r) -> std::filesystem::path {
        return std::filesystem::path(&*r.begin(), &*r.end());
    };

    auto range = str
        | std::ranges::views::split(':')
        | std::ranges::views::transform(to_path);

    return { std::ranges::begin(range), std::ranges::end(range) };
}

struct GlobalResolveContext {
    std::optional<CacheMemory> cache;
    std::filesystem::path cache_path = "";
    std::vector<std::filesystem::path> ld_library_path;

    void read_from_environment() {
        cache = std::nullopt;

        const std::string_view ld_library_path_env = std::getenv("LD_LIBRARY_PATH");
        ld_library_path = split_paths(ld_library_path_env);
    }
};

struct LibraryResolveContext {
    LsObject object = nullptr;
    std::vector<std::filesystem::path> rpath_runpath;
    enum class mode_enum {
        rpath,
        runpath,
        none,
    } rpath_mode = mode_enum::none;

    void read_from_object() {
        const LsObjectInfo* info = lsGetObjectInfo(object);

        if (info->pRunPath != nullptr) {
            rpath_runpath = split_paths(info->pRunPath);
            rpath_mode = mode_enum::runpath;
        } else if (info->pRPath != nullptr) {
            rpath_runpath = split_paths(info->pRPath);
            rpath_mode = mode_enum::rpath;
        } else {
            rpath_runpath = {};
            rpath_mode = mode_enum::none;
        }
    }
};

std::optional<std::filesystem::path> search_library_path(
    const std::string_view& name, const std::filesystem::path& path) {
    std::filesystem::path full_path = path / name;
    if (exists(full_path))
        return full_path;

    return std::nullopt;
}

std::optional<std::filesystem::path> resolve_library_path(
    const std::string_view& name, GlobalResolveContext& global_context, const LibraryResolveContext& library_context) {
    if (name.find('/') != std::string_view::npos)
        return name;

    if (library_context.rpath_mode == LibraryResolveContext::mode_enum::rpath) {
        for (const auto& rpath : library_context.rpath_runpath) {
            const auto path = search_library_path(name, rpath);
            if (path)
                return path;
        }
    }

    for (const auto& ld_library_path : global_context.ld_library_path) {
        const auto path = search_library_path(name, ld_library_path);
        if (path)
            return path;
    }

    if (library_context.rpath_mode == LibraryResolveContext::mode_enum::runpath) {
        for (const auto& rpath : library_context.rpath_runpath) {
            const auto path = search_library_path(name, rpath);
            if (path)
                return path;
        }
    }

    if (!global_context.cache_path.empty() && !global_context.cache) {
        global_context.cache = std::make_optional<CacheMemory>();
        global_context.cache->load_from_file(global_context.cache_path);
    }

    {
        const auto path = global_context.cache->operator[](name);
        if (path)
            return path;
    }

    {
        const auto path = search_library_path(name, "/lib");
        if (path)
            return path;
    }

    {
        const auto path = search_library_path(name, "/usr/lib");
        if (path)
            return path;
    }

    return std::nullopt;
}


//////////////////////
// argument parsing //
//////////////////////

struct Options {
    std::filesystem::path cache_path = "/etc/ld.so.cache";
    std::filesystem::path elf_path;
    bool debug_support = false;

    enum class verbosity_enum {
        quiet,
        normal,
        verbose,
        debug,
    } verbosity = verbosity_enum::quiet;

    std::vector<std::string_view> entry_point_args;
};

struct Argument {
    std::string_view name;
    uint32_t param_count;

    std::function<void(Options&, const std::vector<std::string_view>&)> callback;
};

const std::array arguments = {
    Argument { "cache", 1, [](Options& opt, const std::vector<std::string_view>& args) {
        opt.cache_path = args[0];
    } },
    Argument { "v", 0, [](Options& opt, const std::vector<std::string_view>&) {
        opt.verbosity = Options::verbosity_enum::normal;
    } },
    Argument { "vv", 0, [](Options& opt, const std::vector<std::string_view>&) {
        opt.verbosity = Options::verbosity_enum::verbose;
    } },
    Argument { "vvv", 0, [](Options& opt, const std::vector<std::string_view>&) {
        opt.verbosity = Options::verbosity_enum::debug;
    } },
    Argument { "debug", 0, [](Options& opt, const std::vector<std::string_view>&) {
        opt.debug_support = true;
    } },
};

std::optional<Options> parse_options(const std::span<const std::string_view>& args) {
    Options options;

    const auto begin = std::ranges::begin(args);
    const auto end = std::ranges::end(args);
    auto it = begin;
    while (it != end) {
        const auto& arg_raw = *it;
        if (arg_raw.size() < 3 || arg_raw[0] != '-' || arg_raw[1] != '-') {
            break;
        }
        const auto arg = arg_raw.substr(2, std::string::npos);

        const auto arg_type = std::ranges::find_if(arguments, [&arg](auto&& r) { return r.name == arg; });
        if (arg_type == std::ranges::end(arguments)) {
            std::cerr << "Error: Unrecognized argument --'" << arg << "'" << std::endl;
            return std::nullopt;
        }

        std::vector<std::string_view> arg_values;
        arg_values.reserve(arg_type->param_count);
        for (uint32_t i = 0; i < arg_type->param_count; ++i) {
            ++it;
            if (it == end) {
                std::cerr << "Error: Expected " << arg_type->param_count << " argument(s) for '" << arg << "', got " << --i << std::endl;
                return std::nullopt;
            }
            arg_values.push_back(*it);
        }

        arg_type->callback(options, arg_values);
        ++it;
    }

    if (it == end) {
        std::cerr << "Error: Expected positional argument <elf_file>, got end of arguments" << std::endl;
        return std::nullopt;
    }
    options.elf_path = *it;

    ++it;
    options.entry_point_args.insert(options.entry_point_args.end(), it, end);

    return options;
}


/////////////////////
// library loading //
/////////////////////

extern std::unordered_set<std::string> system_library_overrides;

struct GlobalLoadContext;
struct LibraryLoadContext {
    LibraryResolveContext library_context;
    std::vector<LibraryLoadContext*> dependencies;
    GlobalLoadContext* global_context = nullptr;
    std::filesystem::path path;

    explicit LibraryLoadContext(const std::filesystem::path& path) : path(path) {}

    struct hash {
        std::size_t operator()(const LibraryLoadContext& context) const {
            return std::hash<std::string>{}(context.path.string());
        }
    };

    struct equal_to {
        bool operator()(const LibraryLoadContext& lhs, const LibraryLoadContext& rhs) const {
            return lhs.path == rhs.path;
        }
    };
};

struct GlobalLoadContext {
    std::unordered_set<LibraryLoadContext, LibraryLoadContext::hash, LibraryLoadContext::equal_to> loaded_objects;
    std::unordered_map<std::string, void*> system_libraries;
    GlobalResolveContext resolve_context;
    Options options;

    void load_from_options(const Options& options);
};

void message_callback(void* pUserData, LsSeverity severity, const char* pMessage) {
    const auto* context = static_cast<GlobalLoadContext*>(pUserData);
    switch (context->options.verbosity) {
        case Options::verbosity_enum::quiet:
            return;
        case Options::verbosity_enum::normal:
            if (severity < LS_SEVERITY_ERROR)
                return;
            break;
        case Options::verbosity_enum::verbose:
            if (severity < LS_SEVERITY_WARNING)
                return;
            break;
        case Options::verbosity_enum::debug:
        default:
            break;
    }

    std::cout << "[" << lsSeverityToString(severity) << "]: " << pMessage << std::endl;
}

LsStatus load_callback(void* pUserData, LsObject, const char* pNeededName) {
    auto* context = static_cast<LibraryLoadContext*>(pUserData);

    const LsObjectInfo* info = lsGetObjectInfo(context->library_context.object);

    if (system_library_overrides.contains(pNeededName)) {
        std::cout << "Library '" << info->pPath << "' needs '" << pNeededName << "' from the system" << std::endl;
        if (context->global_context->system_libraries.contains(pNeededName))
            return LS_OK;

        void* library = dlopen(pNeededName, RTLD_NOW);
        if (library == nullptr) {
            std::cerr << "Error: Failed to open system library '" << pNeededName << "'" << std::endl;
            return LS_ERROR;
        }

        context->global_context->system_libraries.emplace(pNeededName, library);
        return LS_OK;
    }
    std::cout << "Library '" << info->pPath << "' needs '" << pNeededName << "'" << std::endl;

    const auto path = resolve_library_path(pNeededName, context->global_context->resolve_context, context->library_context);
    if (!path) {
        std::cerr << "Error: Failed to resolve library '" << pNeededName << "'" << std::endl;
        return LS_ERROR;
    }

    auto [it, inserted] = context->global_context->loaded_objects.emplace(*path);
    auto* library_context = const_cast<LibraryLoadContext*>(&*it);
    context->dependencies.push_back(library_context);
    if (!inserted)
        return LS_OK;

    library_context->global_context = context->global_context;
    {
        const LsStatus status = lsOpenObjectFromFile(
            path->c_str(),
            context->global_context->options.debug_support ? LS_DEBUG_SUPPORT_ENABLE_GNU : LS_DEBUG_SUPPORT_DISABLE,
            &library_context->library_context.object,
            nullptr);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to open library '" << pNeededName << "': " << lsGetObjectInfo(it->library_context.object)->pSoname << std::endl;
            return status;
        }
    }
    library_context->library_context.read_from_object();

    LsObjectLoadCallbacks load_callbacks;
    load_callbacks.pUserData = reinterpret_cast<void*>(library_context);
    load_callbacks.pfnLoadNeeded = &load_callback;

    {
        const LsStatus status = lsLoadObject(it->library_context.object, &load_callbacks);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to load library '" << pNeededName << std::endl;
            return status;
        }
    }

    return LS_OK;
}

LsStatus resolve_symbol_callback(void* pUserData, LsObject object, const char* pSymbolName, void** pSymbolAddress) {
    auto* context = static_cast<GlobalLoadContext*>(pUserData);
    for (const auto& library_context : context->loaded_objects) {
        if (library_context.library_context.object == object)
            continue;

        void* symbol_address = lsGetSymbolAddress(library_context.library_context.object, pSymbolName);
        if (symbol_address == nullptr)
            continue;

        *pSymbolAddress = symbol_address;
        return LS_OK;
    }

    for (const auto library: context->system_libraries | std::views::values) {
        void* symbol_address = dlsym(library, pSymbolName);
        if (symbol_address == nullptr)
            continue;

        *pSymbolAddress = symbol_address;
        return LS_OK;
    }

    return LS_ERROR_SYMBOL_NOT_FOUND;
}

void GlobalLoadContext::load_from_options(const Options& command_line_options) {
    options = command_line_options;
    resolve_context.read_from_environment();

    if (!options.cache_path.empty())
        resolve_context.cache_path = options.cache_path;

    LsMessageCallbacks message_callbacks;
    message_callbacks.pUserData = this;
    message_callbacks.pfnMessage = message_callback;
    lsSetMessageCallback(&message_callbacks);

    auto [it, _] = loaded_objects.emplace(options.elf_path);
    auto* library_context = const_cast<LibraryLoadContext*>(&*it);
    library_context->global_context = this;
    {
        const LsStatus status = lsOpenObjectFromFile(
            options.elf_path.c_str(),
            options.debug_support ? LS_DEBUG_SUPPORT_ENABLE_GNU : LS_DEBUG_SUPPORT_DISABLE,
            &library_context->library_context.object,
            nullptr);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to open library '" << options.elf_path << std::endl;
            return;
        }
    }
    library_context->library_context.read_from_object();

    LsObjectLoadCallbacks load_callbacks;
    load_callbacks.pUserData = reinterpret_cast<void*>(library_context);
    load_callbacks.pfnLoadNeeded = &load_callback;

    {
        const LsStatus status = lsLoadObject(it->library_context.object, &load_callbacks);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to load library '" << options.elf_path << "': " << lsGetObjectInfo(it->library_context.object)->pSoname << std::endl;
            return;
        }
    }

    // Post-order traversal of the dependency graph
    std::vector<LibraryLoadContext*> load_order;
    {
        std::stack<LibraryLoadContext*> stack;
        std::unordered_set<LibraryLoadContext*> visited;
        load_order.reserve(loaded_objects.size());
        visited.reserve(loaded_objects.size());
        stack.push(library_context);
        visited.insert(library_context);
        while (!stack.empty()) {
            auto* context = stack.top();
            bool all_dependencies_resolved = true;

            for (auto* dependency : context->dependencies) {
                if (!visited.contains(dependency)) {
                    all_dependencies_resolved = false;
                    stack.push(dependency);
                }
            }

            if (all_dependencies_resolved) {
                context = stack.top();
                stack.pop();

                visited.insert(context);
                load_order.push_back(context);
            }
        }
    }

    for (const auto* context : load_order) {
        LsObjectResolveCallbacks resolve_callbacks;
        resolve_callbacks.pUserData = reinterpret_cast<void*>(this);
        resolve_callbacks.pfnResolveSymbol = resolve_symbol_callback;

        const LsStatus status = lsResolveObject(context->library_context.object, &resolve_callbacks);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to resolve symbols in library '" << context->path << "': " << lsGetObjectInfo(context->library_context.object)->pSoname << std::endl;
            return;
        }
    }

    for (const auto* context : load_order) {
        const LsStatus status = lsInitializeObject(context->library_context.object, nullptr);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to initialize library '" << context->path << "': " << lsGetObjectInfo(context->library_context.object)->pSoname << std::endl;
            return;
        }
    }

    void* entry_point_address = lsGetSymbolAddress(library_context->library_context.object, "main");
    if (entry_point_address == nullptr) {
        puts("Failed to get entry point address\n");
        return;
    }
    auto main_func = reinterpret_cast<int(*)(int argc, char** argv)>(entry_point_address);
    std::vector<char*> argv(options.entry_point_args.size() + 1);
    argv[0] = const_cast<char*>(options.elf_path.c_str());
    std::ranges::transform(options.entry_point_args, argv.begin() + 1, [](auto&& r) { return const_cast<char*>(r.data()); });
    main_func(static_cast<int>(argv.size()), argv.data());

    for (const auto* context : load_order) {
        const LsStatus status = lsFinalizeObject(context->library_context.object, nullptr);
        if (status != LS_OK) {
            std::cerr << "Error: Failed to finalize library '" << context->path << "': " << lsGetObjectInfo(context->library_context.object)->pSoname << std::endl;
            return;
        }
    }

}


//////////////////////
// main entry point //
//////////////////////

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <elf_file> [args...]" << std::endl;
        return 1;
    }

    auto range = std::span(argv + 1, argv + argc)
        | std::views::transform([](auto&& r) { return std::string_view(r); });

    auto args = std::vector(std::ranges::begin(range), std::ranges::end(range));

    const auto& options = parse_options(args);
    if (!options)
        return 1;

    GlobalLoadContext context;
    context.load_from_options(*options);
    return 0;
}


///////////////////////
// library overrides //
///////////////////////

std::unordered_set<std::string> system_library_overrides = {
    "libc.so.6",
    "ld-linux-x86-64.so.2",
};


