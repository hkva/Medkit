#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
    #define _DEFAULT_SOURCE
#endif
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
    #define _CRT_SECURE_NO_WARNINGS
#endif

#include "medkit.h" // @amalgamate-remove

#if defined(_MSC_VER)
    #define _MK_TLS __declspec(thread)
#elif defined(__GNUC__)
    #define _MK_TLS __thread
#else
    #pragma message "Unknown compiler, _MK_TLS is undefined and medkit will not be thread-safe"
    #define _MK_TLS
#endif

#ifdef _WIN32
    #define _MK_WINDOWS
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>
#endif
#ifdef __linux__
    #define _MK_LINUX
    #include <dirent.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/ptrace.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef _MK_MALLOC
    #include <stdlib.h>
    #define _MK_MALLOC(sz)  malloc(sz)
    #define _MK_MFREE(p)    free(p)
#endif

//
// Core API
//

static _MK_TLS char _mk_last_error[512] = { 'N', 'o', ' ', 'e', 'r', 'r', 'o', 'r', '\0' };

const char* mk_get_last_error(void) {
    return _mk_last_error;
}

//
// Helper functions
//

#define _MK_MIN(a, b) ((a) < (b) ? (a) : (b))
#define _MK_MAX(a, b) ((a) > (b) ? (a) : (b))

#define _MK_ZERO(s) memset(&s, 0, sizeof(s))

static void _mk_set_last_error(const char* fmt, ...) {
    va_list va; va_start(va, fmt);
    vsnprintf(_mk_last_error, sizeof(_mk_last_error), fmt, va);
    va_end(va);
}

#if defined(_MK_LINUX)
    #define _MK_EINTERNAL()  _mk_set_last_error("Internal error (errno = %d)", errno)
#else
    #define _MK_EINTERNAL()  _mk_set_last_error("Internal error")
#endif
#define _MK_EINVAL(argname) _mk_set_last_error("Invalid argument: %s", argname)
#define _MK_ENOMEM() _mk_set_last_error("Out of memory")
#define _MK_EBADELF() _mk_set_last_error("Malformed ELF file")
#define _MK_EBADPE() _mk_set_last_error("Malformed PE file")

typedef struct _MK_Reader {
    MK_Buffer   buf;
    size_t      cur;
} _MK_Reader;

#define _MK_READ_CORE_TYPE_IMPL(r, T)            \
    if (r->cur + sizeof(T) > r->buf.length) {   \
        return 0;                               \
    }                                           \
    T val = *(T*)&r->buf.data[r->cur];          \
    r->cur += sizeof(T);                        \
    return val;

static uint8_t _mk_read_u8(_MK_Reader* r) {
    _MK_READ_CORE_TYPE_IMPL(r, uint8_t);
}

static uint16_t _mk_read_u16(_MK_Reader* r) {
    _MK_READ_CORE_TYPE_IMPL(r, uint16_t);
}

static uint32_t _mk_read_u32(_MK_Reader* r) {
    _MK_READ_CORE_TYPE_IMPL(r, uint32_t);
}

static uint64_t _mk_read_u64(_MK_Reader* r) {
    _MK_READ_CORE_TYPE_IMPL(r, uint64_t);
}

static void _mk_read(_MK_Reader* r, uint8_t* dst, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (r->cur + i > r->buf.length) {
            return;
        }
        dst[i] = r->buf.data[r->cur];
        r->cur += 1;
    }
}

#ifdef _MK_LINUX
static bool _mk_is_str_numeric(const char* str) {
    for (size_t i = 0; str[i] != '\0'; ++i) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}
#endif // _MK_LINUX

static const char* _mk_basename(const char* path) {
    const char* file = path;
    for (size_t i = 0; path[i] != '\0'; ++i) {
        if ((path[i] == '/' || path[i] == '\\') && path[i+1] != '\0') {
            file = &path[i+1];
        }
    }
    return file;
}

//
// Process API
//

struct MK_ProcessList {
#ifdef _MK_WINDOWS
    HANDLE snapshot;
    size_t entry_num;
#endif
#ifdef _MK_LINUX
    DIR* procdir;
#endif
};

unsigned long mk_get_pid(void) {
#ifdef _MK_WINDOWS
    return GetCurrentProcessId();
#endif
#ifdef _MK_LINUX
    return getpid();
#endif
}

MK_ProcessList* mk_begin_process_list(void) {
    MK_ProcessList* list = (MK_ProcessList*)_MK_MALLOC(sizeof(MK_ProcessList));
    if (list == NULL) {
        _MK_ENOMEM(); return NULL;
    }
#ifdef _MK_WINDOWS
    list->snapshot  = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    list->entry_num = 0;
    if (list->snapshot == INVALID_HANDLE_VALUE) {
        _MK_EINTERNAL(); goto fail;
    }
#endif
#ifdef _MK_LINUX
    if ((list->procdir = opendir("/proc")) == NULL) {
        _MK_EINTERNAL(); goto fail;
    }
#endif
    return list;
fail:
    _MK_MFREE(list);
    return NULL;
}

bool mk_next_process(MK_ProcessList* list, MK_ProcessInfo* info) {
    if (!list) { _MK_EINVAL("list"); return false; }
    if (!info) { _MK_EINVAL("info"); return false; }
#ifdef _MK_WINDOWS
    PROCESSENTRY32 entry; entry.dwSize = sizeof(PROCESSENTRY32);
    BOOL ok = (list->entry_num == 0) ? Process32First(list->snapshot, &entry) : Process32Next(list->snapshot, &entry);
    if (ok == FALSE) {
        return false;
    }
    list->entry_num += 1;
    info->pid = entry.th32ProcessID;
    
    // Try to get full process path
    DWORD nchar = MK_MAX_PATH;
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info->pid);
    if (proc == NULL || QueryFullProcessImageNameA(proc, 0, info->path, &nchar) == FALSE) {
        // Process is protected, just copy exe file name
        strncpy(info->path, entry.szExeFile, MK_MAX_PATH);
    }
    if (proc != NULL) {
        CloseHandle(proc);
    }

    return true;
#endif
#ifdef _MK_LINUX
    struct dirent* dir = NULL;
    while ((dir = readdir(list->procdir)) != NULL) {
        // Only care about numeric subdirectories
        if (dir->d_type != DT_DIR || !_mk_is_str_numeric(dir->d_name)) {
            continue;
        }

        info->pid = atoi(dir->d_name);
        // read /proc/pid/exe symlink
        char proc_link[32] = { 0 };
        snprintf(proc_link, sizeof(proc_link), "/proc/%lu/exe", info->pid);
        ssize_t r = readlink(proc_link, info->path, MK_MAX_PATH);
        if (r > -1) {
            info->path[r] = '\0';
            return true;
        }
    }
    return false;
#endif
}

void mk_end_process(MK_ProcessList* list) {
    if (!list) { _MK_EINVAL("list"); return; }
#ifdef _MK_WINDOWS
    CloseHandle(list->snapshot);
#endif
#ifdef _MK_LINUX
    closedir(list->procdir);
#endif
    _MK_MFREE(list);
}

bool mk_find_process(const char* name, MK_ProcessInfo* info) {
    if (!name) { _MK_EINVAL("name"); return false; }
    if (!info) { _MK_EINVAL("info"); return false; }
    MK_ProcessList* list = mk_begin_process_list();
    if (list == NULL) {
        return false;
    }
    bool found = false;
    while (mk_next_process(list, info)) {
        if (strcmp(info->path, name) == 0 || strcmp(_mk_basename(info->path), name) == 0) {
            found = true;
            break;
        }
    }
    mk_end_process(list);
    return found;
}

//
// Tracer API
//

struct MK_ProcessTracer {
    unsigned long   pid;
#ifdef _MK_WINDOWS
    HANDLE          process;
#endif
};

MK_ProcessTracer* mk_attach(unsigned long pid) {
    MK_ProcessTracer* trace = (MK_ProcessTracer*)_MK_MALLOC(sizeof(MK_ProcessTracer));
    if (trace == NULL) {
        _MK_ENOMEM(); return NULL;
    }
    trace->pid = pid;
#ifdef _MK_WINDOWS
    if ((trace->process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL) {
        _MK_EINTERNAL(); goto fail;
    }
#endif
#ifdef _MK_LINUX
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        _MK_EINTERNAL(); goto fail;
    }
    waitpid(pid, NULL, 0);
#endif
    return trace;
fail:
    _MK_MFREE(trace);
    return NULL;
}

void mk_detach(MK_ProcessTracer* trace) {
    if (!trace) { _MK_EINVAL("trace"); return; }
#ifdef _MK_WINDOWS
    CloseHandle(trace->process);
#endif
#ifdef _MK_LINUX
    ptrace(PTRACE_DETACH, trace->pid, 0, 0);
#endif
    _MK_MFREE(trace);
}

size_t mk_remote_read(MK_ProcessTracer* trace, uintptr_t addr, void* data, size_t size) {
    if (!trace) { _MK_EINVAL("trace"); return 0; }
    if (!data)  { _MK_EINVAL("data"); return 0; }
#ifdef _MK_WINDOWS
    SIZE_T nb = 0;
    if (ReadProcessMemory(trace->process, (void*)addr, data, size, &nb) == 0) {
        _MK_EINTERNAL(); return 0;
    }
    return nb;
#endif
#ifdef _MK_LINUX
    // Read from /proc/<pid>/mem
    char proc_mem[32];
    snprintf(proc_mem, sizeof(proc_mem), "/proc/%lu/mem", trace->pid);
    int fd = open(proc_mem, O_RDONLY);
    if (fd == -1) {
        _MK_EINTERNAL(); return 0;
    }

    ssize_t r = pread(fd, data, size, addr);
    close(fd);
    if (r == -1) {
        _MK_EINTERNAL(); return 0;
    }
    return (size_t)r;
#endif
}

size_t mk_remote_write(MK_ProcessTracer* trace, uintptr_t addr, const void* data, size_t size) {
    if (!trace) { _MK_EINVAL("trace"); return 0; }
    if (!data)  { _MK_EINVAL("data"); return 0; }
#ifdef _MK_WINDOWS
    SIZE_T nb = 0;
    if (WriteProcessMemory(trace->process, (void*)addr, data, size, &nb) == 0) {
        _MK_EINTERNAL(); return 0;
    }
    return nb;
#endif
#ifdef _MK_LINUX
    // Write to /proc/<pid>/mem
    char proc_mem[32];
    snprintf(proc_mem, sizeof(proc_mem), "/proc/%lu/mem", trace->pid);
    int fd = open(proc_mem, O_RDWR);
    if (fd == -1) {
        _MK_EINTERNAL(); return 0;
    }

    ssize_t r = pwrite(fd, data, size, addr);
    close(fd);
    if (r == -1) {
        _MK_EINTERNAL(); return 0;
    }
    return (size_t)r;
#endif
}

//
// Module API
//

struct MK_ModuleList {
    unsigned long   pid;
#ifdef _MK_WINDOWS
    HANDLE          snapshot;
    size_t          entry_num;
#endif
#ifdef _MK_LINUX
    FILE*           mapfile;
    char            last_map_path[MK_MAX_PATH];
    int             map_count;
#endif
};

MK_ModuleList* mk_begin_module_list(unsigned long pid) {
    MK_ModuleList* list = (MK_ModuleList*)_MK_MALLOC(sizeof(MK_ModuleList));
    if (list == NULL) {
        _MK_ENOMEM(); return NULL;
    }
    list->pid = pid;
#ifdef _MK_WINDOWS
    if ((list->snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) == NULL) {
        _MK_EINTERNAL(); goto fail;
    }
    list->entry_num = 0;
#endif
#ifdef _MK_LINUX
    // Have to pase /proc/<pid>/maps
    // I wish Linux has a nicer API for this
    char map_path[32];
    snprintf(map_path, sizeof(map_path), "/proc/%lu/maps", pid);
    if ((list->mapfile = fopen(map_path, "r")) == NULL) {
        _MK_EINTERNAL(); goto fail;
    }
    list->last_map_path[0] = '\0';
    list->map_count = 0;
#endif
    return list;
fail:
    _MK_MFREE(list);
    return NULL;
}

bool mk_next_module(MK_ModuleList* list, MK_ModuleInfo* info) {
    if (!list) { _MK_EINVAL("list"); return false; }
    if (!info) { _MK_EINVAL("info"); return false; }
    info->base_address  = 0;
    info->path[0]       = '\0';
#ifdef _MK_WINDOWS
    MODULEENTRY32 entry;
    entry.dwSize = sizeof(MODULEENTRY32);
    BOOL ok = (list->entry_num == 0) ? Module32First(list->snapshot, &entry) : Module32Next(list->snapshot, &entry);
    if (ok == FALSE) {
        return false;
    }
    list->entry_num += 1;
    info->base_address = (uintptr_t)entry.modBaseAddr;
    info->size = entry.modBaseSize;
    strncpy(info->path, entry.szExePath, MK_MAX_PATH);
    return true;
#endif
#ifdef _MK_LINUX
    // Lex /proc/<pid>/maps
    // Only care about starting address (first column) and path (optional list column)    
    char c = EOF;
    while ((c = fgetc(list->mapfile))) {
        // EOF -> done
        if (c == EOF) {
            return false;
        }
        // Whitespace -> skip
        if (c == ' ') {
            continue;
        }
        // Newline -> entry complete
        if (c == '\n') {
            break;
        }
        // c has some kind of legit data at this point
        // If it's the start of the entry, then it's the base address
        // If we already read the base address, wait until we hit '/' (start of path)
        if (!info->base_address) {
            // Read lowercase hex string
            do {
                uint8_t byte = (c >= 'a') ? ((uint8_t)(c - 'a') + 10) : ((uint8_t)(c - '0'));
                info->base_address = (info->base_address << 4) | (byte & 0xF);
            } while ((c = fgetc(list->mapfile)) != '-'); // base address ends with '-'
        } else if (c == '/') {
            // Read path up until newline or EOF
            size_t i = 0;
            for (; i < MK_MAX_PATH; ++i) {
                info->path[i] = c;
                c = fgetc(list->mapfile);
                if (c == '\n' || c == EOF) {
                    break;
                }
            }
            info->path[i + 1] = '\0';
            break;
        }
    }

    // Skip entries with invalid names (except for the first entry, which is always the actual executable)
    if (info->path[0] != '/' || (list->map_count > 0 && strstr(info->path, ".so") == NULL)) {
        return mk_next_module(list, info);
    }
    list->map_count += 1;

    // Ignore sequential duplicate entries
    if (strcmp(info->path, list->last_map_path) == 0) {
        return mk_next_module(list, info);
    }
    strncpy(list->last_map_path, info->path, MK_MAX_PATH);

    // Get file size
    info->size = 0;
    int fd = open(info->path, O_RDONLY);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) != -1) {
            info->size = st.st_size;
        }
        close(fd);
    }

    return true;
#endif
}

void mk_end_module_list(MK_ModuleList* list) {
    if (!list) { _MK_EINVAL("list"); return; }
#ifdef _MK_WINDOWS
    CloseHandle(list->snapshot);
#endif
#ifdef _MK_LINUX
    fclose(list->mapfile);
#endif
    _MK_MFREE(list);
}

bool mk_find_module(unsigned long pid, const char* name, MK_ModuleInfo* info) {
    if (!name) { _MK_EINVAL("name"); return false; }
    if (!info) { _MK_EINVAL("info"); return false; }
    MK_ModuleList* list = mk_begin_module_list(pid);
    if (list == NULL) {
        return false;
    }
    bool found = false;
    while (mk_next_module(list, info)) {
        if (strcmp(info->path, name) == 0 || strcmp(_mk_basename(info->path), name) == 0) {
            found = true;
            break;
        }
    }
    mk_end_module_list(list);
    return found;
}

bool mk_get_process_module(unsigned long pid, MK_ModuleInfo* info) {
    if (!info) { _MK_EINVAL("info"); return false; }
    // This sucks. Can't find any better way to do this with WinAPI
    MK_ModuleList* list = mk_begin_module_list(pid);
    if (list == NULL) {
        return false;
    }
    bool found = mk_next_module(list, info);
    mk_end_module_list(list);
    return found;
}

//
// Executable parsing
//

typedef struct _MK_ElfShdr {
    uint32_t sh_name;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint64_t sh_entsize;
} _MK_ElfShdr;

typedef struct _MK_ElfSym {
    uint32_t st_name;
    uint64_t st_value;
} _MK_ElfSym;

static bool _mk_parse_elf_shdr(_MK_Reader* r, bool is_32, _MK_ElfShdr* hdr) {
    if (is_32) {
        hdr->sh_name = _mk_read_u32(r);
        _mk_read_u32(r); // sh_type
        _mk_read_u32(r); // sh_flags
        hdr->sh_addr = _mk_read_u32(r); // sh_addr
        hdr->sh_offset = _mk_read_u32(r);
        hdr->sh_size = _mk_read_u32(r);
        _mk_read_u32(r); // sh_link
        _mk_read_u32(r); // sh_info
        _mk_read_u32(r); // sh_addralign
        hdr->sh_entsize = _mk_read_u32(r);
    } else {
        hdr->sh_name = _mk_read_u32(r);
        _mk_read_u32(r); // sh_type
        _mk_read_u64(r); // sh_flags
        hdr->sh_addr = _mk_read_u64(r); // sh_addr
        hdr->sh_offset = _mk_read_u64(r);
        hdr->sh_size = _mk_read_u64(r);
        _mk_read_u32(r); // sh_link
        _mk_read_u32(r); // sh_info
        _mk_read_u64(r); // sh_addralign
        hdr->sh_entsize = _mk_read_u64(r);
    }
    return true;
}

static bool _mk_parse_elf_sym(_MK_Reader* r, bool is_32, _MK_ElfSym* sym) {
    if (is_32) {
        sym->st_name = _mk_read_u32(r);
        sym->st_value = _mk_read_u32(r);
        _mk_read_u32(r);    // st_size
        _mk_read_u8(r);     // st_info
        _mk_read_u8(r);     // st_other
        _mk_read_u16(r);    // st_shndx
    } else {
        sym->st_name = _mk_read_u32(r);
        _mk_read_u8(r);     // st_info
        _mk_read_u8(r);     // st_other
        _mk_read_u16(r);    // st_shndx
        sym->st_value = _mk_read_u64(r);
        _mk_read_u64(r);    // st_size
    }
    return true;
}

static bool _mk_parse_elf(MK_Buffer buffer, MK_Exe* exe) {
    _MK_Reader r = { buffer, 0 };

    exe->type = MK_EXE_TYPE_ELF;

    // Read file header (ElfN_Ehdr)
    uint8_t e_ident[16]; _MK_ZERO(e_ident);
    _mk_read(&r, e_ident, sizeof(e_ident));
    if (e_ident[5] != 1) { // EI_CLASS != ELFCLASS32
        _mk_set_last_error("Big-endian ELF executables are not supported\n");
        return false;
    }
    bool is_32 = e_ident[4] == 1;
    _mk_read_u16(&r);   // e_type
    _mk_read_u16(&r);   // e_machine
    _mk_read_u32(&r);   // e_version
    (is_32) ? _mk_read_u32(&r) : _mk_read_u64(&r);  // e_entry
    (is_32) ? _mk_read_u32(&r) : _mk_read_u64(&r);  // e_phoff
    uint64_t e_shoff = (is_32) ? _mk_read_u32(&r) : _mk_read_u64(&r);
    _mk_read_u32(&r);   // e_flags
    _mk_read_u16(&r);   // e_shsize
    _mk_read_u16(&r);   // e_phentsize
    _mk_read_u16(&r);   // e_phnum
    uint16_t e_shentsize = _mk_read_u16(&r);
    uint16_t e_shnum = _mk_read_u16(&r);
    uint16_t e_shstrndx = _mk_read_u16(&r);

    // Some sanity checking
    if (e_shstrndx >= e_shnum) {
        _MK_EBADELF(); return false;
    }

    // Get section header string table
    _MK_ElfShdr shstrtabhdr;
    r.cur = e_shoff + e_shentsize * e_shstrndx;
    if (!_mk_parse_elf_shdr(&r, is_32, &shstrtabhdr)) {
        _MK_EBADELF(); return false;
    }
    if (shstrtabhdr.sh_offset + shstrtabhdr.sh_size >= buffer.length) {
        _MK_EBADELF(); return false;
    }
    const char* shstrtab = (const char*)&buffer.data[shstrtabhdr.sh_offset];

    // Parse sections
    exe->sections_count = e_shnum;
    exe->sections = (MK_ExeSection*)_MK_MALLOC(sizeof(MK_ExeSection) * e_shnum);
    if (!exe->sections) {
        _MK_ENOMEM(); return false;
    }
    _MK_ElfShdr sh_symtab; _MK_ZERO(sh_symtab);
    _MK_ElfShdr sh_strtab; _MK_ZERO(sh_strtab);
    for (size_t i = 0; i < exe->sections_count; ++i) {
        _MK_ElfShdr shdr;
        r.cur = e_shoff + e_shentsize * i;
        if (!_mk_parse_elf_shdr(&r, is_32, &shdr)) {
            _MK_EBADELF(); return false;
        }
        if (shdr.sh_name >= shstrtabhdr.sh_size) {
            _MK_EBADELF(); return false;
        }
        const char* name = &shstrtab[shdr.sh_name];
        exe->sections[i].type = MK_EXE_SECTION_TYPE_UNKNOWN;
        if (strcmp(name, ".text") == 0) {
            exe->sections[i].type = MK_EXE_SECTION_TYPE_CODE;
        } else if (strcmp(name, ".symtab") == 0) {
            sh_symtab = shdr;
        } else if (strcmp(name, ".strtab") == 0) {
            sh_strtab = shdr;
        }
        exe->sections[i].image_offset = shdr.sh_offset;
        exe->sections[i].memory_offset = shdr.sh_addr;
        exe->sections[i].length = shdr.sh_size;
    }

    // Parse embedded symbols
    if (sh_symtab.sh_offset && sh_strtab.sh_offset) {
        if (sh_symtab.sh_offset + sh_symtab.sh_size >= buffer.length) {
            _MK_EBADELF(); return false;
        }
        if (sh_strtab.sh_offset + sh_strtab.sh_size >= buffer.length) {
            _MK_EBADELF(); return false;
        }
        const char* strtab = (const char*)&buffer.data[sh_strtab.sh_offset];
        exe->symbols_count = sh_symtab.sh_size / sh_symtab.sh_entsize;
        exe->symbols = (MK_ExeSymbol*)_MK_MALLOC(sizeof(MK_ExeSymbol) * exe->symbols_count);
        if (!exe->symbols) {
            _MK_ENOMEM(); return false;
        }
        for (size_t i = 0; i < exe->symbols_count; ++i) {
            _MK_ElfSym sym;
            r.cur = sh_symtab.sh_offset + sh_symtab.sh_entsize * i;
            if (!_mk_parse_elf_sym(&r, is_32, &sym)) {
                _MK_EBADELF(); return false;
            }
            if (sym.st_name >= sh_strtab.sh_size) {
                _MK_EBADELF(); return false;
            }
            exe->symbols[i].name = &strtab[sym.st_name];
            exe->symbols[i].value = sym.st_value;
        }
    }

    return true;
}

static bool _mk_parse_pe(MK_Buffer buffer, MK_Exe* exe) {
    _MK_Reader r = { buffer, 0 };

    exe->type = MK_EXE_TYPE_PE;

    // Read DOS header
    // https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
    _mk_read_u16(&r);    // e_magic
    _mk_read_u16(&r);    // e_cblp
    _mk_read_u16(&r);    // e_cp
    _mk_read_u16(&r);    // e_crlc
    _mk_read_u16(&r);    // e_cparhdr
    _mk_read_u16(&r);    // e_minalloc
    _mk_read_u16(&r);    // e_maxalloc
    _mk_read_u16(&r);    // e_ss
    _mk_read_u16(&r);    // e_sp
    _mk_read_u16(&r);    // e_csum
    _mk_read_u16(&r);    // e_ip
    _mk_read_u16(&r);    // e_cs
    _mk_read_u16(&r);    // e_lfarlc
    _mk_read_u16(&r);    // ovno
    for (int i = 0; i < 4; ++i) {
        _mk_read_u16(&r);   // e_res[4]
    }
    _mk_read_u16(&r);   // e_oemid
    _mk_read_u16(&r);   // e_oeminfo
    for (int i = 0; i < 10; ++i) {
        _mk_read_u16(&r);   // e_res2[10]
    }
    uint32_t e_lfanew = _mk_read_u32(&r);

    // Read NT header
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
    r.cur = e_lfanew;
    uint32_t pe_sig = _mk_read_u32(&r);
    if (pe_sig != 0x00004550) {
        _MK_EBADPE(); return false;
    }

    // IMAGE_FILE_HEADER
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
    _mk_read_u16(&r);   // Machine
    uint16_t fh_number_of_sections = _mk_read_u16(&r);
    _mk_read_u32(&r);   // TimeDateStamp
    _mk_read_u32(&r);   // PointerToSymbolTable
    _mk_read_u32(&r);   // NumberOfSymbols
    uint16_t fh_ohdr_size = _mk_read_u16(&r);
    _mk_read_u16(&r);   // Characteristics
    
    // Skip optional header
    r.cur += fh_ohdr_size;

    // Parse sections
    exe->sections_count = fh_number_of_sections;
    exe->sections = (MK_ExeSection*)_MK_MALLOC(sizeof(MK_ExeSection) * exe->sections_count);
    if (!exe->sections) {
        _MK_ENOMEM(); return false;
    }
    for (size_t i = 0; i < exe->sections_count; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            _mk_read_u8(&r);    // Name
        }
        _mk_read_u32(&r);   // Misc
        exe->sections[i].memory_offset = _mk_read_u32(&r);   // VirtualAddress
        exe->sections[i].length = _mk_read_u32(&r);
        exe->sections[i].image_offset = _mk_read_u32(&r);
        _mk_read_u32(&r);    // PointerToRelocations
        _mk_read_u32(&r);    // PointerToLinenumbers
        _mk_read_u16(&r);    // NumberOfRelocations
        _mk_read_u16(&r);    // NumberOfLinenumbers
        uint32_t sh_characteristics = _mk_read_u32(&r);
        exe->sections[i].type = MK_EXE_SECTION_TYPE_UNKNOWN;
        if (sh_characteristics & 0x20) {
            exe->sections[i].type = MK_EXE_SECTION_TYPE_CODE;
        }
    }

    return true;
}

MK_Exe* mk_parse_exe(MK_Buffer buffer) {
    if (!buffer.data)   { _MK_EINVAL("buffer"); return NULL; }

    MK_Exe* exe = (MK_Exe*)_MK_MALLOC(sizeof(MK_Exe));
    if (!exe) {
        _MK_ENOMEM(); return NULL;
    }
    _MK_ZERO(*exe);

    // Determine file type from header
    const uint8_t FILE_MAGIC_ELF[]  = { 0x7f, 'E', 'L', 'F' };
    const uint8_t FILE_MAGIC_PE[]   = { 'M', 'Z' };
    if (memcmp(buffer.data, FILE_MAGIC_ELF, _MK_MIN(sizeof(FILE_MAGIC_ELF), buffer.length)) == 0) {
        if (!_mk_parse_elf(buffer, exe)) {
            goto fail;
        }
    } else if (memcmp(buffer.data, FILE_MAGIC_PE, _MK_MIN(sizeof(FILE_MAGIC_PE), buffer.length)) == 0)  {
        if (!_mk_parse_pe(buffer, exe)) {
            goto fail;
        }
    } else {
        _mk_set_last_error("Executable is malformed or not supported");
        goto fail;
    }

    return exe;
fail:
    mk_free_exe(exe);
    return NULL;
}

void mk_free_exe(MK_Exe* exe) {
    if (!exe)   { _MK_EINVAL("exe"); return; }
    if (exe->sections_count > 0) {
        _MK_MFREE(exe->sections);
    }
    if (exe->symbols_count > 0) {
        _MK_MFREE(exe->symbols);
    }
    _MK_MFREE(exe);
}

//
// Function detours
//

static bool _mk_toggle_detour(MK_Detour* detour) {
    if (!detour->backup[0]) {
        // NOTE(HK): Calling for the first time, generate the trampoline
        // E9 = x86 jump near relative
        detour->backup[0] = 0xE9;
        const uintptr_t rel = detour->destination - detour->target - 5;
        memcpy(&detour->backup[1], &rel, sizeof(rel));
    }
    const size_t trampoline_size = 1 + sizeof(uintptr_t);
    const uintptr_t page = MK_PAGE_ALIGN(detour->target);
#ifdef _MK_LINUX
    if (mprotect((void*)page, MK_PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        _MK_EINTERNAL(); return false;
    }
#endif
#ifdef _MK_WINDOWS
    DWORD old_protect = 0;
    if (!VirtualProtect((LPVOID)page, MK_PAGE_SIZE * 2, PAGE_EXECUTE_READWRITE, &old_protect)) {
        _MK_EINTERNAL(); return false;
    }
#endif
    uint8_t backup2[9] = { 0 };
    memcpy(backup2, (const void*)detour->target, trampoline_size);
    memcpy((void*)detour->target, detour->backup, trampoline_size);
#ifdef _MK_LINUX
    if (mprotect((void*)page, MK_PAGE_SIZE * 2, PROT_EXEC) == -1) {
        _MK_EINTERNAL(); return false;
    }
#endif
#ifdef _MK_WINDOWS
    DWORD ignore = 0;
    if (!VirtualProtect((LPVOID)page, MK_PAGE_SIZE * 2, old_protect, &ignore)) {
        _MK_EINTERNAL(); return false;
    }
#endif
    memcpy(detour->backup, backup2, trampoline_size);
    detour->installed = !detour->installed;
    return true;
};

bool mk_install_detour(MK_Detour* detour) {
    if (detour->installed) {
        return true;
    }
    return _mk_toggle_detour(detour);
}

bool mk_uninstall_detour(MK_Detour* detour) {
    if (!detour->installed) {
        return true;
    }
    return _mk_toggle_detour(detour);
}
