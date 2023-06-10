#ifndef _MEDKIT_H_
#define _MEDKIT_H_

// @amalgamate-include-comment("LICENSE")

#if defined(MK_DLL_EXPORT) && defined(_MSC_VER)
    #define MK_API __declspec(dllexport)
#elif defined(__cplusplus)
    #define MK_API extern "C"
#else
    #define MK_API
#endif

#ifndef MK_MAX_PATH
    #define MK_MAX_PATH 1024
#endif

#include <stdbool.h>    // true, false
#include <stddef.h>     // size_t used for array sizes
#include <stdint.h>     // uintptr_t used for pointer values

//
// Core API
//

typedef struct MK_Buffer {
    uint8_t*    data;
    size_t      length;
} MK_Buffer;

// Returns the last error for the calling thread
MK_API const char* mk_get_last_error(void);

//
// Process API
//

typedef struct MK_ProcessInfo {
    unsigned long   pid;                // OS-specific identifier
    char            path[MK_MAX_PATH];  // Executable file path, if present
} MK_ProcessInfo;

typedef struct MK_ProcessList MK_ProcessList;

// Get the PID of the calling process
MK_API unsigned long mk_get_pid(void);

// Walk the process list
MK_API MK_ProcessList*  mk_begin_process_list(void);
MK_API bool             mk_next_process(MK_ProcessList* list, MK_ProcessInfo* info);
MK_API void             mk_end_process_list(MK_ProcessList* list);

// Find a process by name
// Matches absolute path and file name
MK_API bool mk_find_process(const char* name, MK_ProcessInfo* info);

//
// Tracer API
//

typedef struct MK_ProcessTracer MK_ProcessTracer;

// Attach to a running process
MK_API MK_ProcessTracer* mk_attach(unsigned long pid);

// Detach from a running process
MK_API void mk_detach(MK_ProcessTracer* trace);

// Modify virtual memory
MK_API size_t mk_remote_read(MK_ProcessTracer* trace, uintptr_t addr, void* data, size_t size);
MK_API size_t mk_remote_write(MK_ProcessTracer* trace, uintptr_t addr, const void* data, size_t size);

//
// Module API
//

// Only x86 is supported
#define MK_PAGE_SIZE (1 << 12)

// Align a memory address to the lower x86 memory page boundary
#define MK_PAGE_ALIGN(addr) ((addr) & ~(MK_PAGE_SIZE - 1))

typedef struct MK_ModuleInfo {
    uintptr_t   base_address;
    uintptr_t   size;
    char        path[MK_MAX_PATH];
} MK_ModuleInfo;

typedef struct MK_ModuleList MK_ModuleList;

// Walk the module list
MK_API MK_ModuleList*   mk_begin_module_list(unsigned long pid);
MK_API bool             mk_next_module(MK_ModuleList* list, MK_ModuleInfo* info);
MK_API void             mk_end_module_list(MK_ModuleList* list);

// Find a module by name
// Matches absolute path and file name
MK_API bool mk_find_module(unsigned long pid, const char* name, MK_ModuleInfo* info);

// Get the module for a process' executable
MK_API bool mk_get_process_module(unsigned long pid, MK_ModuleInfo* info);

//
// Executable parsing
//

typedef enum MK_ExeType {
    MK_EXE_TYPE_ELF = 0,
    MK_EXE_TYPE_PE,
} MK_ExeType;

typedef enum MK_ExeSectionType {
    MK_EXE_SECTION_TYPE_UNKNOWN = 0,
    MK_EXE_SECTION_TYPE_CODE,
} MK_ExeSectionType;

typedef struct MK_ExeSection {
    MK_ExeSectionType   type;
    uint64_t            image_offset;
    uint64_t            memory_offset;
    uint64_t            length;
} MK_ExeSection;

typedef struct MK_ExeSymbol {
    const char* name;
    size_t      value;
} MK_ExeSymbol;

typedef struct MK_Exe {
    MK_ExeType      type;
    MK_ExeSection*  sections;
    size_t          sections_count;
    MK_ExeSymbol*   symbols;
    size_t          symbols_count;
} MK_Exe;

// Parse an executable
MK_API MK_Exe* mk_parse_exe(MK_Buffer buffer);

// Free a parsed executable
MK_API void mk_free_exe(MK_Exe* exe);

//
// Function detours
//

typedef struct MK_Detour {
    uintptr_t   target;
    uintptr_t   destination;
    bool        installed;
    uint8_t     backup[1 + sizeof(uintptr_t)];
} MK_Detour;

MK_API bool mk_install_detour(MK_Detour* detour);
MK_API bool mk_uninstall_detour(MK_Detour* detour);

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// BEGIN IMPLEMENTATION
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#ifdef MEDKIT_IMPLEMENTATION

// @amalgamate-include("medkit.c")

#endif // MEDKIT_IMPLEMENTATION

#endif // _MEDKIT_H_
