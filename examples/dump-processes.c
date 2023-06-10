#include "../medkit.c"

#include <stdio.h>

int main(void) {
    // Walk process list
    MK_ProcessList* plist = mk_begin_process_list();
    MK_ProcessInfo pinfo;

    while (mk_next_process(plist, &pinfo)) {

        // Print process info
        printf("[PID = %5.0lu] %s\n", pinfo.pid, pinfo.path);

        // Walk module list for each process
        MK_ModuleList* mlist = mk_begin_module_list(pinfo.pid);
        MK_ModuleInfo minfo;
        while (mk_next_module(mlist, &minfo)) {
            // Print module info
            printf("    %s\n", minfo.path);
            printf("        Base address: %p\n", (void*)minfo.base_address);
            printf("        Size: %p\n", (void*)minfo.size);
        }
        mk_end_module_list(mlist);
    }

    mk_end_process_list(plist);

    // Look up some specific programs by name
    const char* EXAMPLE_PROGRAMS[] = {
        "notepad.exe",
        "firefox.exe",
        "bash",
        "vim",
    };

    for (size_t i = 0; i < sizeof(EXAMPLE_PROGRAMS) / sizeof(EXAMPLE_PROGRAMS[0]); ++i) {
        printf("Is %s running? ", EXAMPLE_PROGRAMS[i]);
        if (mk_find_process(EXAMPLE_PROGRAMS[i], &pinfo)) {
            printf("Yes (PID = %lu)\n", pinfo.pid);
        } else {
            printf("No\n");
        }
    }

    // Get base address for this process
    MK_ModuleInfo this_info;
    if (mk_get_process_module(mk_get_pid(), &this_info)) {
        printf("Base address of %s: %p\n", this_info.path, (void*)this_info.base_address);
    }
}
