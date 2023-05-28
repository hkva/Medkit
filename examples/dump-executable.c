#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#endif

#include "../medkit.c"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load into buffer
    MK_Buffer buf = { 0 };
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: Couldn't load executable %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    fseek(f, 0, SEEK_END);
    buf.length = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf.data = malloc(buf.length); assert(buf.data);
    if (fread(buf.data, 1, buf.length, f) == 0) {
        fprintf(stderr, "Error: Zero-length file\n");
        return EXIT_FAILURE;
    }
    fclose(f);

    // Parse
    MK_Exe* exe = mk_parse_exe(buf);
    if (!exe) {
        fprintf(stderr, "Error: Failed to parse executable: %s\n", mk_get_last_error());
        return EXIT_FAILURE;
    }

    const char* exe_type_names[] = {
        "ELF",
        "PE",
    };

    printf("Executable type: %s\n", exe_type_names[exe->type]);

    const char* section_type_names[] = {
        "Unknown",
        "Code",
    };

    printf("Sections:\n");
    for (size_t i = 0; i < exe->sections_count; ++i) {
        printf("section %zu/%zu:\n", i+1, exe->sections_count);
        printf("    type:           %s\n", section_type_names[exe->sections[i].type]);
        printf("    image offset:   0x%" PRIx64 "\n", exe->sections[i].image_offset);
        printf("    memory offset:  0x%" PRIx64 "\n", exe->sections[i].memory_offset);
        printf("    length:         0x%" PRIx64 "\n", exe->sections[i].length);
    }

    printf("First 25 symbols:\n");
    size_t n = (25 < exe->symbols_count) ? 25 : exe->symbols_count;
    for (size_t i = 0; i < n; ++i) {
        printf("symbol %zu/%zu:\n", i+1, n);
        printf("    name:   %s\n", exe->symbols[i].name);
        printf("    value:  0x%" PRIx64 "\n", exe->symbols[i].value);
    }

    free(buf.data);

}
