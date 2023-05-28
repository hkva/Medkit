//
// Experiment: Dump ELF sections of a process executable in memory
//
// $ gcc -o elf-inspect-self -Wall -Wextra -Wpedantic elf-inspect-self.c
//

#ifndef _GNU_SOURCE_
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <link.h>

#define ASSERT(cond) if (!(cond)) { fprintf(stderr, "ASSERT FAILED %s:%d %s\n", __FILE__, __LINE__, #cond); exit(1); }

static void dump_elf(const void* elf_ptr) {
    uintptr_t base = (uintptr_t)elf_ptr;
    // File header
    const ElfW(Ehdr)* hdr = (ElfW(Ehdr)*)elf_ptr;
    // Validate header
    unsigned char ELF_MAGIC[] = { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 };
    for (size_t i = 0; i < (sizeof(ELF_MAGIC) / sizeof(ELF_MAGIC[0])); ++i) {
        if (hdr->e_ident[i] != ELF_MAGIC[i]) {
            ASSERT(0 && "Failed to validate ELF header");
        }
    }
    // Program header table
    const ElfW(Phdr)* phtab = (ElfW(Phdr)*)(base + hdr->e_phoff);
    // Section header table
    const ElfW(Shdr)* shtab = (ElfW(Shdr)*)(base + hdr->e_shoff);
    // Section header string table
    const char* shstrtab = NULL;
    if (shtab[hdr->e_shstrndx].sh_offset) {
        shstrtab = (const char*)(base + shtab[hdr->e_shstrndx].sh_offset);
    }
    // Print first 10 program headers
    printf("Program header count: %d\n", hdr->e_phnum);
    size_t phcount = (hdr->e_phnum < 10) ? hdr->e_phnum : 10;
    for (size_t i = 0; i < phcount; ++i) {
        const ElfW(Phdr)* ph = &phtab[i];
        printf("    ELF program #%lu (%d) at offset +0x%lX\n", i, ph->p_type, ph->p_offset);
    }
    // Print first 10 section headers
    printf("Section header count: %d\n", hdr->e_shnum);
    size_t shcount = (hdr->e_shnum < 10) ? hdr->e_shnum : 10;
    for (size_t i = 0; i < shcount; ++i) {
        const ElfW(Shdr)* sh = &shtab[i];
        const char* name = (shstrtab != NULL) ? &shstrtab[sh->sh_name] : "no name";
        printf("    ELF section #%lu (%s) at offset +0x%lX\n", i, name, sh->sh_offset);
    }
}

int main(void) {
    // Get libc handle
    void* libc = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD); ASSERT(libc);
    // Get ELF base address via link_map entry
    struct link_map* lmap = NULL;
    dlinfo(libc, RTLD_DI_LINKMAP, &lmap); ASSERT(lmap);
    printf("libc path: %s\n", lmap->l_name);
    printf("libc base: %p\n", (void*)lmap->l_addr);

    // Test 1: ELF from disk - works just fine
    printf("Parsing libc ELF from disk:\n");
    {
        FILE* f = fopen(lmap->l_name, "rb"); ASSERT(f);
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        void* elf = malloc(len); ASSERT(elf);
        fseek(f, 0, SEEK_SET);
        fread(elf, 1, len, f);
        dump_elf(elf);
    }
    // Test 2: ELF from memory - ELF section header fields are all 0
    // I don't know why!
    // Dynamic linker source code: glibc/elf/rtld.c - doesn't help (?)
    printf("Parsing libc ELF from memory:\n");
    {
        dump_elf((void*)lmap->l_addr);
    }
}
