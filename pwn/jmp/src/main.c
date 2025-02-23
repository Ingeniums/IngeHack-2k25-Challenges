#include <stdio.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

void check(unsigned char *shellcode, size_t shellcode_size) {
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t i;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }

    count = cs_disasm(handle, shellcode, shellcode_size, 0x1000, 0, &insn);
    if (count > 0) {
        for (i = 0; i < count; i++) {
            if (strncmp(insn[i].mnemonic, "jmp", 3) != 0) {
                puts("bye");
                exit(1);
            }
        }

        cs_free(insn, count);
    } else {
        printf("Failed to disassemble shellcode\n");
    }

    cs_close(&handle);
}


void disable_buffering() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void main() {

    disable_buffering();
    
    void *shellcode = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode == MAP_FAILED) {
        perror("mmap");
    }

    ssize_t n = read(0, shellcode, 0x100);

    check(shellcode, n);

    mprotect(shellcode, 4096, PROT_READ | PROT_EXEC);

    ((void(*)())shellcode)();

}
