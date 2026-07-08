#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

/*
 * Fork a child process and set it up for tracing.
 * Replaces the child's image with the target program.
 */
pid_t run_target(char* const argv[])
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(argv[0], argv);
        exit(1);
    } else {
        perror("fork");
        exit(1);
    }
    return 0;
}

void* get_elf_content(const char* sym_name, const char* file_name)
{
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd < 0) {
        perror("failed to open file");
        return NULL;
    }

    struct stat elf_stats;
    int ret = fstat(elf_fd, &elf_stats);
    if (ret < 0) {
        perror("fstat failed");
        close(elf_fd);
        return NULL;
    }
    long file_size = elf_stats.st_size;

    void* file_content = malloc(file_size);
    if (!file_content) {
        perror("malloc failed");
        close(elf_fd);
        return NULL;
    }

    ret = read(elf_fd, file_content, file_size);
    if (ret < file_size) {
        perror("read failed or incomplete");
        free(file_content);
        close(elf_fd);
        return NULL;
    }
    close(elf_fd);

    return file_content;
}

unsigned long parse_elf(const char* target_sym, void* file_contents)
{
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_contents;
    Elf64_Shdr* shdrs = (Elf64_Shdr*)((char*)file_contents + ehdr->e_shoff);
    Elf64_Shdr* shstrtab_shdr = &shdrs[ehdr->e_shstrndx];
    const char* shstrtab = (const char*)file_contents + shstrtab_shdr->sh_offset;

    Elf64_Shdr* symtab_shdr = NULL;
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = &shdrs[i];
            break;
        }
    }

    if (!symtab_shdr) return 0;

    Elf64_Shdr* strtab_shdr = &shdrs[symtab_shdr->sh_link];
    if (!strtab_shdr) return 0;

    Elf64_Sym* symtab = (Elf64_Sym*)((char*)file_contents + symtab_shdr->sh_offset);
    const char* strtab = (const char*)file_contents + strtab_shdr->sh_offset;
    int num_syms = symtab_shdr->sh_size / symtab_shdr->sh_entsize;

    for (int i = 0; i < num_syms; ++i) {
        if (strcmp(strtab + symtab[i].st_name, target_sym) == 0) {
            if (symtab[i].st_shndx != SHN_UNDEF) {
                return symtab[i].st_value;
            }
        }
    }

    return 0;
}

void print_params(struct user_regs_struct* regs, int nr_params) {
    if (nr_params == 0) {
        printf("()");
        return;
    }
    printf("(");
    for (int i = 0; i < nr_params; i++) {
        long long val = 0;
        switch (i) {
            case 0: val = regs->rdi; break;
            case 1: val = regs->rsi; break;
            case 2: val = regs->rdx; break;
            case 3: val = regs->rcx; break;
            case 4: val = regs->r8;  break;
            case 5: val = regs->r9;  break;
        }
        printf("%d", (int)val);
        if (i < nr_params - 1) printf(", ");
    }
    printf(")");
}

void run_tracer(pid_t child_pid, unsigned long addr, int nr_params)
{
    int wait_status;
    struct user_regs_struct regs;

    wait(&wait_status);
    if (!WIFSTOPPED(wait_status)) {
        return;
    }

    unsigned long bp1_orig_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    if ((bp1_orig_data & 0xFF) == 0x55) {
        printf("PRF:: This function starts by pushing rbp\n");
    }

    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)((bp1_orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC));

    int call_counter = 1;
    bool in_function = false;
    unsigned long outer_rsp = 0;
    unsigned long bp2_addr = 0;
    unsigned long bp2_orig_data = 0;
    bool bp2_active = false;

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    while (1) {
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
            break;
        }
        if (!WIFSTOPPED(wait_status)) {
            continue;
        }

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        if (regs.rip - 1 == addr) {
            if (!in_function) {
                in_function = true;
                outer_rsp = regs.rsp;
                bp2_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
                bp2_orig_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)bp2_addr, NULL);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)bp2_addr, (void*)((bp2_orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC));
                bp2_active = true;

                printf("PRF:: run #%d called with ", call_counter++);
                print_params(&regs, nr_params);
                printf(":\n");
            } else {
                printf("PRF::     entered recursive call with ");
                print_params(&regs, nr_params);
                printf("\n");
            }

            ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)bp1_orig_data);
            regs.rip = addr;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)((bp1_orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC));

            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        } else if (bp2_active && regs.rip - 1 == bp2_addr) {
            if (regs.rsp == outer_rsp + 8) {
                printf("PRF::   call to function returned with %d\n", (int)regs.rax);
                in_function = false;

                ptrace(PTRACE_POKETEXT, child_pid, (void*)bp2_addr, (void*)bp2_orig_data);
                regs.rip = bp2_addr;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                bp2_active = false;

                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            } else {
                ptrace(PTRACE_POKETEXT, child_pid, (void*)bp2_addr, (void*)bp2_orig_data);
                regs.rip = bp2_addr;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_POKETEXT, child_pid, (void*)bp2_addr, (void*)((bp2_orig_data & 0xFFFFFFFFFFFFFF00) | 0xCC));

                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            }
        } else {
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        }
    }
}

int main(int argc, char* const argv[])
{
    if (argc < 4) {
        printf("usage: <sym_name> <number of input params> <elf_path> "
               "[optional input params for elf file]\n");
        return 0;
    }

    const char* sym_name  = argv[1];
    int nr_params         = strtol(argv[2], NULL, 10);
    const char* file_name = argv[3];

    void* file_content = get_elf_content(sym_name, file_name);
    if (!file_content) {
        return 1;
    }

    unsigned long addr = parse_elf(sym_name, file_content);
    free(file_content);

    if (addr == 0) {
        printf("PRF:: symbol not found\n");
        return 1;
    }
    
    printf("PRF:: symbol address is 0x%lX\n", addr);

    pid_t child_pid = run_target(argv + 3);

    run_tracer(child_pid, addr, nr_params);

    return 0;
}
