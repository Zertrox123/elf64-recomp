#include "runtime64.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
    rt_init(argc, argv, envp);

    CPU64 cpu;
    rt_init_thread_cpu(&cpu, 8 * 1024 * 1024);

    /* Resolve IFUNC relocations before running constructors. */
    for (size_t i = 0; i < g_rt_irelative_count; i++) {
        uint64_t resolved = rt_invoke64(&cpu, g_rt_irelatives[i].resolver, 0, 0, 0, 0, 0, 0);
        W64(g_rt_irelatives[i].got, resolved);
    }

    /* Run ELF DT_INIT / DT_INIT_ARRAY constructors (shared libs first, then main). */
    for (size_t i = 0; i < g_rt_init_array_count; i++) {
        rt_invoke64(&cpu, g_rt_init_array[i],
                    (uint64_t)argc, (uint64_t)(uintptr_t)argv, (uint64_t)(uintptr_t)envp,
                    0, 0, 0);
        if (cpu.halted) return cpu.exit_code;
    }

    if (g_rt_main_addr) {
        uint64_t ret = rt_invoke64(&cpu, g_rt_main_addr,
                                   (uint64_t)argc, (uint64_t)(uintptr_t)argv, (uint64_t)(uintptr_t)envp,
                                   0, 0, 0);
        return cpu.halted ? cpu.exit_code : (int)(int32_t)ret;
    }

    if (g_rt_entry_addr) {
        /* Build Linux x86_64 _start stack: argc, argv..., NULL, envp..., NULL, auxv(AT_NULL). */
        int envc = 0;
        while (envp && envp[envc]) envc++;
        push64(&cpu, 0); push64(&cpu, 0); /* AT_NULL */
        push64(&cpu, 0);
        for (int i = envc - 1; i >= 0; i--) push64(&cpu, (uint64_t)(uintptr_t)envp[i]);
        push64(&cpu, 0);
        for (int i = argc - 1; i >= 0; i--) push64(&cpu, (uint64_t)(uintptr_t)argv[i]);
        push64(&cpu, (uint64_t)argc);
        rt_call(&cpu, g_rt_entry_addr);
        return cpu.halted ? cpu.exit_code : (int)(int32_t)cpu.rax;
    }

    fprintf(stderr, "elf64-recomp: no main symbol or entry point found\n");
    return 1;
}
