.section .text.init
.global _start
_start:
    /* Initialize stack pointer */
    la sp, _stack_top
    andi sp, sp, -16  /* 16-byte align */

    /* Clear BSS section */
    la a0, __bss_start
    la a1, __bss_end
    bgeu a0, a1, 2f
1:
    sw zero, 0(a0)
    addi a0, a0, 4
    bltu a0, a1, 1b
2:
    /* Call main */
    call main
    call _Exit