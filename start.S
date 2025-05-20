.section .text.init
.globl _start
_start:
    la sp, _stack
    call main
    j .