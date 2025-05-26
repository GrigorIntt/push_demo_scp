OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128K
}

SECTIONS {
    .text : {
        *(.text.init)
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
    } > RAM

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        __bss_end = .;
    } > RAM

    /* Stack at end of memory */
    .stack (NOLOAD) : {
        . = ALIGN(16);
        _stack = .;
        . += 0x4000;  /* 16KB stack */
        _stack_top = .;
    } > RAM

    /* SPIKE communication */
    .tohost : {
        tohost = .;
    } > RAM

    .fromhost : {
        fromhost = .;
    } > RAM

    _end = .;
}