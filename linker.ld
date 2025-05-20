/* Simple linker script for RISC-V */
OUTPUT_ARCH( "riscv" )
ENTRY( _start )

SECTIONS
{
  /* Text section (code) */
  . = 0x80000000;
  .text : {
    *(.text.init)
    *(.text .text.*)
  }

  /* Global data */
  .data : { *(.data .data.*) }
  .rodata : { *(.rodata .rodata.*) }
  .bss : { *(.bss .bss.*) }

  /* Ensure there's some stack space */
  . = ALIGN(16);
  . += 0x1000;
  _stack = .;

  /* End of memory */
  _end = .;
}