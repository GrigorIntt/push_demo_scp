# Makefile for RISC-V program compilation

# Toolchain configuration
RISCV_PREFIX ?= riscv64-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy

INSTGEN = instruction_generate
PROGRAM = $(INSTGEN)/output

# Ensure output directory exists
$(shell mkdir -p $(PROGRAM))

# Source files
SRC_C = test_program.c
STARTUP = $(INSTGEN)/start.S
LINKER_SCRIPT = $(INSTGEN)/linker.ld 
TARGET = $(PROGRAM)/program

# Compilation flags
CFLAGS = -march=rv64imac -mabi=lp64 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O2

all: $(TARGET).bin

$(TARGET).elf: $(SRC_C) $(STARTUP) $(LINKER_SCRIPT)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(SRC_C) -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -fr $(PROGRAM)/*

.PHONY: all clean