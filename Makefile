# Makefile for RISC-V program compilation

# Toolchain configuration
RISCV_PREFIX ?= riscv64-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy

# Source files
SRC_C = test_program.c
STARTUP = start.S
TARGET = program

# Compilation flags
CFLAGS = -march=rv64imac -mabi=lp64 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O2

all: $(TARGET).bin

$(TARGET).elf: $(SRC_C) $(STARTUP)
	$(CC) $(CFLAGS) -T linker.ld $(STARTUP) $< -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.elf *.bin *.o

.PHONY: all clean