RISCV_PREFIX ?= riscv32-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy

# Source files
STARTUP = start.S
LINKER_SCRIPT = linker.ld 

# Compilation flags
CFLAGS = -march=rv32i -mabi=ilp32 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O0

ifdef INCLUDE_DIR
CFLAGS += -I$(INCLUDE_DIR)
endif

ifndef OUT
OUT = compile
endif

ifndef TARGET
TARGET = ../test_program.c
endif

ifndef NAME
NAME = out
endif

all:
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(TARGET) -o $(OUT)/$(NAME).elf
	$(OBJCOPY) -O binary $(OUT)/$(NAME).elf $(OUT)/$(NAME).bin
	python3 elf_viewer.py $(OUT)/$(NAME).elf $(OUT)/$(NAME).log