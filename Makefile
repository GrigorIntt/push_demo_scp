# Makefile for RISC-V program compilation

# Toolchain configuration
RISCV_PREFIX ?= riscv64-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy

INSTGEN = instruction_generate
PROGRAM = $(INSTGEN)/output
TRACE = $(INSTGEN)/trace
SPIKE = riscv-tools/riscv-isa-sim/build/spike

# Ensure output and trace directories exist
$(shell mkdir -p $(PROGRAM))
$(shell mkdir -p $(TRACE))

# Source files
SRC_C = test_program.c
STARTUP = $(INSTGEN)/start.S
LINKER_SCRIPT = $(INSTGEN)/linker.ld 
TARGET = $(PROGRAM)/program
CMD_FILE = $(INSTGEN)/spike_drive.cmd
INCLUDE_DIR = src

# Compilation flags
CFLAGS = -march=rv64imac_zicsr -mabi=lp64 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O2 \
		 -I$(INCLUDE_DIR)

all: $(TARGET).bin trace

$(TARGET).elf: $(SRC_C) $(STARTUP) $(LINKER_SCRIPT)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(SRC_C) -o $@

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

trace: $(TARGET).elf
	$(SPIKE) \
		--instructions=1000 \
		-l --log=$(TRACE)/trace.log \
		-d --debug-cmd=${CMD_FILE} \
		$(TARGET).elf > $(TRACE)/output.log

clean:
	rm -fr $(PROGRAM)/* $(TRACE)/*

.PHONY: all clean trace