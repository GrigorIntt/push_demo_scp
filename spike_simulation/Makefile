# Toolchain configuration
RISCV_PREFIX ?= riscv32-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy

OUTDIR = output
PROGRAM = compile

TRACE = trace
SPIKE = $(PARENT_DIR)/riscv-tools/riscv-isa-sim/build/spike

# Source files
STARTUP = start.S
LINKER_SCRIPT = linker.ld 

TARGET = $(PROGRAM)/program
CMD_FILE = spike_drive.cmd
SRC_C = $(PARENT_DIR)/$(C_CODE)

# Compilation flags
CFLAGS = -march=rv32imac_zicsr -mabi=ilp32 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O2

ifdef INCLUDE_DIR
CFLAGS += -I$(INCLUDE_DIR)
endif

all: $(TARGET).bin trace

$(TARGET).elf: $(SRC_C) $(STARTUP) $(LINKER_SCRIPT)
	mkdir -p $(PROGRAM)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(SRC_C) -o $@


$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

trace: $(TARGET).elf
	mkdir -p $(OUTDIR)
	$(SPIKE) \
		--isa=RV32IMAFDC \
		--instructions=100 \
		-l --log=$(OUTDIR)/trace.log \
		$(TARGET).elf 2>&1 | tee $(OUTDIR)/output.log

debug: $(TARGET).elf
	$(SPIKE) \
		-l --log=$(TRACE)/trace.log \
		-d --debug-cmd=${CMD_FILE} \
		$(TARGET).elf 2>&1 | tee $(TRACE)/output.log

manual: $(TARGET).elf
	$(SPIKE) \
		-l --log=$(TRACE)/trace.log \
		-d \
		$(TARGET).elf

python: $(TARGET).elf
	python3 spike_driver.py $(SPIKE) $(TARGET).elf $(TRACE)/output.log


clean:
	rm -fr $(PROGRAM)/* $(TRACE)/*

.PHONY: all clean trace