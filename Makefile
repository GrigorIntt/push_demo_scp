SRC_C = test_program.c

RISCV_PREFIX ?= riscv32-unknown-elf-
CC = $(RISCV_PREFIX)gcc
OBJCOPY = $(RISCV_PREFIX)objcopy
COMPILE_DIR = compile
TARGET = $(COMPILE_DIR)/target
# Source files
STARTUP = start.S
LINKER_SCRIPT = linker.ld 

# Compilation flags
CFLAGS = -march=rv32imac_zicsr -mabi=ilp32 -static -mcmodel=medany \
         -fvisibility=hidden -nostdlib -nostartfiles -O2

ifdef INCLUDE_DIR
CFLAGS += -I$(INCLUDE_DIR)
endif

DESIGN = $(PWD)/design
INCLUDE = $(PWD)/design/include

SIM = simulation
SIM_OUT = $(SIM)/output/trace.log

SPK = spike_simulation
SPIKE_OUT = $(SPK)/output/trace.log

all: compile sim spk

sim:
	make -C $(SIM) PARENT_DIR=$(PWD) DESIGN=$(DESIGN) TARGET=$(TARGET) INCLUDE=$(INCLUDE)

spk:
	make -C $(SPK) PARENT_DIR=$(PWD) TARGET=$(TARGET)

compile:
	mkdir -p $(COMPILE_DIR)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(SRC_C) -o $(TARGET).elf
	$(OBJCOPY) -O binary $(TARGET).elf $(TARGET).bin

drive:
	make -C $(SPK) python

clean: clean_spk clean_sim
	rm -fr $(COMPILE_DIR)
	rm -f $(SPIKE_OUT) $(SIM_OUT)

clean_spk:
	make -C $(SPK) clean

clean_sim:
	make -C $(SIM) clean

.PHONY: clean clean_sim clean_spk spk sim compile