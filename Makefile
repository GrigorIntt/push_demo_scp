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

TRACE = trace.log

SIM = simulation
SIM_OUT = $(SIM)/$(TRACE)

SPK = spike_simulation
SPIKE_OUT = $(SPK)/$(TRACE)

all: compile spk sim

spk: 
	make -C $(SPK) PARENT_DIR=$(PWD) TARGET=$(TARGET) TRACE=$(TRACE)

sim: spk
	make -C $(SIM) PARENT_DIR=$(PWD) TARGET=$(TARGET) TRACE=$(TRACE) \
	DESIGN=$(DESIGN) INCLUDE=$(INCLUDE)

compile:
	mkdir -p $(COMPILE_DIR)
	$(CC) $(CFLAGS) -T $(LINKER_SCRIPT) $(STARTUP) $(SRC_C) -o $(TARGET).elf
# $(CC) -o $(TARGET).elf $(SRC_C)
	$(OBJCOPY) -O binary $(TARGET).elf $(TARGET).bin

drive:
	make -C $(SPK) python

clean: spk_clean sim_clean
	rm -fr $(COMPILE_DIR)
	rm -f $(SPIKE_OUT) $(SIM_OUT)

spk_clean:
	make -C $(SPK) clean

sim_clean:
	make -C $(SIM) clean

.PHONY: clean sim_clean spk_clean spk sim compile