RISCV_PREFIX ?= riscv64-unknown-elf-
SPIKE_PATH ?= /riscv-tools/riscv-isa-sim/build
VERILATOR ?= verilator
PROGRAM = test_program
DUT = single_stage_proc

.PHONY: compile_prog

compile_prog: $(PROGRAM).c
	$(RISCV_PREFIX)gcc -march=rv32i -mabi=ilp32 -o $(PROGRAM).elf $<
	$(RISCV_PREFIX)objcopy -O binary $(PROGRAM).elf $(PROGRAM).bin
	$(RISCV_PREFIX)objdump -d $(PROGRAM).elf > $(PROGRAM).dump