CMD_FILE = spike_drive.cmd

ifndef SPIKE
SPIKE = ../riscv-tools/riscv-isa-sim/build/spike
endif

ifndef OUT
OUT = compile
endif

ifndef ELF
ELF = ../compilation/compiled/test_program.elf
endif

ifndef NAME
NAME = out
endif

all:
	mkdir -p $(OUT)
	$(SPIKE) \
		--isa=RV32IMAFDC \
		--instructions=100 \
		-l --log=$(OUT)/$(NAME).log \
		$(ELF) 2>&1 | tee $(OUT)/logs.txt