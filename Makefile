EVAL = evaluation

CMP = compilation
SRC_C = $(realpath test_program.c)
CMP_OUT = compiled
CMP_NAME = test_program
DEST_ELF = $(PWD)/$(EVAL)/$(CMP_OUT)/$(CMP_NAME).elf

SPK = spike_simulation
SPIKE_BUILD = $(realpath riscv-tools/riscv-isa-sim/build/spike)
SPK_OUT = output
SPK_NAME = spike_trace
DEST_SPK_TRACE = $(PWD)/$(EVAL)/$(SPK_NAME).log

SIM = simulation
DESIGN = $(realpath design)
INCLUDE = $(realpath design/include)
DESIGN_TOP = "SCP"
SIM_OUT = output
SIM_NAME = compare
DEST_SIM_COMP = $(PWD)/$(EVAL)/$(SIM_NAME).log

all: compile spk sim

compile:
	make -C $(CMP) TARGET=$(SRC_C) OUT=$(CMP_OUT) NAME=$(CMP_NAME)
	mkdir -p $(EVAL)/$(CMP_OUT)
	cp $(CMP)/$(CMP_OUT)/$(CMP_NAME).elf $(DEST_ELF)

spk: $(DEST_ELF)
	make -C $(SPK) ELF=$(DEST_ELF) OUT=$(SPK_OUT) NAME=$(SPK_NAME)
	cp $(SPK)/$(SPK_OUT)/$(SPK_NAME).log $(DEST_SPK_TRACE)

sim: $(DEST_ELF) $(DEST_SPK_TRACE) import-this-to-python
	make -C $(SIM) ELF=$(DEST_ELF) OUT=$(SIM_OUT) NAME=$(SIM_NAME) \
	DESIGN=$(DESIGN) INCLUDE=$(INCLUDE) TOPLEVEL=$(DESIGN_TOP)
	cp $(SIM)/$(SIM_OUT)/$(SIM_NAME).log $(DEST_SIM_COMP)

import-this-to-python:
	echo "$(realpath ./)" > $(shell python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")/utils.pth

clean_eval:
	rm -fr $(EVAL)

clean_spk:
	rm -fr $(SPK)/$(SPK_OUT)

clean_sim:
	rm -fr $(SIM)/$(SIM_OUT)
	make -C $(SIM) clean

clean: clean_eval clean_spk clean_sim

.PHONY: clean clean_eval clean_spk clean_sim spk sim compile