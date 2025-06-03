EVAL = evaluation
DEST = $(PWD)/$(EVAL)

all: compile spk sim

CMP = compilation
SRC_C = $(realpath test_program.c)
CMP_OUT = compiled
CMP_NAME = test_program
ELF = $(realpath $(CMP)/$(CMP_OUT)/$(CMP_NAME).elf)

compile:
	make -C $(CMP) TARGET=$(SRC_C) OUT=$(CMP_OUT) NAME=$(CMP_NAME)
	mkdir -p $(DEST)
	cp $(CMP)/$(CMP_OUT)/$(CMP_NAME).log $(DEST)


SPK = spike_simulation
SPIKE_BUILD = $(realpath riscv-tools/riscv-isa-sim/build/spike)
SPK_OUT = output
SPK_NAME = spike_trace
DEST_SPK_TRACE = $(DEST)/$(SPK_NAME).log

spk: $(ELF)
	make -C $(SPK) ELF=$(ELF) OUT=$(SPK_OUT) NAME=$(SPK_NAME)
	cp $(SPK)/$(SPK_OUT)/$(SPK_NAME).log $(DEST_SPK_TRACE)

SIM = simulation
DESIGN = $(realpath design)
INCLUDE = $(realpath design/include)
DESIGN_TOP = "SCP"
SIM_OUT = output
SIM_NAME = compare
DEST_SIM_COMP = $(DEST)/$(SIM_NAME).log

sim: $(ELF) $(DEST_SPK_TRACE) import-this-to-python
	make -C $(SIM) ELF=$(ELF) OUT=$(SIM_OUT) NAME=$(SIM_NAME) \
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

outclean:
	rm -fr $(EVAL) $(SPK)/$(SPK_OUT) $(SIM)/$(SIM_OUT)

clean: clean_eval clean_spk clean_sim

.PHONY: clean clean_eval clean_spk clean_sim spk sim compile