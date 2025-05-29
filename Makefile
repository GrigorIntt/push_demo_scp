DESIGN = $(PWD)/design
INCLUDE = $(PWD)/design/include

SIM = simulation
SIM_OUT = $(SIM)/output/trace.log

SPK = spike_simulation
SPIKE_OUT = $(SPK)/output/trace.log

all: $(SIM_OUT) $(SPIKE_OUT)

$(SIM_OUT):
	make -C $(SIM) DESIGN=$(DESIGN) INCLUDE=$(INCLUDE)

$(SPIKE_OUT):
	make -C $(SPK) PARENT_DIR=$(PWD) C_CODE="test_program.c"

drive:
	make -C $(SPK) python

clean: clean_spike clean_sim

clean_spike:
	make -C $(SPK) clean

clean_sim:
	make -C $(SIM) clean