DESIGN = $(PWD)/design
INCLUDE = $(PWD)/design/include

OUTPUT = out

SIM = simulation
SIM_OUT = $(SIM)/output/trace.log

SPK = spike_simulation
SPIKE_OUT = $(SPK)/output/trace.log

all: $(SIM_OUT) $(SPIKE_OUT)

$(SIM_OUT):
	make -C $(SIM) DESIGN=$(DESIGN) INCLUDE=$(INCLUDE) OUTDIR=$(OUTPUT)

$(SPIKE_OUT):
	make -C $(SPK) PARENT_DIR=$(PWD) C=test_program.c OUTDIR=$(OUTPUT)

clean:
	make -C $(SIM) OUTDIR=$(OUTPUT) clean
	make -C $(SPK) OUTDIR=$(OUTPUT) clean