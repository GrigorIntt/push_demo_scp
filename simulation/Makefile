SIM = verilator
TOPLEVEL_LANG = verilog
MODULE = sim_evaluator

ifndef OUT
OUT = compile
endif

ifndef ELF
ELF = ../compilation/compiled/test_program.elf
endif

ifndef NAME
NAME = out
endif

ifndef TOPLEVEL
TOPLEVEL = design_top
endif

ifndef SPK_TRACE
SPK_TRACE = ../spike_simulation/output/spike_trace.log
endif

ifndef DESIGN
DESIGN = ../design
endif

ifndef INCLUDE
INCLUDE = ../design/include
endif

VERILOG_SOURCES := $(shell find $(DESIGN) -name '*.sv')
EXTRA_ARGS += -I$(INCLUDE) 
EXTRA_ARGS += --trace --trace-structs
# EXTRA_ARGS += --assert --coverage

SIM_OUT_FILES = $(abspath dump.vcd results.xml write.txt $(NAME).log)

all:
	$(MAKE) -f $(shell cocotb-config --makefiles)/Makefile.sim \
		TOPLEVEL_LANG=$(TOPLEVEL_LANG) \
		SIM=$(SIM) \
		TOPLEVEL=$(TOPLEVEL) \
		MODULE=$(MODULE) \
		EXTRA_ARGS="$(EXTRA_ARGS)" \
		VERILOG_SOURCES="$(VERILOG_SOURCES)" \
		ELF=$(ELF) SPK_TRACE=$(SPK_TRACE) NAME=$(NAME) \
		|| { echo "Simulation failed, cleaning up... \n$(SIM_OUT_FILES)"; rm -f $(SIM_OUT_FILES); exit 1;}

	mkdir -p $(OUT)
	mv $(SIM_OUT_FILES) $(OUT)


clean:
	$(MAKE) -f $(shell cocotb-config --makefiles)/Makefile.sim clean
	rm -rf $(OUT)
	rm -f $(SIM_OUT_FILES)