TOPLEVEL_LANG = verilog
SIM = verilator
TOPLEVEL = SCP
MODULE = sim_evaluator
VERILOG_SOURCES := $(shell find $(DESIGN) -name '*.sv')
ELF = $(PARENT_DIR)/$(TARGET).elf
OUTDIR = output

# # Print each Verilog source on a new line (Make 4.0+)
# $(info )
# $(foreach src,$(VERILOG_SOURCES),$(info $(src)))
# $(info )

# Include paths
EXTRA_ARGS += -I$(INCLUDE) 

# Verilator specific options
EXTRA_ARGS += --trace --trace-structs
# EXTRA_ARGS += --assert --coverage

SIM_OUT_FILES := dump.vcd results.xml write.log

SITE_PACKAGES_DIR := $(shell find $(PARENT_DIR)/.venv/lib/ -type d -name site-packages)

all: create-utils-pth trace

create-utils-pth:
	echo "$(PARENT_DIR)" > $(SITE_PACKAGES_DIR)/utils.pth

trace:
	$(MAKE) -f $(shell cocotb-config --makefiles)/Makefile.sim \
		TOPLEVEL_LANG=$(TOPLEVEL_LANG) \
		SIM=$(SIM) \
		TOPLEVEL=$(TOPLEVEL) \
		MODULE=$(MODULE) \
		EXTRA_ARGS="$(EXTRA_ARGS)" \
		VERILOG_SOURCES="$(VERILOG_SOURCES)" \
		ELF=$(ELF) SPK_TRACE=$(SPK_TRACE) \
		|| { echo "Simulation failed, cleaning up..."; rm -fr $(OUTDIR); exit 1; }

	@if [ "trace.log" != "$(TRACE)" ]; then mv trace.log $(TRACE); fi

	mkdir -p $(OUTDIR)
	mv $(SIM_OUT_FILES) $(OUTDIR)


clean:
	$(MAKE) -f $(shell cocotb-config --makefiles)/Makefile.sim clean
	rm -rf $(OUTDIR)