OUTDIR = output

SPIKE = $(PARENT_DIR)/riscv-tools/riscv-isa-sim/build/spike
ELF = $(PARENT_DIR)/$(TARGET)
CMD_FILE = spike_drive.cmd

all: trace

trace:
	mkdir -p $(OUTDIR)
	$(SPIKE) \
		--isa=RV32IMAFDC \
		--instructions=100 \
		-l --log=$(OUTDIR)/trace.log \
		$(ELF).elf 2>&1 | tee $(OUTDIR)/output.log

debug:
	$(SPIKE) \
		-l --log=$(OUTDIR)/trace.log \
		-d --debug-cmd=${CMD_FILE} \
		$(ELF).elf 2>&1 | tee $(OUTDIR)/output.log

manual:
	$(SPIKE) \
		-l --log=$(OUTDIR)/trace.log \
		-d \
		$(ELF).elf

python:
	python3 spike_driver.py $(SPIKE) $(ELF).elf $(OUTDIR)/output.log


clean:
	rm -fr $(OUTDIR)

.PHONY: all clean trace