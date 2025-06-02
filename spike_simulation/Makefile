OUTDIR = output

SPIKE = $(PARENT_DIR)/riscv-tools/riscv-isa-sim/build/spike

CMD_FILE = spike_drive.cmd

all: trace

trace: $(TARGET).elf
	mkdir -p $(OUTDIR)
	$(SPIKE) \
		--isa=RV32IMAFDC \
		--instructions=100 \
		-l --log=$(OUTDIR)/trace.log \
		$(TARGET).elf 2>&1 | tee $(OUTDIR)/output.log

debug: $(TARGET).elf
	$(SPIKE) \
		-l --log=$(OUTDIR)/trace.log \
		-d --debug-cmd=${CMD_FILE} \
		$(TARGET).elf 2>&1 | tee $(OUTDIR)/output.log

manual: $(TARGET).elf
	$(SPIKE) \
		-l --log=$(OUTDIR)/trace.log \
		-d \
		$(TARGET).elf

python: $(TARGET).elf
	python3 spike_driver.py $(SPIKE) $(TARGET).elf $(OUTDIR)/output.log


clean:
	rm -fr $(OUTDIR)

.PHONY: all clean trace