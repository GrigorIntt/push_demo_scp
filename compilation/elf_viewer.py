from capstone import *
from utils import read_elf_instructions

import sys

elf = sys.argv[1]
outname = sys.argv[2]

write_file = open(outname, 'w')


md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
elf_instructions, data, arch = read_elf_instructions(elf)

skipped = 0
for addr, inst, inst_bytes in elf_instructions:

    out = [*md.disasm(inst_bytes, 0)]
    if len(out) > 0:
        print(f"ADDR: '0x{addr:08x}'", end=" | ", file=write_file)
        print(f"INST: '0x{inst:08x}'", end=" | ", file=write_file)
        for i in out:
            print(f"READ: {i.mnemonic} {i.op_str}", file=write_file)
    else:
        skipped += 1

print(f"Skipped instructions: {skipped}", file=write_file)

    