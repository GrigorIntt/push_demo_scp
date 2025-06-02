from capstone import *
from utils import read_elf_instructions

md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
elf_instructions, data, arch = read_elf_instructions('compile/target.elf')
# for addr, inst16, inst2 in elf_instructions:

print(data)
print()
# out = md.disasm(data, int(elf_instructions[0][0], 16))

skipped = 0
for addr, inst, inst_bytes in elf_instructions:
    # print(f"{pc} | 0x{}, b{inst2}")

    out = [*md.disasm(inst_bytes, 0)]
    if len(out) > 0:

        print()

        print(f"ADDR: {addr:08x}", end=" | ")
        print(f"INST: {inst:08x}", end=" | ")
        for i in out:
            print(f"READ: {i.mnemonic} {i.op_str}")
        # print(f"Hexed: {hexed}")
    else:
        skipped += 1

print(f"Skipped instruction: {skipped}")

    