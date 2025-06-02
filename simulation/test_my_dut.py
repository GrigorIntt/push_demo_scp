import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer, FallingEdge
from cocotb.binary import BinaryValue, BinaryRepresentation
import os

from utils import read_elf_instructions, sv_enumerate

from capstone import *


@cocotb.test()
async def test_vector_assignment(dut):
    elf = os.getenv("ELF")

    log_trace = open('trace.log', 'w')
    log_write = open('write.log', 'w')
    
    insts, data, arch = read_elf_instructions(elf)

    # Start a 10ns period clock on 'clk'
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)

    for i, (addr, inst, ibytes) in enumerate(insts):
        
        out = [*md.disasm(ibytes, 0)]
        print(f"ADDR: {addr:08x}", end=" | ", file=log_write)
        print(f"INST: {inst:08x}", end=" | ", file=log_write)
        if len(out) > 0:
            inst_bin_str = format(inst, '032b')
            dut.IM.instruction_memory[i].value = BinaryValue(inst_bin_str, n_bits=32)
            for i in out:
                print(f"READ: {i.mnemonic} {i.op_str}", file=log_write)
        else:
            print("XXX SKIPPED XXX", file=log_write)
    

    dut.rst.value = 1
    await Timer(10)
    dut.rst.value = 0
    
    return 0
    for i in range(10):
        await RisingEdge(dut.clk)
        # legal, inst_assembly = riscv_binary_to_assembly(str(dut.instruction.value))

        print(f'{i:<5} {dut.addr.value.integer:<10} {inst_assembly}', file=log)

    print(file=log)
    
    for i, inst_in_memory in sv_enumerate(dut.IM.instruction_memory, 1):
        pass
        # legal, inst_assembly = riscv_binary_to_assembly(str(inst_in_memory.value))
        # if not legal:
        #     continue
        # print(f'{i:<5} == {inst_assembly}', file=log)


    # await Timer(100, 'ns')

    # dut.alu_out.value = BinaryValue(32 * '1', n_bits=32)
    # dut.br_taken.value = BinaryValue('1', n_bits=1)

    # print(file=log)
    # print(dut.program_counter.value.integer, file=log)

    # for i in range(10):
    #     if i == 5:
    #         dut.rst.value = 1
    #         await FallingEdge(dut.clk)
    #         dut.rst.value = 0

    #     await RisingEdge(dut.clk)
    #     print(dut.program_counter.value.integer, dut.next_addr.value.integer, dut.addr.value.integer, file=log)

    


    log.close()

def enchant_binary_instr(inst:str):
    return inst
