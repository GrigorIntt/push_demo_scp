import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer, FallingEdge
from cocotb.binary import BinaryValue, BinaryRepresentation
import os

from utils import read_elf_instructions, sv_enumerate, parse_spike_trace_to_dict

from capstone import *


@cocotb.test()
async def spike_evaluation_trace_test(dut):
    elf = os.getenv("ELF")
    spk_trace = os.getenv("SPK_TRACE")

    log_trace = open('trace.log', 'w')
    log_write = open('write.log', 'w')

    insts, data, arch = read_elf_instructions(elf)
    parse_spike_trace_to_dict()

    # custom = [0x00004117, 
    #         0x04010113, 
    #         0xff017113, 
    #         0x00000517, 
    #         0x03050513, 
    #         0x00000597, 
    #         0x02858593, 
    #         0x00b57763, 
    #         0x00e000ef]
    # insts = [(i, inst, inst.to_bytes(4, byteorder='little')) for i, inst in enumerate(custom)]

    # Start a 10ns period clock on 'clk'
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)

    for decoded, (addr, inst, ibytes) in enumerate(insts):
        
        out = [*md.disasm(ibytes, 0)]
        print(f"ADDR: {addr:08x}", end=" | ", file=log_write)
        print(f"INST: {inst:08x}", end=" | ", file=log_write)
        if len(out) == 1:
            inst_bin_str = format(inst, '032b')
            dut.IM.instruction_memory[decoded].value = BinaryValue(inst_bin_str, n_bits=32)
            decoded = out[0]
            print(f"READ: {decoded.mnemonic} {decoded.op_str}", file=log_write)
        else:
            print(f"XXX SKIPPED (error={len(out)}) XXX", file=log_write)
    

    dut.rst.value = 1
    await Timer(10)
    dut.rst.value = 0
    
    for decoded in range(15):
        await RisingEdge(dut.clk)


        pc = dut.addr.value.integer
        addr = 0xf000000 + pc * 4

        inst = dut.instruction.value.integer
        ibytes = inst.to_bytes(4, byteorder='little')
        out = [*md.disasm(ibytes, 0)]


        if len(out) == 1:
            decoded = out[0]
            inst_txt = f"{decoded.mnemonic} {decoded.op_str}"
            print(f'core   0: 0x{addr:08x} (0x{inst:08x}) {inst_txt}', file=log_trace)
        else:
            print(f"XXX SKIPPED (error={len(out)}) XXX", file=log_trace)

    # for i, inst_in_memory in sv_enumerate(dut.IM.instruction_memory, 1):
    #     pass
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

    


    log_trace.close()
    log_write.close()

def enchant_binary_instr(inst:str):
    return inst
