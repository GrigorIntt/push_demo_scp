import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer, FallingEdge
from cocotb.binary import BinaryValue, BinaryRepresentation
import os

from utils import read_elf_instructions, sv_enumerate, parse_spike_trace_to_dict
from tabulate import tabulate

from capstone import *


@cocotb.test()
async def spike_evaluation_trace_test(dut):
    elf = os.getenv("ELF")
    spk_trace = os.getenv("SPK_TRACE")
    outname = os.getenv("NAME")

    log_trace = open(f'{outname}.log', 'w')
    log_write = open('write.txt', 'w')

    insts, data, arch = read_elf_instructions(elf)
    spk_eval = parse_spike_trace_to_dict(spk_trace)

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

    try:
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)

        for number, (addr, inst, ibytes) in enumerate(insts):
            
            out = [*md.disasm(ibytes, 0)]
            print(f"ADDR: {addr:08x}", end=" | ", file=log_write)
            print(f"INST: {inst:08x}", end=" | ", file=log_write)

            index = 4 * number
            if len(out) == 1:
                inst_bin_str = format(inst, '032b')
                for i in range(4):
                    dut.IM.instruction_memory[index + i].value = \
                        BinaryValue(inst_bin_str[8 * i: 8 * i + 8], n_bits=8)
                index = out[0]
                print(f"READ: {index.mnemonic} {index.op_str}", file=log_write)
            else:
                print(f"XXX SKIPPED (error={len(out)}) XXX", file=log_write)
        

        dut.rst.value = 1
        await Timer(10)
        dut.rst.value = 0
        

        program_entry_point = 0xf0000000
        start_point_ind = -1
        for i, (a, inst) in enumerate(spk_eval):
            if a == program_entry_point:
                start_point_ind = i
                break
        
        if start_point_ind == -1:
            raise Exception(f"Cant find start point {program_entry_point:08x} in \n" 
                            + "\n".join([f"{a:08x} | {inst}" for a, inst in spk_eval]))

        eval_table = ''
        eval_headers = ["index", "address", "instrution", "simulation executed"]
        eval_data = []

        mm_table = ''
        mm_headers = ["-", "SPIKE", "SIMULATION"]
        mm_data = []

        for i, (spk_addr, spk_inst) in enumerate(spk_eval[start_point_ind:]):
            await RisingEdge(dut.clk)


            pc = dut.addr.value.integer
            sim_addr = program_entry_point + pc
            sim_inst = dut.instruction.value.integer
            
            ibytes = spk_inst.to_bytes(4, byteorder='little')
            out = [*md.disasm(ibytes, 0)]

            undecoded = len(out) != 1
            
            inst_txt = "UNDECODED" if undecoded else f"{out[0].mnemonic} {out[0].op_str}"
            eval_data.append([i, 
                              f"0x{spk_addr:08x}", 
                              f"0x{spk_inst:08x} ({inst_txt})", 
                              f"0x{sim_inst:08x}"])

            addr_check = sim_addr == spk_addr
            inst_check = sim_inst == spk_inst
            if (not addr_check or not inst_check):
                mm_data = [
                        ["ADDRESS", f"0x{spk_addr:08x}", f"0x{sim_addr:08x}"],
                        ["INSTRUTION", f"0x{spk_inst:08x}", f"0x{sim_inst:08x}"],
                        ["INDEX", f"{i}", ""],
                    ]
                if inst_check:
                    raise Exception(f"Mismatch found on addresses\n{mm_table}")
                elif addr_check:
                    raise Exception(f"Mismatch found on instructions\n{mm_table}")
                else:
                    raise Exception(f"Mismatch found on addr and inst\n{mm_table}")




    except Exception as e:
        mm_table = tabulate(mm_data, headers=mm_headers, tablefmt="grid")

        print(mm_table, file=log_trace)
        raise Exception('\n' * 3 + str(e) + '\n' * 3)
    finally:
        eval_table = tabulate(eval_data, eval_headers, tablefmt="grid")
        print(eval_table, file=log_trace)
        print(file=log_trace)
        log_trace.close()
        log_write.close()

def enchant_binary_instr(inst:str):
    return inst
