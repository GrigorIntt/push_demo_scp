import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer, FallingEdge
from cocotb.binary import BinaryValue, BinaryRepresentation

# from utils import format_riscv_instruction, riscv_binary_to_assembly

@cocotb.test()
async def test_vector_assignment(dut):
    log = open_py_log_file()
    insts = get_instuctions_list()
    # print(insts, file=log)
    # print(file=log)

    # Start a 10ns period clock on 'clk'
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())

    for i, inst_hex_str in enumerate(insts):
        inst_bin_str = format(int(inst_hex_str, 16), '032b')
        dut.IM.instruction_memory[i].value = BinaryValue(inst_bin_str, n_bits=32)
        # legal, inst_assembly = riscv_binary_to_assembly(inst_bin_str)
        # print(f'{i:<5} {inst_bin_str} -> {inst_assembly}', file=log)
    
    print(file=log)

    dut.rst.value = 1
    await Timer(10)
    dut.rst.value = 0
    

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

def get_instuctions_list():
    with open("instructions.txt", 'r') as f:
        return [l.strip() for l in f.readlines()]
    
def open_py_log_file():
    return open('trace.log', 'w')

def enchant_binary_instr(inst:str):
    return inst

def sv_enumerate(sv_array, force_ascending=False): 
    # if force_ascending is True you will lost the real indexing diection
    start_index, end_index = sv_array._range
    inc = 1 if start_index < end_index else -1 # Define the incerment direction
    for i in range(start_index, end_index + inc, inc)[::inc if force_ascending else 1]:
        yield i, sv_array[i]
