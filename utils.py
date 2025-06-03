from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re

def format_riscv_instruction(bin_str:str, reverse=False):
    """Format a RISC-V binary instruction string into a readable representation.
    
    Args:
        bin_str: Binary string (e.g., '000101010...') of a RISC-V instruction
        
    Returns:
        Beautifully formatted string showing instruction fields
    """
    if len(bin_str) != 32:
        return f"Invalid instruction length: {len(bin_str)} bits (expected 32)"
    if reverse:
        bin_str = bin_str[::-1]
    # Extract the opcode (bits 0-6)
    opcode = bin_str[-7:]  # Using -7: to get the 7 LSBs
    
    # Determine instruction format based on opcode
    if opcode[-2:] == '11':  # Most standard 32-bit instructions
        # R-type: opcode(7) + rd(5) + funct3(3) + rs1(5) + rs2(5) + funct7(7)
        if opcode[-5:] == '01100':  # OP (R-type)
            parts = [
                ('funct7', bin_str[:7]),
                ('rs2', bin_str[7:12]),
                ('rs1', bin_str[12:17]),
                ('funct3', bin_str[17:20]),
                ('rd', bin_str[20:25]),
                ('opcode', bin_str[25:])
            ]
            return "R-type: " + " | ".join(f"{name}: {val}" for name, val in parts)
        
        # I-type: opcode(7) + rd(5) + funct3(3) + rs1(5) + imm(12)
        elif opcode[-5:] == '00100' or opcode == '0000011':  # OP-IMM or LOAD
            parts = [
                ('imm[11:0]', bin_str[:12]),
                ('rs1', bin_str[12:17]),
                ('funct3', bin_str[17:20]),
                ('rd', bin_str[20:25]),
                ('opcode', bin_str[25:])
            ]
            return "I-type: " + " | ".join(f"{name}: {val}" for name, val in parts)
        
        # S-type: opcode(7) + imm[4:0](5) + funct3(3) + rs1(5) + rs2(5) + imm[11:5](7)
        elif opcode == '0100011':  # STORE
            imm_11_5 = bin_str[:7]
            rs2 = bin_str[7:12]
            rs1 = bin_str[12:17]
            funct3 = bin_str[17:20]
            imm_4_0 = bin_str[20:25]
            opcode = bin_str[25:]
            imm = imm_11_5 + imm_4_0
            parts = [
                ('imm[11:5]', imm_11_5),
                ('rs2', rs2),
                ('rs1', rs1),
                ('funct3', funct3),
                ('imm[4:0]', imm_4_0),
                ('opcode', opcode),
                ('imm[11:0]', imm)
            ]
            return "S-type: " + " | ".join(f"{name}: {val}" for name, val in parts)
        
        # U-type: opcode(7) + rd(5) + imm(20)
        elif opcode[-5:] == '01101' or opcode[-5:] == '00101':  # LUI or AUIPC
            parts = [
                ('imm[31:12]', bin_str[:20]),
                ('rd', bin_str[20:25]),
                ('opcode', bin_str[25:])
            ]
            return "U-type: " + " | ".join(f"{name}: {val}" for name, val in parts)
        
        # J-type: opcode(7) + rd(5) + imm(20)
        elif opcode == '1101111':  # JAL
            imm_20 = bin_str[0]
            imm_10_1 = bin_str[1:11]
            imm_11 = bin_str[11]
            imm_19_12 = bin_str[12:20]
            rd = bin_str[20:25]
            opcode = bin_str[25:]
            imm = imm_20 + imm_19_12 + imm_11 + imm_10_1 + '0'  # LSB is 0
            parts = [
                ('imm[20]', imm_20),
                ('imm[10:1]', imm_10_1),
                ('imm[11]', imm_11),
                ('imm[19:12]', imm_19_12),
                ('rd', rd),
                ('opcode', opcode),
                ('imm[20:1]', imm[:-1])  # Remove the added 0
            ]
            return "J-type: " + " | ".join(f"{name}: {val}" for name, val in parts)
    
    return f"Unknown instruction format for opcode: {opcode}"

def riscv_binary_to_assembly(binary_str):
    """
    Convert a 32-bit binary string representing a RISC-V instruction to assembly-like code.
    
    Args:
        binary_str: 32-character binary string (e.g., '00000000000100001000000110110011')
    
    Returns:
        String representing the assembly instruction (e.g., 'add x3, x1, x2')
    """
    
    if len(binary_str) != 32:
        return True, "Error: Input must be a 32-bit binary string"
    
    # Extract fields common to all instruction formats
    opcode = binary_str[-7:]
    rd = int(binary_str[-12:-7], 2)
    funct3 = binary_str[-15:-12]
    rs1 = int(binary_str[-20:-15], 2)
    rs2 = int(binary_str[-25:-20], 2)
    funct7 = binary_str[:7]
    
    # R-type instructions
    if opcode == '0110011':
        if funct3 == '000':
            if funct7 == '0000000':
                return True, f"add x{rd}, x{rs1}, x{rs2}"
            elif funct7 == '0100000':
                return True, f"sub x{rd}, x{rs1}, x{rs2}"
        elif funct3 == '110':
            if funct7 == '0000000':
                return True, f"or x{rd}, x{rs1}, x{rs2}"
        elif funct3 == '111':
            if funct7 == '0000000':
                return True, f"and x{rd}, x{rs1}, x{rs2}"
        elif funct3 == '001':
            if funct7 == '0000000':
                return True, f"sll x{rd}, x{rs1}, x{rs2}"
        elif funct3 == '101':
            if funct7 == '0000000':
                return True, f"srl x{rd}, x{rs1}, x{rs2}"
            elif funct7 == '0100000':
                return True, f"sra x{rd}, x{rs1}, x{rs2}"
    
    # I-type instructions
    elif opcode == '0010011':
        imm = int(binary_str[:12], 2)
        if funct3 == '000':
            return True, f"addi x{rd}, x{rs1}, {imm}"
        elif funct3 == '110':
            return True, f"ori x{rd}, x{rs1}, {imm}"
        elif funct3 == '111':
            return True, f"andi x{rd}, x{rs1}, {imm}"
        elif funct3 == '001':
            shamt = int(binary_str[-20:-15], 2)
            return True, f"slli x{rd}, x{rs1}, {shamt}"
        elif funct3 == '101':
            shamt = int(binary_str[-20:-15], 2)
            if funct7 == '0000000':
                return True, f"srli x{rd}, x{rs1}, {shamt}"
            elif funct7 == '0100000':
                return True, f"srai x{rd}, x{rs1}, {shamt}"
    
    # Load instructions (I-type)
    elif opcode == '0000011':
        imm = int(binary_str[:12], 2)
        if funct3 == '010':
            return True, f"lw x{rd}, {imm}(x{rs1})"
    
    # S-type instructions (store)
    elif opcode == '0100011':
        imm = int(binary_str[:7] + binary_str[-12:-7], 2)
        if funct3 == '010':
            return True, f"sw x{rs2}, {imm}(x{rs1})"
    
    # B-type instructions (branch)
    elif opcode == '1100011':
        # B-type immediate calculation (sign-extended)
        imm = int(binary_str[0] + binary_str[-8] + binary_str[1:7] + binary_str[-12:-8] + '0', 2)
        if imm >= 4096:  # Handle negative offsets
            imm -= 8192
        if funct3 == '000':
            return True, f"beq x{rs1}, x{rs2}, {imm}"
        elif funct3 == '001':
            return True, f"bne x{rs1}, x{rs2}, {imm}"
        elif funct3 == '100':
            return True, f"blt x{rs1}, x{rs2}, {imm}"
        elif funct3 == '101':
            return True, f"bge x{rs1}, x{rs2}, {imm}"
        elif funct3 == '110':
            return True, f"bltu x{rs1}, x{rs2}, {imm}"
        elif funct3 == '111':
            return True, f"bgeu x{rs1}, x{rs2}, {imm}"
    
    # J-type instructions (jal)
    elif opcode == '1101111':
        imm = int(binary_str[0] + binary_str[12:20] + binary_str[11] + binary_str[1:11] + '0', 2)
        if imm >= 1048576:  # Handle negative offsets
            imm -= 2097152
        return True, f"jal x{rd}, {imm}"
    
    # U-type instructions (lui, auipc)
    elif opcode == '0110111':
        imm = int(binary_str[:20], 2) << 12
        return True, f"lui x{rd}, {imm}"
    elif opcode == '0010111':
        imm = int(binary_str[:20], 2) << 12
        return True, f"auipc x{rd}, {imm}"
    
    # If no match found
    return False, f"Unknown instruction: {binary_str}"

def read_elf_instructions(file_path, arch=32):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        
        # Find the text section (where code typically resides)
        text_section = elf.get_section_by_name('.text')
        # text_section = [s.name for s in elf.iter_sections()]
        # print(text_section)
        if not text_section:
            raise ValueError("No .text section found in ELF file")
            
        data = text_section.data()
        
        ind = arch // 8
        instructions = []
        for i in range(0, len(data), ind):
            instruction_bytes = data[i:i+ind]
            if len(instruction_bytes) < ind:
                break
            instruction = int.from_bytes(instruction_bytes, byteorder='little')
            pc = text_section['sh_addr'] + i
            instructions.append((
                pc,
                instruction,
                instruction_bytes
            ))
            
        return instructions, data, arch


def sv_enumerate(sv_array, force_ascending=False): 
    # if force_ascending is True you will lost the real indexing diection
    start_index, end_index = sv_array._range
    inc = 1 if start_index < end_index else -1 # Define the incerment direction
    for i in range(start_index, end_index + inc, inc)[::inc if force_ascending else 1]:
        yield i, sv_array[i]

def parse_spike_trace_to_dict(file_path):
    result = []
    pattern = re.compile(r'0x[0-9a-fA-F]+')

    with open(file_path, 'r') as file:
        for line in file:
            matches = pattern.findall(line)
            if len(matches) >= 2:
                key = int(matches[0], 16)
                value = int(matches[1], 16)
                result.append((key, value))

    return result