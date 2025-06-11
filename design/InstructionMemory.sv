module InstructionMemory (
    input logic[31:0] addr,
    output instruction_packed instruction
);
  
logic[7:0] instruction_memory[2**16:0];

assign instruction = {
    instruction_memory[addr],
    instruction_memory[addr+1],
    instruction_memory[addr+2],
    instruction_memory[addr+3]
    };

endmodule
