module InstructionMemory (
    input logic[31:0] addr,
    output instruction_packed instruction
);
  
logic[31:0] instruction_memory[2**10:0];

assign instruction = instruction_memory[addr];

endmodule
