module InstructionMemory (
    input logic[31:0] addr,
    output instruction_packed instruction
);
  
logic[31:0] instruction_memory[1024:0];

assign instruction = instruction_memory[{addr[10:2], 2'b00}];

endmodule
