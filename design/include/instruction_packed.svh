typedef struct packed {
    logic [6:0]  funct7;    // bits [31:25]
    logic [4:0]  rs2;       // bits [24:20]
    logic [4:0]  rs1;       // bits [19:15]
    logic [2:0]  funct3;    // bits [14:12]
    logic [4:0]  rd;        // bits [11:7]
    logic [6:0]  opcode;    // bits [6:0]
} instruction_packed;
