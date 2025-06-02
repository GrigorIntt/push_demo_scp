`include "instruction_packed.svh"

module SCP (input logic clk, input logic rst);

// Wires
logic PCsrc, reg_wr, sel_A, sel_B, cs, wr, br_taken;
logic[1:0] wb_sel;
logic[2:0] imm_type, funct3;
logic[3:0] mask;
logic[4:0] raddr1, raddr2, waddr, alu_op;
logic[31:0] addr, program_counter, wdata, rdata1, rdata2, imm_out, next_addr;
logic[31:0] alu_in1, alu_in2, alu_result, rdata, data_rd, data_wr;
instruction_packed instruction;

// Fetch
assign next_addr = addr + 1;

Multiplexer_N_to_1 #(.N(3)) MUX_PC(.in('{next_addr, alu_result, 32'b0}), .select({rst, br_taken & !rst}), .out(program_counter));
ProgramCounter PC(clk, rst, program_counter, addr);
InstructionMemory IM(addr, instruction);

// Decode
RegisterFile RF (.clk(clk), .rst(rst), .reg_wr(reg_wr), .raddr1(instruction.rs1), .raddr2(instruction.rs2),
                            .waddr(instruction.rd), .wdata(wdata), .rdata1(rdata1), .rdata2(rdata2));
ImmExtract IMME (.inst(instruction), .imm_type(imm_type), .imm_out(imm_out));
Controller C (.inst(instruction), .reg_wr(reg_wr), .sel_A(sel_A), .sel_B(sel_B), 
              .wb_sel(wb_sel), .imm_type(imm_type), .alu_op(alu_op));
MemoryController MC (.funct3(instruction.funct3), .instr_opcode(instruction.opcode), .data_rd(data_rd),
                     .rdata2(rdata2), .alu_result(alu_result), .cs(cs), .wr(wr), .mask(mask), .data_wr(data_wr), .rdata(rdata));

// Execute
ArithmeticLogicUnit ALU (alu_op, alu_in1, alu_in2, alu_result);
Multiplexer_N_to_1 SEL_ALU_IN1(.in('{addr, rdata1}), .select(sel_A), .out(alu_in1));
Multiplexer_N_to_1 SEL_ALU_IN2(.in('{rdata2, imm_out}), .select(sel_B), .out(alu_in2));
BranchCond BC (.funct3(instruction.funct3), .instr_opcode(instruction.opcode), .rdata1(rdata1), .rdata2(rdata2), .br_taken(br_taken));

// Memory
DataMemory DM (.clk(clk), .rst(rst), .cs(cs), .wr(wr), .mask(mask), .addr(alu_result), .data_wr(data_wr), .data_rd(data_rd));

// Writeback
Multiplexer_N_to_1 #(.N(3)) SEL_WB(.in('{next_addr, alu_result, data_rd}), .select(wb_sel), .out(wdata));



  initial begin
    $dumpfile("dump.vcd");
    $dumpvars(0, Controller);
  end

endmodule
