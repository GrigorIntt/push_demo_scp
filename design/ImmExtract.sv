module ImmExtract (
  input  logic [31:0] inst,
  input  logic [2:0]  imm_type,
  output logic [31:0] imm_out
);

logic [24:0] Imm;
assign Imm = inst [31:7];

  always_comb begin
    case(imm_type)
    // I Type
    3'b000:   imm_out = {{20{Imm[24]}}, Imm[24:13]};
    // S Type
    3'b001:   imm_out = {{20{Imm[24]}}, Imm[24:18], Imm[4:0]};
    // B Type
    3'b010:   imm_out = {{20{Imm[24]}}, Imm[0],  Imm[23:18], Imm[4:1], 1'b0};
    // J Type
    3'b011:   imm_out = {{12{Imm[24]}}, Imm[12:5],  Imm[13], Imm[23:14], 1'b0};
    // U Type
    3'b100:   imm_out = {12'b0, Imm[24:5]}; 
    default: 	imm_out = 32'dx; // undefined
    endcase
  end

endmodule
