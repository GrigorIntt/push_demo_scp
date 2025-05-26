module ProgramCounter (
	input  logic clk, rst,
	input  logic [31:0] PC,
	output logic [31:0] addr
);

always_ff @(posedge clk or posedge rst) begin
	if (rst) addr <= 32'd0;
	else addr <= PC;
end
endmodule
