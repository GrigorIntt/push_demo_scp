module Multiplexer_N_to_1 #(
  parameter N = 2,
  parameter StartIndex = 31, parameter EndIndex = 0
) (
  input  logic[StartIndex:EndIndex] in[N],
  input  logic[$clog2(N)-1:0]       select,
  output logic[StartIndex:EndIndex] out
);
  assign out = in[select];
endmodule
