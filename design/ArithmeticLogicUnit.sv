module ArithmeticLogicUnit (
    input logic  [4:0]  alu_op,
    input logic  [31:0] in1, in2,
    output logic [31:0] result
);


 always_comb begin
    case(alu_op)
    5'b00000: result = in1 + in2 ;                             //Addition
    5'b00001: result = in1 - in2 ;                             //Subtraction
    5'b00010: result = in1 << in2[4:0];                        //Shift Left Logical
    5'b00011: result = ($signed(in1) < $signed(in2)) ? 1 : 0;  //Set Less than
    5'b00100: result = (in1 < in2) ? 1 : 0;                    //Set Less than unsigned
    5'b00101: result = in1 ^ in2;                              //LOgical xor
    5'b00110: result = in1 >> in2;                             //Shift Right Logical
    5'b00111: result = in1 >>> in2[4:0];                       //Shift Right Arithmetic
    5'b01000: result = in1 | in2;                              //Logical Or
    5'b01001: result = in1 & in2;                              //Logical and
    5'b01010: result = in2;                                    //Load Upper Immediate

    default:  result = in1 + in2;
    endcase

  end
endmodule
