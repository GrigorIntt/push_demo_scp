module RegisterFile (
    input logic         clk, rst, reg_wr,
    input logic  [4:0]  raddr1, raddr2, waddr,
    input logic  [31:0] wdata,
    output logic [31:0] rdata1, rdata2
);
    logic [31:0] register_file[31:0];

    // Asynchronous Read 
    always_comb begin
        rdata1 = (raddr1 != 0) ? register_file[raddr1] : '0; 
        rdata2 = (raddr2 != 0) ? register_file[raddr2] : '0; 
    end

    // Synchronous Write
    always_ff @(negedge clk or posedge rst) begin
        if (rst) begin
            foreach (register_file[i]) begin 
                register_file[i] <= '0;
            end
        end
        else if (reg_wr && (waddr != 0)) begin
            register_file[waddr] <= wdata;
        end
    end
endmodule
