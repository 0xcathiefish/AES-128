`timescale 1ns/1ns;

module aes_tb;

    parameter cycle = 2     ;

    reg clk,rst             ;
    reg  [127:0] plaintext  ;
    reg  [127:0] key        ;
    wire [127:0] ciphertext ;
    wire [31:0]  words      ;

    wire [7:0] inter_val_0  ;
    wire [7:0] inter_val_1  ;
    wire [7:0] inter_val_2  ;
    wire [7:0] inter_val_3  ;


aes_128 aes_inst(clk,rst,plaintext,key,ciphertext,words,inter_val_0,inter_val_1,inter_val_2,inter_val_3);

initial begin

    clk = 1;
    rst = 1;

    plaintext = 128'd0;
    key       = 128'd0;

    forever begin
        #(cycle/2) clk = ~clk;
    end
end

initial begin
    #10 rst = 0;


    //expected:3925841d02dc09fbdc118597196a0b32

    plaintext = 128'h3243f6a8885a308d313198a2e0370734;
    key       = 128'h2b7e151628aed2a6abf7158809cf4f3c;


    //expected:69c4e0d86a7b0430d8cdb78070b4c55a

    //plaintext = 128'h00112233445566778899aabbccddeeff;
    //key       = 128'h000102030405060708090a0b0c0d0e0f;

    #210;
    rst = 1;
    $finish;  
    
    // if(ciphertext === 128'h3925841d02dc09fbdc118597196a0b32) begin
    //     $display("Encryption successful! Result matches expected output.");
    // end
    // else begin
    //     $display("failed");
    // end

end


endmodule
