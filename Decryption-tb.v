`timescale 1ns/1ns;

module inv_aes_tb;

    parameter cycle = 2     ;

    reg clk,rst             ;
    reg  [127:0] ciphertext ;
    reg  [127:0] key        ;
    wire [127:0] plaintext  ;
    wire [31:0]  words      ;

    wire [7:0] inter_val_0  ;
    wire [7:0] inter_val_1  ;
    wire [7:0] inter_val_2  ;
    wire [7:0] inter_val_3  ;


inv_aes_128 inv_aes_inst(clk,rst,ciphertext,key,plaintext,words,inter_val_0,inter_val_1,inter_val_2,inter_val_3);

initial begin

    clk = 1;
    rst = 1;

    ciphertext = 128'd0;
    key        = 128'd0;

    forever begin
        #(cycle/2) clk = ~clk;
    end
end

initial begin
    #10 rst = 0;

    //expected:00112233445566778899aabbccddeeff

    ciphertext = 128'h69c4e0d86a7b0430d8cdb78070b4c55a;
    key        = 128'h000102030405060708090a0b0c0d0e0f;

    #240;  
    rst = 1;
    $finish;
    
    // if(plaintext === 128'h3925841d02dc09fbdc118597196a0b32) begin
    //     $display("Decryption successful! Result matches expected output.");
    // end 
end


endmodule
