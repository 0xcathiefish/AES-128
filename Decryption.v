module inv_aes_128(

    input clk,rst                           ,

    input wire [127:0] ciphertext           ,
    input wire [127:0] key                  ,

    output reg [127:0] plaintext            ,
    output reg [31:0] words                 ,

    output reg [7:0] inter_val_0            ,
    output reg [7:0] inter_val_1            ,
    output reg [7:0] inter_val_2            ,
    output reg [7:0] inter_val_3    
);  

integer i,j,t                               ;

localparam Nb = 4                           ;
localparam Nk = 4                           ;
localparam Nr = 10                          ;

// State definitions    
localparam IDLE          = 'd0              ;  // Initial state
localparam LOAD          = 'd1              ;  // Load ciphertext and key
localparam ROUND         = 'd2              ;  // AddRoundKey operation
localparam InvMixCol     = 'd3              ;  // Inverse mix columns
localparam InvShiftRow   = 'd4              ;  // Inverse shift rows
localparam InvByteSub    = 'd5              ;  // Inverse byte substitution
localparam Decryption    = 'd6              ;  // Key expansion for decryption
localparam OUTPUT        = 'd7              ;  // Output plaintext
localparam INTER         = 'd8              ;  // OUTPUT the INTER value at every round begin

reg [4:0] curr_state                        ;
reg [4:0] round_counter                     ;

reg [7:0]  matrix_ciphertext [3:0] [3:0]    ;
reg [7:0]  matrix_key        [3:0] [3:0]    ;
reg [7:0]  temp_matrix       [3:0] [3:0]    ;
reg [31:0] Rcon              [1:10]         ;
reg [31:0] word              [0:43]         ;
reg [31:0] temp                             ;
reg [1:0]  key_expansion_done               ;
reg [1:0]  flag                             ;


// Initialize Rcon 
initial begin
    Rcon[1]  = 32'h01000000;
    Rcon[2]  = 32'h02000000;
    Rcon[3]  = 32'h04000000;
    Rcon[4]  = 32'h08000000;
    Rcon[5]  = 32'h10000000;
    Rcon[6]  = 32'h20000000;
    Rcon[7]  = 32'h40000000;
    Rcon[8]  = 32'h80000000;
    Rcon[9]  = 32'h1b000000;
    Rcon[10] = 32'h36000000;
end


// Register initialization
initial begin

    i = 0                                   ;
    j = 0                                   ;
    t = 0                                   ;

    for(i=0;i<=3;i=i+1) begin
        for(j=0;j<=3;j=j+1) begin
            matrix_ciphertext[i][j] <= 8'd0 ;
            matrix_key[i][j]        <= 8'd0 ;
            temp_matrix[i][j]       <= 8'd0 ;
        end
    end

	for(i=1;i<=43;i=i+1) begin
		word[i] <= 32'd0;
	end

	plaintext 			<= 128'd0           ;
	words 				<= 32'd0            ;
	key_expansion_done  <= 2'd0             ;
    flag                <= 2'd0             ;
    inter_val_0         <= 8'd0             ;
    inter_val_1         <= 8'd0             ;
    inter_val_2         <= 8'd0             ;
    inter_val_3         <= 8'd0             ;
end


// Inverse S-box function
function [7:0] inv_s_box(input [7:0] din);
    case(din)
        8'h00: inv_s_box = 8'h52;    8'h01: inv_s_box = 8'h09;    8'h02: inv_s_box = 8'h6a;    8'h03: inv_s_box = 8'hd5;
        8'h04: inv_s_box = 8'h30;    8'h05: inv_s_box = 8'h36;    8'h06: inv_s_box = 8'ha5;    8'h07: inv_s_box = 8'h38;
        8'h08: inv_s_box = 8'hbf;    8'h09: inv_s_box = 8'h40;    8'h0a: inv_s_box = 8'ha3;    8'h0b: inv_s_box = 8'h9e;
        8'h0c: inv_s_box = 8'h81;    8'h0d: inv_s_box = 8'hf3;    8'h0e: inv_s_box = 8'hd7;    8'h0f: inv_s_box = 8'hfb;
        
        8'h10: inv_s_box = 8'h7c;    8'h11: inv_s_box = 8'he3;    8'h12: inv_s_box = 8'h39;    8'h13: inv_s_box = 8'h82;
        8'h14: inv_s_box = 8'h9b;    8'h15: inv_s_box = 8'h2f;    8'h16: inv_s_box = 8'hff;    8'h17: inv_s_box = 8'h87;
        8'h18: inv_s_box = 8'h34;    8'h19: inv_s_box = 8'h8e;    8'h1a: inv_s_box = 8'h43;    8'h1b: inv_s_box = 8'h44;
        8'h1c: inv_s_box = 8'hc4;    8'h1d: inv_s_box = 8'hde;    8'h1e: inv_s_box = 8'he9;    8'h1f: inv_s_box = 8'hcb;
        
        8'h20: inv_s_box = 8'h54;    8'h21: inv_s_box = 8'h7b;    8'h22: inv_s_box = 8'h94;    8'h23: inv_s_box = 8'h32;
        8'h24: inv_s_box = 8'ha6;    8'h25: inv_s_box = 8'hc2;    8'h26: inv_s_box = 8'h23;    8'h27: inv_s_box = 8'h3d;
        8'h28: inv_s_box = 8'hee;    8'h29: inv_s_box = 8'h4c;    8'h2a: inv_s_box = 8'h95;    8'h2b: inv_s_box = 8'h0b;
        8'h2c: inv_s_box = 8'h42;    8'h2d: inv_s_box = 8'hfa;    8'h2e: inv_s_box = 8'hc3;    8'h2f: inv_s_box = 8'h4e;
        
        8'h30: inv_s_box = 8'h08;    8'h31: inv_s_box = 8'h2e;    8'h32: inv_s_box = 8'ha1;    8'h33: inv_s_box = 8'h66;
        8'h34: inv_s_box = 8'h28;    8'h35: inv_s_box = 8'hd9;    8'h36: inv_s_box = 8'h24;    8'h37: inv_s_box = 8'hb2;
        8'h38: inv_s_box = 8'h76;    8'h39: inv_s_box = 8'h5b;    8'h3a: inv_s_box = 8'ha2;    8'h3b: inv_s_box = 8'h49;
        8'h3c: inv_s_box = 8'h6d;    8'h3d: inv_s_box = 8'h8b;    8'h3e: inv_s_box = 8'hd1;    8'h3f: inv_s_box = 8'h25;
        
        8'h40: inv_s_box = 8'h72;    8'h41: inv_s_box = 8'hf8;    8'h42: inv_s_box = 8'hf6;    8'h43: inv_s_box = 8'h64;
        8'h44: inv_s_box = 8'h86;    8'h45: inv_s_box = 8'h68;    8'h46: inv_s_box = 8'h98;    8'h47: inv_s_box = 8'h16;
        8'h48: inv_s_box = 8'hd4;    8'h49: inv_s_box = 8'ha4;    8'h4a: inv_s_box = 8'h5c;    8'h4b: inv_s_box = 8'hcc;
        8'h4c: inv_s_box = 8'h5d;    8'h4d: inv_s_box = 8'h65;    8'h4e: inv_s_box = 8'hb6;    8'h4f: inv_s_box = 8'h92;
        
        8'h50: inv_s_box = 8'h6c;    8'h51: inv_s_box = 8'h70;    8'h52: inv_s_box = 8'h48;    8'h53: inv_s_box = 8'h50;
        8'h54: inv_s_box = 8'hfd;    8'h55: inv_s_box = 8'hed;    8'h56: inv_s_box = 8'hb9;    8'h57: inv_s_box = 8'hda;
        8'h58: inv_s_box = 8'h5e;    8'h59: inv_s_box = 8'h15;    8'h5a: inv_s_box = 8'h46;    8'h5b: inv_s_box = 8'h57;
        8'h5c: inv_s_box = 8'ha7;    8'h5d: inv_s_box = 8'h8d;    8'h5e: inv_s_box = 8'h9d;    8'h5f: inv_s_box = 8'h84;
        
        8'h60: inv_s_box = 8'h90;    8'h61: inv_s_box = 8'hd8;    8'h62: inv_s_box = 8'hab;    8'h63: inv_s_box = 8'h00;
        8'h64: inv_s_box = 8'h8c;    8'h65: inv_s_box = 8'hbc;    8'h66: inv_s_box = 8'hd3;    8'h67: inv_s_box = 8'h0a;
        8'h68: inv_s_box = 8'hf7;    8'h69: inv_s_box = 8'he4;    8'h6a: inv_s_box = 8'h58;    8'h6b: inv_s_box = 8'h05;
        8'h6c: inv_s_box = 8'hb8;    8'h6d: inv_s_box = 8'hb3;    8'h6e: inv_s_box = 8'h45;    8'h6f: inv_s_box = 8'h06;
        
        8'h70: inv_s_box = 8'hd0;    8'h71: inv_s_box = 8'h2c;    8'h72: inv_s_box = 8'h1e;    8'h73: inv_s_box = 8'h8f;
        8'h74: inv_s_box = 8'hca;    8'h75: inv_s_box = 8'h3f;    8'h76: inv_s_box = 8'h0f;    8'h77: inv_s_box = 8'h02;
        8'h78: inv_s_box = 8'hc1;    8'h79: inv_s_box = 8'haf;    8'h7a: inv_s_box = 8'hbd;    8'h7b: inv_s_box = 8'h03;
        8'h7c: inv_s_box = 8'h01;    8'h7d: inv_s_box = 8'h13;    8'h7e: inv_s_box = 8'h8a;    8'h7f: inv_s_box = 8'h6b;
        
        8'h80: inv_s_box = 8'h3a;    8'h81: inv_s_box = 8'h91;    8'h82: inv_s_box = 8'h11;    8'h83: inv_s_box = 8'h41;
        8'h84: inv_s_box = 8'h4f;    8'h85: inv_s_box = 8'h67;    8'h86: inv_s_box = 8'hdc;    8'h87: inv_s_box = 8'hea;
        8'h88: inv_s_box = 8'h97;    8'h89: inv_s_box = 8'hf2;    8'h8a: inv_s_box = 8'hcf;    8'h8b: inv_s_box = 8'hce;
        8'h8c: inv_s_box = 8'hf0;    8'h8d: inv_s_box = 8'hb4;    8'h8e: inv_s_box = 8'he6;    8'h8f: inv_s_box = 8'h73;
        
        8'h90: inv_s_box = 8'h96;    8'h91: inv_s_box = 8'hac;    8'h92: inv_s_box = 8'h74;    8'h93: inv_s_box = 8'h22;
        8'h94: inv_s_box = 8'he7;    8'h95: inv_s_box = 8'had;    8'h96: inv_s_box = 8'h35;    8'h97: inv_s_box = 8'h85;
        8'h98: inv_s_box = 8'he2;    8'h99: inv_s_box = 8'hf9;    8'h9a: inv_s_box = 8'h37;    8'h9b: inv_s_box = 8'he8;
        8'h9c: inv_s_box = 8'h1c;    8'h9d: inv_s_box = 8'h75;    8'h9e: inv_s_box = 8'hdf;    8'h9f: inv_s_box = 8'h6e;
        
        8'ha0: inv_s_box = 8'h47;    8'ha1: inv_s_box = 8'hf1;    8'ha2: inv_s_box = 8'h1a;    8'ha3: inv_s_box = 8'h71;
        8'ha4: inv_s_box = 8'h1d;    8'ha5: inv_s_box = 8'h29;    8'ha6: inv_s_box = 8'hc5;    8'ha7: inv_s_box = 8'h89;
        8'ha8: inv_s_box = 8'h6f;    8'ha9: inv_s_box = 8'hb7;    8'haa: inv_s_box = 8'h62;    8'hab: inv_s_box = 8'h0e;
        8'hac: inv_s_box = 8'haa;    8'had: inv_s_box = 8'h18;    8'hae: inv_s_box = 8'hbe;    8'haf: inv_s_box = 8'h1b;
        
        8'hb0: inv_s_box = 8'hfc;    8'hb1: inv_s_box = 8'h56;    8'hb2: inv_s_box = 8'h3e;    8'hb3: inv_s_box = 8'h4b;
        8'hb4: inv_s_box = 8'hc6;    8'hb5: inv_s_box = 8'hd2;    8'hb6: inv_s_box = 8'h79;    8'hb7: inv_s_box = 8'h20;
        8'hb8: inv_s_box = 8'h9a;    8'hb9: inv_s_box = 8'hdb;    8'hba: inv_s_box = 8'hc0;    8'hbb: inv_s_box = 8'hfe;
        8'hbc: inv_s_box = 8'h78;    8'hbd: inv_s_box = 8'hcd;    8'hbe: inv_s_box = 8'h5a;    8'hbf: inv_s_box = 8'hf4;
        
        8'hc0: inv_s_box = 8'h1f;    8'hc1: inv_s_box = 8'hdd;    8'hc2: inv_s_box = 8'ha8;    8'hc3: inv_s_box = 8'h33;
        8'hc4: inv_s_box = 8'h88;    8'hc5: inv_s_box = 8'h07;    8'hc6: inv_s_box = 8'hc7;    8'hc7: inv_s_box = 8'h31;
        8'hc8: inv_s_box = 8'hb1;    8'hc9: inv_s_box = 8'h12;    8'hca: inv_s_box = 8'h10;    8'hcb: inv_s_box = 8'h59;
        8'hcc: inv_s_box = 8'h27;    8'hcd: inv_s_box = 8'h80;    8'hce: inv_s_box = 8'hec;    8'hcf: inv_s_box = 8'h5f;
        
        8'hd0: inv_s_box = 8'h60;    8'hd1: inv_s_box = 8'h51;    8'hd2: inv_s_box = 8'h7f;    8'hd3: inv_s_box = 8'ha9;
        8'hd4: inv_s_box = 8'h19;    8'hd5: inv_s_box = 8'hb5;    8'hd6: inv_s_box = 8'h4a;    8'hd7: inv_s_box = 8'h0d;
        8'hd8: inv_s_box = 8'h2d;    8'hd9: inv_s_box = 8'he5;    8'hda: inv_s_box = 8'h7a;    8'hdb: inv_s_box = 8'h9f;
        8'hdc: inv_s_box = 8'h93;    8'hdd: inv_s_box = 8'hc9;    8'hde: inv_s_box = 8'h9c;    8'hdf: inv_s_box = 8'hef;
        
        8'he0: inv_s_box = 8'ha0;    8'he1: inv_s_box = 8'he0;    8'he2: inv_s_box = 8'h3b;    8'he3: inv_s_box = 8'h4d;
        8'he4: inv_s_box = 8'hae;    8'he5: inv_s_box = 8'h2a;    8'he6: inv_s_box = 8'hf5;    8'he7: inv_s_box = 8'hb0;
        8'he8: inv_s_box = 8'hc8;    8'he9: inv_s_box = 8'heb;    8'hea: inv_s_box = 8'hbb;    8'heb: inv_s_box = 8'h3c;
        8'hec: inv_s_box = 8'h83;    8'hed: inv_s_box = 8'h53;    8'hee: inv_s_box = 8'h99;    8'hef: inv_s_box = 8'h61;
        
        8'hf0: inv_s_box = 8'h17;    8'hf1: inv_s_box = 8'h2b;    8'hf2: inv_s_box = 8'h04;    8'hf3: inv_s_box = 8'h7e;
        8'hf4: inv_s_box = 8'hba;    8'hf5: inv_s_box = 8'h77;    8'hf6: inv_s_box = 8'hd6;    8'hf7: inv_s_box = 8'h26;
        8'hf8: inv_s_box = 8'he1;    8'hf9: inv_s_box = 8'h69;    8'hfa: inv_s_box = 8'h14;    8'hfb: inv_s_box = 8'h63;
        8'hfc: inv_s_box = 8'h55;    8'hfd: inv_s_box = 8'h21;    8'hfe: inv_s_box = 8'h0c;    8'hff: inv_s_box = 8'h7d;
    endcase
endfunction


// Basic multiplication function of 2
function [7:0] gf_mult_by_2(input [7:0] x);
    begin
        gf_mult_by_2 = (x[7] == 1) ? ((x << 1) ^ 8'h1b) : (x << 1);
    end
endfunction

// x9 = x8 + x = x2^3 + x
function [7:0] gf_mult_by_9(input [7:0] x);
    begin
        gf_mult_by_9 = gf_mult_by_2(gf_mult_by_2(gf_mult_by_2(x))) ^ x;
    end
endfunction

// xb = x8 + x2 + x = x2^3 + x2 + x
function [7:0] gf_mult_by_b(input [7:0] x);
    begin
        gf_mult_by_b = gf_mult_by_2(gf_mult_by_2(gf_mult_by_2(x))) ^ gf_mult_by_2(x) ^ x;
    end
endfunction

// xd = x8 + x4 + x = x2^3 + x2^2 + x
function [7:0] gf_mult_by_d(input [7:0] x);
    begin
        gf_mult_by_d = gf_mult_by_2(gf_mult_by_2(gf_mult_by_2(x))) ^ gf_mult_by_2(gf_mult_by_2(x)) ^ x;
    end
endfunction

// xe = x8 + x4 + x2 = x2^3 + x2^2 + x2
function [7:0] gf_mult_by_e(input [7:0] x);
    begin
        gf_mult_by_e = gf_mult_by_2(gf_mult_by_2(gf_mult_by_2(x))) ^ gf_mult_by_2(gf_mult_by_2(x)) ^ gf_mult_by_2(x);
    end
endfunction



//inv_SubByte function
function [31:0] inv_SubByte(input [31:0] a);
    begin
        inv_SubByte = {inv_s_box(a[31:24]), inv_s_box(a[23:16]), inv_s_box(a[15:8]), inv_s_box(a[7:0])};
    end
endfunction

// RotByte function
function [31:0] RotByte(input [31:0] text);
    begin
        RotByte = {text[23:16], text[15:8], text[7:0], text[31:24]};
    end
endfunction


//return sbox substitution value
function [7:0]s_box (input [7:0] din); 		
    case(din)
        8'h00: s_box = 8'h63;    8'h01: s_box = 8'h7c;    8'h02: s_box = 8'h77;    8'h03: s_box = 8'h7b;
        8'h04: s_box = 8'hf2;    8'h05: s_box = 8'h6b;    8'h06: s_box = 8'h6f;    8'h07: s_box = 8'hc5;
        8'h08: s_box = 8'h30;    8'h09: s_box = 8'h01;    8'h0a: s_box = 8'h67;    8'h0b: s_box = 8'h2b;
        8'h0c: s_box = 8'hfe;    8'h0d: s_box = 8'hd7;    8'h0e: s_box = 8'hab;    8'h0f: s_box = 8'h76;
        
        8'h10: s_box = 8'hca;    8'h11: s_box = 8'h82;    8'h12: s_box = 8'hc9;    8'h13: s_box = 8'h7d;
        8'h14: s_box = 8'hfa;    8'h15: s_box = 8'h59;    8'h16: s_box = 8'h47;    8'h17: s_box = 8'hf0;
        8'h18: s_box = 8'had;    8'h19: s_box = 8'hd4;    8'h1a: s_box = 8'ha2;    8'h1b: s_box = 8'haf;
        8'h1c: s_box = 8'h9c;    8'h1d: s_box = 8'ha4;    8'h1e: s_box = 8'h72;    8'h1f: s_box = 8'hc0;
        
        8'h20: s_box = 8'hb7;    8'h21: s_box = 8'hfd;    8'h22: s_box = 8'h93;    8'h23: s_box = 8'h26;
        8'h24: s_box = 8'h36;    8'h25: s_box = 8'h3f;    8'h26: s_box = 8'hf7;    8'h27: s_box = 8'hcc;
        8'h28: s_box = 8'h34;    8'h29: s_box = 8'ha5;    8'h2a: s_box = 8'he5;    8'h2b: s_box = 8'hf1;
        8'h2c: s_box = 8'h71;    8'h2d: s_box = 8'hd8;    8'h2e: s_box = 8'h31;    8'h2f: s_box = 8'h15;
        
        8'h30: s_box = 8'h04;    8'h31: s_box = 8'hc7;    8'h32: s_box = 8'h23;    8'h33: s_box = 8'hc3;
        8'h34: s_box = 8'h18;    8'h35: s_box = 8'h96;    8'h36: s_box = 8'h05;    8'h37: s_box = 8'h9a;
        8'h38: s_box = 8'h07;    8'h39: s_box = 8'h12;    8'h3a: s_box = 8'h80;    8'h3b: s_box = 8'he2;
        8'h3c: s_box = 8'heb;    8'h3d: s_box = 8'h27;    8'h3e: s_box = 8'hb2;    8'h3f: s_box = 8'h75;
        
        8'h40: s_box = 8'h09;    8'h41: s_box = 8'h83;    8'h42: s_box = 8'h2c;    8'h43: s_box = 8'h1a;
        8'h44: s_box = 8'h1b;    8'h45: s_box = 8'h6e;    8'h46: s_box = 8'h5a;    8'h47: s_box = 8'ha0;
        8'h48: s_box = 8'h52;    8'h49: s_box = 8'h3b;    8'h4a: s_box = 8'hd6;    8'h4b: s_box = 8'hb3;
        8'h4c: s_box = 8'h29;    8'h4d: s_box = 8'he3;    8'h4e: s_box = 8'h2f;    8'h4f: s_box = 8'h84;
        
        8'h50: s_box = 8'h53;    8'h51: s_box = 8'hd1;    8'h52: s_box = 8'h00;    8'h53: s_box = 8'hed;
        8'h54: s_box = 8'h20;    8'h55: s_box = 8'hfc;    8'h56: s_box = 8'hb1;    8'h57: s_box = 8'h5b;
        8'h58: s_box = 8'h6a;    8'h59: s_box = 8'hcb;    8'h5a: s_box = 8'hbe;    8'h5b: s_box = 8'h39;
        8'h5c: s_box = 8'h4a;    8'h5d: s_box = 8'h4c;    8'h5e: s_box = 8'h58;    8'h5f: s_box = 8'hcf;
        
        8'h60: s_box = 8'hd0;    8'h61: s_box = 8'hef;    8'h62: s_box = 8'haa;    8'h63: s_box = 8'hfb;
        8'h64: s_box = 8'h43;    8'h65: s_box = 8'h4d;    8'h66: s_box = 8'h33;    8'h67: s_box = 8'h85;
        8'h68: s_box = 8'h45;    8'h69: s_box = 8'hf9;    8'h6a: s_box = 8'h02;    8'h6b: s_box = 8'h7f;
        8'h6c: s_box = 8'h50;    8'h6d: s_box = 8'h3c;    8'h6e: s_box = 8'h9f;    8'h6f: s_box = 8'ha8;
        
        8'h70: s_box = 8'h51;    8'h71: s_box = 8'ha3;    8'h72: s_box = 8'h40;    8'h73: s_box = 8'h8f;
        8'h74: s_box = 8'h92;    8'h75: s_box = 8'h9d;    8'h76: s_box = 8'h38;    8'h77: s_box = 8'hf5;
        8'h78: s_box = 8'hbc;    8'h79: s_box = 8'hb6;    8'h7a: s_box = 8'hda;    8'h7b: s_box = 8'h21;
        8'h7c: s_box = 8'h10;    8'h7d: s_box = 8'hff;    8'h7e: s_box = 8'hf3;    8'h7f: s_box = 8'hd2;
        
        8'h80: s_box = 8'hcd;    8'h81: s_box = 8'h0c;    8'h82: s_box = 8'h13;    8'h83: s_box = 8'hec;
        8'h84: s_box = 8'h5f;    8'h85: s_box = 8'h97;    8'h86: s_box = 8'h44;    8'h87: s_box = 8'h17;
        8'h88: s_box = 8'hc4;    8'h89: s_box = 8'ha7;    8'h8a: s_box = 8'h7e;    8'h8b: s_box = 8'h3d;
        8'h8c: s_box = 8'h64;    8'h8d: s_box = 8'h5d;    8'h8e: s_box = 8'h19;    8'h8f: s_box = 8'h73;
        
        8'h90: s_box = 8'h60;    8'h91: s_box = 8'h81;    8'h92: s_box = 8'h4f;    8'h93: s_box = 8'hdc;
        8'h94: s_box = 8'h22;    8'h95: s_box = 8'h2a;    8'h96: s_box = 8'h90;    8'h97: s_box = 8'h88;
        8'h98: s_box = 8'h46;    8'h99: s_box = 8'hee;    8'h9a: s_box = 8'hb8;    8'h9b: s_box = 8'h14;
        8'h9c: s_box = 8'hde;    8'h9d: s_box = 8'h5e;    8'h9e: s_box = 8'h0b;    8'h9f: s_box = 8'hdb;
        
        8'ha0: s_box = 8'he0;    8'ha1: s_box = 8'h32;    8'ha2: s_box = 8'h3a;    8'ha3: s_box = 8'h0a;
        8'ha4: s_box = 8'h49;    8'ha5: s_box = 8'h06;    8'ha6: s_box = 8'h24;    8'ha7: s_box = 8'h5c;
        8'ha8: s_box = 8'hc2;    8'ha9: s_box = 8'hd3;    8'haa: s_box = 8'hac;    8'hab: s_box = 8'h62;
        8'hac: s_box = 8'h91;    8'had: s_box = 8'h95;    8'hae: s_box = 8'he4;    8'haf: s_box = 8'h79;
        
        8'hb0: s_box = 8'he7;    8'hb1: s_box = 8'hc8;    8'hb2: s_box = 8'h37;    8'hb3: s_box = 8'h6d;
        8'hb4: s_box = 8'h8d;    8'hb5: s_box = 8'hd5;    8'hb6: s_box = 8'h4e;    8'hb7: s_box = 8'ha9;
        8'hb8: s_box = 8'h6c;    8'hb9: s_box = 8'h56;    8'hba: s_box = 8'hf4;    8'hbb: s_box = 8'hea;
        8'hbc: s_box = 8'h65;    8'hbd: s_box = 8'h7a;    8'hbe: s_box = 8'hae;    8'hbf: s_box = 8'h08;
        
        8'hc0: s_box = 8'hba;    8'hc1: s_box = 8'h78;    8'hc2: s_box = 8'h25;    8'hc3: s_box = 8'h2e;
        8'hc4: s_box = 8'h1c;    8'hc5: s_box = 8'ha6;    8'hc6: s_box = 8'hb4;    8'hc7: s_box = 8'hc6;
        8'hc8: s_box = 8'he8;    8'hc9: s_box = 8'hdd;    8'hca: s_box = 8'h74;    8'hcb: s_box = 8'h1f;
        8'hcc: s_box = 8'h4b;    8'hcd: s_box = 8'hbd;    8'hce: s_box = 8'h8b;    8'hcf: s_box = 8'h8a;
        
        8'hd0: s_box = 8'h70;    8'hd1: s_box = 8'h3e;    8'hd2: s_box = 8'hb5;    8'hd3: s_box = 8'h66;
        8'hd4: s_box = 8'h48;    8'hd5: s_box = 8'h03;    8'hd6: s_box = 8'hf6;    8'hd7: s_box = 8'h0e;
        8'hd8: s_box = 8'h61;    8'hd9: s_box = 8'h35;    8'hda: s_box = 8'h57;    8'hdb: s_box = 8'hb9;
        8'hdc: s_box = 8'h86;    8'hdd: s_box = 8'hc1;    8'hde: s_box = 8'h1d;    8'hdf: s_box = 8'h9e;
        
        8'he0: s_box = 8'he1;    8'he1: s_box = 8'hf8;    8'he2: s_box = 8'h98;    8'he3: s_box = 8'h11;
        8'he4: s_box = 8'h69;    8'he5: s_box = 8'hd9;    8'he6: s_box = 8'h8e;    8'he7: s_box = 8'h94;
        8'he8: s_box = 8'h9b;    8'he9: s_box = 8'h1e;    8'hea: s_box = 8'h87;    8'heb: s_box = 8'he9;
        8'hec: s_box = 8'hce;    8'hed: s_box = 8'h55;    8'hee: s_box = 8'h28;    8'hef: s_box = 8'hdf;
        
        8'hf0: s_box = 8'h8c;    8'hf1: s_box = 8'ha1;    8'hf2: s_box = 8'h89;    8'hf3: s_box = 8'h0d;
        8'hf4: s_box = 8'hbf;    8'hf5: s_box = 8'he6;    8'hf6: s_box = 8'h42;    8'hf7: s_box = 8'h68;
        8'hf8: s_box = 8'h41;    8'hf9: s_box = 8'h99;    8'hfa: s_box = 8'h2d;    8'hfb: s_box = 8'h0f;
        8'hfc: s_box = 8'hb0;    8'hfd: s_box = 8'h54;    8'hfe: s_box = 8'hbb;    8'hff: s_box = 8'h16;
        endcase
endfunction


//return the substitution of the input
function [31:0] SubByte(input [31:0] a);	

	SubByte = {s_box(a[31:24]),s_box(a[23:16]),s_box(a[15:8]),s_box(a[7:0])};
endfunction



always @(posedge clk) begin
    if(rst) begin
        curr_state <= IDLE;
        round_counter <= 4'd0;
    end
    else begin
        case(curr_state)

            IDLE: begin
                round_counter <= 4'd0;
                curr_state <= LOAD;
            end


            INTER: begin                                    //check

                if(t == 4) begin

                    inter_val_0 <= 8'h00                    ;
                    inter_val_1 <= 8'h00                    ;
                    inter_val_2 <= 8'h00                    ;
                    inter_val_3 <= 8'h00                    ;
                end

                else begin

                    inter_val_0 <= matrix_ciphertext[0][t]  ;
                    inter_val_1 <= matrix_ciphertext[1][t]  ;
                    inter_val_2 <= matrix_ciphertext[2][t]  ;
                    inter_val_3 <= matrix_ciphertext[3][t]  ;
                end


                t <= t==4 ? 0 : t + 1;

                curr_state <= t==4 ? InvShiftRow : INTER;

            end


            LOAD: begin                                     //check
                
                // load the ciphertext
                // Line 0
                matrix_ciphertext[0][0] <= ciphertext[127:120]      ;
                matrix_ciphertext[1][0] <= ciphertext[119:112]      ;
                matrix_ciphertext[2][0] <= ciphertext[111:104]      ;
                matrix_ciphertext[3][0] <= ciphertext[103:96]       ;

                // Line 1 
                matrix_ciphertext[0][1] <= ciphertext[95:88]        ;
                matrix_ciphertext[1][1] <= ciphertext[87:80]        ;
                matrix_ciphertext[2][1] <= ciphertext[79:72]        ;
                matrix_ciphertext[3][1] <= ciphertext[71:64]        ;

                // Line 2 
                matrix_ciphertext[0][2] <= ciphertext[63:56]        ;
                matrix_ciphertext[1][2] <= ciphertext[55:48]        ;
                matrix_ciphertext[2][2] <= ciphertext[47:40]        ;
                matrix_ciphertext[3][2] <= ciphertext[39:32]        ;

                // Line 3 
                matrix_ciphertext[0][3] <= ciphertext[31:24]        ;
                matrix_ciphertext[1][3] <= ciphertext[23:16]        ;
                matrix_ciphertext[2][3] <= ciphertext[15:8]         ;
                matrix_ciphertext[3][3] <= ciphertext[7:0]          ;

                // load the key
                // Line 0
                matrix_key[0][0] = key[127:120]                     ;
                matrix_key[1][0] = key[119:112]                     ;
                matrix_key[2][0] = key[111:104]                     ;
                matrix_key[3][0] = key[103:96]                      ;

                // Line 1
                matrix_key[0][1] = key[95:88]                       ;
                matrix_key[1][1] = key[87:80]                       ;
                matrix_key[2][1] = key[79:72]                       ;
                matrix_key[3][1] = key[71:64]                       ;

                // Line 2
                matrix_key[0][2] = key[63:56]                       ;
                matrix_key[1][2] = key[55:48]                       ;
                matrix_key[2][2] = key[47:40]                       ;
                matrix_key[3][2] = key[39:32]                       ;

                // Line 3
                matrix_key[0][3] = key[31:24]                       ;
                matrix_key[1][3] = key[23:16]                       ;
                matrix_key[2][3] = key[15:8]                        ;
                matrix_key[3][3] = key[7:0]                         ;


                if(key_expansion_done == 0) begin

                    // Generate the first pre-round key
                    for(i=0; i<=3; i=i+1) begin
						word[i] = {matrix_key[0][i],matrix_key[1][i],matrix_key[2][i],matrix_key[3][i]};
					end

                    // Generate all round keys
                    for(i=4; i<=43; i=i+1) begin
                        if(i % 4 == 0) begin
                            word[i] = word[i-4] ^ (SubByte(RotByte(word[i-1])) ^ Rcon[i/4]);
                        end
                        else begin
                            word[i] = word[i-4] ^ word[i-1];
                        end
                    end


                    if(round_counter == 0) begin

                        // Get the new Round key from the word
                        for(i=0; i<4; i=i+1) begin
                            matrix_key[0][i] <= word[40+i][31:24]   ;
                            matrix_key[1][i] <= word[40+i][23:16]   ;
                            matrix_key[2][i] <= word[40+i][15:8]    ;
                            matrix_key[3][i] <= word[40+i][7:0]     ;
                        end
                    end

                    words[31:0] <= word[43];
                    key_expansion_done <= 1'b1;

                end


                curr_state <= InvShiftRow;
            end


            InvShiftRow: begin                              //check


                if(flag == 0) begin
                    for(i=0; i<=3; i=i+1) begin
                        for(j=0; j<=3; j=j+1) begin

                            matrix_ciphertext[i][j] = matrix_ciphertext[i][j] ^ matrix_key[i][j];
                        end
                    end
                
                flag = 1;
                end


                // Row 0
                matrix_ciphertext[0][0] <= matrix_ciphertext[0][0];
                matrix_ciphertext[0][1] <= matrix_ciphertext[0][1];
                matrix_ciphertext[0][2] <= matrix_ciphertext[0][2];
                matrix_ciphertext[0][3] <= matrix_ciphertext[0][3];
                
                // Row 1
                matrix_ciphertext[1][0] <= matrix_ciphertext[1][3];
                matrix_ciphertext[1][1] <= matrix_ciphertext[1][0];
                matrix_ciphertext[1][2] <= matrix_ciphertext[1][1];
                matrix_ciphertext[1][3] <= matrix_ciphertext[1][2];
                
                // Row 2
                matrix_ciphertext[2][0] <= matrix_ciphertext[2][2];
                matrix_ciphertext[2][1] <= matrix_ciphertext[2][3];
                matrix_ciphertext[2][2] <= matrix_ciphertext[2][0];
                matrix_ciphertext[2][3] <= matrix_ciphertext[2][1];
                
                // Row 3
                matrix_ciphertext[3][0] <= matrix_ciphertext[3][1];
                matrix_ciphertext[3][1] <= matrix_ciphertext[3][2];
                matrix_ciphertext[3][2] <= matrix_ciphertext[3][3];
                matrix_ciphertext[3][3] <= matrix_ciphertext[3][0];

                curr_state <= InvByteSub;

            end


            InvByteSub: begin                                //check
                for(i=0; i<=3; i=i+1) begin
                    for(j=0; j<=3; j=j+1) begin

                        matrix_ciphertext[i][j] <= inv_s_box(matrix_ciphertext[i][j]);
                    end
                end

                    curr_state <= Decryption;
            end


            Decryption: begin                               //check

                //Get round key in reverse order (from round 10 to round 0) max round_counter = 9
                for(i=0; i<4; i=i+1) begin
                    matrix_key[0][i] = word[40 - (4*round_counter) - 4 + i][31:24]  ;  
                    matrix_key[1][i] = word[40 - (4*round_counter) - 4 + i][23:16]  ;
                    matrix_key[2][i] = word[40 - (4*round_counter) - 4 + i][15:8]   ;
                    matrix_key[3][i] = word[40 - (4*round_counter) - 4 + i][7:0]    ;
                end

                //Get the title of the key in round
                words[31:0] <= {matrix_key[0][0],matrix_key[1][0],matrix_key[2][0],matrix_key[3][0]};


                round_counter <= round_counter + 1;                
                curr_state <= ROUND;
            end


            ROUND: begin                                    //check
                // AddRoundKey
                for(i=0; i<=3; i=i+1) begin
                    for(j=0; j<=3; j=j+1) begin
                        matrix_ciphertext[i][j] <= matrix_ciphertext[i][j] ^ matrix_key[i][j];
                    end
                end

                curr_state <= round_counter == 10 ? OUTPUT : InvMixCol;
            end


            InvMixCol: begin
                for(j = 0; j < 4; j = j + 1) begin
                    temp_matrix[0][j] = matrix_ciphertext[0][j]                 ;
                    temp_matrix[1][j] = matrix_ciphertext[1][j]                 ;
                    temp_matrix[2][j] = matrix_ciphertext[2][j]                 ;
                    temp_matrix[3][j] = matrix_ciphertext[3][j]                 ;
                    
                    matrix_ciphertext[0][j] <= gf_mult_by_e(temp_matrix[0][j])  ^ 
                                               gf_mult_by_b(temp_matrix[1][j])  ^ 
                                               gf_mult_by_d(temp_matrix[2][j])  ^ 
                                               gf_mult_by_9(temp_matrix[3][j])  ;

                    matrix_ciphertext[1][j] <= gf_mult_by_9(temp_matrix[0][j])  ^ 
                                               gf_mult_by_e(temp_matrix[1][j])  ^ 
                                               gf_mult_by_b(temp_matrix[2][j])  ^ 
                                               gf_mult_by_d(temp_matrix[3][j])  ;

                    matrix_ciphertext[2][j] <= gf_mult_by_d(temp_matrix[0][j])  ^ 
                                               gf_mult_by_9(temp_matrix[1][j])  ^ 
                                               gf_mult_by_e(temp_matrix[2][j])  ^ 
                                               gf_mult_by_b(temp_matrix[3][j])  ;

                    matrix_ciphertext[3][j] <= gf_mult_by_b(temp_matrix[0][j])  ^ 
                                               gf_mult_by_d(temp_matrix[1][j])  ^ 
                                               gf_mult_by_9(temp_matrix[2][j])  ^ 
                                               gf_mult_by_e(temp_matrix[3][j])  ;
                end

                curr_state <= INTER;
            end



            OUTPUT: begin                                   //check

                // OUTPUT the final  result

                plaintext <= {matrix_ciphertext[0][0], matrix_ciphertext[1][0],matrix_ciphertext[2][0], matrix_ciphertext[3][0], 
                              matrix_ciphertext[0][1], matrix_ciphertext[1][1],matrix_ciphertext[2][1], matrix_ciphertext[3][1],
                              matrix_ciphertext[0][2], matrix_ciphertext[1][2],matrix_ciphertext[2][2], matrix_ciphertext[3][2],
                              matrix_ciphertext[0][3], matrix_ciphertext[1][3],matrix_ciphertext[2][3], matrix_ciphertext[3][3]};
            end


        endcase
    end
end




// Debug module
always@(posedge clk) begin

    case(curr_state)
        IDLE:         $display("IDLE")                          ;
        LOAD:         $display("LOAD")                          ;
        ROUND:        $display("ROUND = %d", round_counter)     ;
        InvMixCol:    $display("InvMixCol")                     ;
        InvShiftRow:  $display("InvShiftRow")                   ;
        InvByteSub:   $display("InvByteSub")                    ;
        Decryption:   $display("Decryption")                    ;
        OUTPUT:       $display("OUTPUT")                        ;
    endcase
end

endmodule
