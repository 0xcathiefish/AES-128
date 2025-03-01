module aes_128(

    input clk,rst					        ,

    input wire [127:0] plaintext	        ,
    input wire [127:0] key			        ,

    output reg [127:0] ciphertext	        ,
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
localparam IDLE     		= 'd0           ; // set the situation to rst
localparam LOAD     		= 'd1           ; // load the plaintext and key
localparam ROUND    		= 'd2           ; // do the round
localparam ByteSub  		= 'd3           ; // do the byte substitution
localparam ShiftRow 		= 'd4           ; // do the shift row
localparam MixCol   		= 'd5           ; // do the mix column
localparam Encryption 		= 'd6           ; // do the key expansion
localparam OUTPUT			= 'd7           ; // output the ciphertext
localparam INTER		    = 'd8           ; // output the INTER Value After Shiftrows


reg [4:0] curr_state					    ;
reg [4:0] round_counter					    ;  //round counter


reg [7:0]  matrix_plaintext  [3:0] [3:0]    ;
reg [7:0]  matrix_key        [3:0] [3:0]    ;
reg [7:0]  temp_matrix 		 [3:0] [3:0]    ;
reg [31:0] Rcon 			 [1:10]		    ;
reg [31:0] word				 [0:43]		    ;
reg [31:0] temp							    ;
reg [1:0]  key_expansion_done			    ;


//Initialize the Rcon
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


//Initialize all the registers
initial begin						
    
    i=0                                     ;
    j=0                                     ;
    t=0                                     ;

	for(i=0;i<=3;i=i+1) begin
		for(j=0;j<=3;j=j+1) begin

			matrix_plaintext[i][j]  <= 8'd0 ;
			matrix_key		[i][j] 	<= 8'd0 ;
			temp_matrix		[i][j] 	<= 8'd0 ;
	end
	end

	for(i=1;i<=43;i=i+1) begin

		word[i] <= 32'd0;
	end

	ciphertext 			<= 128'd0           ;
	words 				<= 32'd0            ;
	key_expansion_done  <= 2'd0             ;
    inter_val_0         <= 8'd0             ;
    inter_val_1         <= 8'd0             ;
    inter_val_2         <= 8'd0             ;
    inter_val_3         <= 8'd0             ;
end


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


//return the multiplication of 2 of the mixcol
function [7:0] gf_mult_by_2 (input [7:0] x);
    begin
        gf_mult_by_2 = (x[7] == 1) ? ((x << 1) ^ 8'h1B) : (x << 1);
    end
endfunction

//return the multiplication of 3 of the mixcol
function [7:0] gf_mult_by_3 (input [7:0] x);
    begin
        gf_mult_by_3 = gf_mult_by_2(x) ^ x;
    end
endfunction

//return the rotation of the input text
function [31:0] RotByte(input [31:0] text);	

	RotByte = {text[23:16],text[15:8],text[7:0],text[31:24]};
endfunction

//return the substitution of the text
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
            IDLE: begin                                                                //check          
                round_counter <= 4'd0;
                curr_state <= LOAD;
            end


            INTER: begin                                                                 //check

                //cout the inter value after ShiftRow
                if(t == 4) begin

                    inter_val_0 <= 8'h00;
                    inter_val_1 <= 8'h00;
                    inter_val_2 <= 8'h00;
                    inter_val_3 <= 8'h00;
                end

                else begin

                    inter_val_0 <= matrix_plaintext[0][t];
                    inter_val_1 <= matrix_plaintext[1][t];
                    inter_val_2 <= matrix_plaintext[2][t];
                    inter_val_3 <= matrix_plaintext[3][t];
                end


                t <= t==4 ? 0 : t + 1;

                curr_state <= t==4 ? ShiftRow : INTER;    

            end



            LOAD: begin      														   //check
				
                // Load the plaintext
                // Line 0
                matrix_plaintext[0][0] <= plaintext[127:120]    ; 
                matrix_plaintext[1][0] <= plaintext[119:112]    ; 
                matrix_plaintext[2][0] <= plaintext[111:104]    ; 
                matrix_plaintext[3][0] <= plaintext[103:96]     ; 

                // Line 1   
                matrix_plaintext[0][1] <= plaintext[95:88]      ; 
                matrix_plaintext[1][1] <= plaintext[87:80]      ; 
                matrix_plaintext[2][1] <= plaintext[79:72]      ; 
                matrix_plaintext[3][1] <= plaintext[71:64]      ; 

                // Line 2   
                matrix_plaintext[0][2] <= plaintext[63:56]      ; 
                matrix_plaintext[1][2] <= plaintext[55:48]      ; 
                matrix_plaintext[2][2] <= plaintext[47:40]      ; 
                matrix_plaintext[3][2] <= plaintext[39:32]      ; 

                // Line 3   
                matrix_plaintext[0][3] <= plaintext[31:24]      ; 
                matrix_plaintext[1][3] <= plaintext[23:16]      ; 
                matrix_plaintext[2][3] <= plaintext[15:8]       ; 
                matrix_plaintext[3][3] <= plaintext[7:0]        ; 

                // Load the key 
                // Line 0   
                matrix_key[0][0] <= key[127:120]                ;
                matrix_key[1][0] <= key[119:112]                ;
                matrix_key[2][0] <= key[111:104]                ;
                matrix_key[3][0] <= key[103:96]                 ;

                // Line 1   
                matrix_key[0][1] <= key[95:88]                  ;
                matrix_key[1][1] <= key[87:80]                  ;
                matrix_key[2][1] <= key[79:72]                  ;
                matrix_key[3][1] <= key[71:64]                  ;

                // Line 2                   
                matrix_key[0][2] <= key[63:56]                  ;
                matrix_key[1][2] <= key[55:48]                  ;
                matrix_key[2][2] <= key[47:40]                  ;
                matrix_key[3][2] <= key[39:32]                  ;

                // Line 3                   
                matrix_key[0][3] <= key[31:24]                  ;
                matrix_key[1][3] <= key[23:16]                  ;
                matrix_key[2][3] <= key[15:8]                   ;
                matrix_key[3][3] <= key[7:0]                    ;


                curr_state <= ROUND;
            end


            ROUND: begin                                                               //check
                
                for(i=0;i<=3;i=i+1) begin
                    for(j=0;j<=3;j=j+1) begin

                        //Let the plaintext xor with the roudkey
                        matrix_plaintext[i][j] <= matrix_plaintext[i][j] ^ matrix_key[i][j];
                    end
                end

                curr_state <= round_counter == 10 ? OUTPUT : ByteSub;

            end

            OUTPUT: begin 														   	   //check	
                
                //output the final result
                ciphertext <= {matrix_plaintext[0][0], matrix_plaintext[1][0], matrix_plaintext[2][0], matrix_plaintext[3][0],
                               matrix_plaintext[0][1], matrix_plaintext[1][1], matrix_plaintext[2][1], matrix_plaintext[3][1],
                               matrix_plaintext[0][2], matrix_plaintext[1][2], matrix_plaintext[2][2], matrix_plaintext[3][2],
                               matrix_plaintext[0][3], matrix_plaintext[1][3], matrix_plaintext[2][3], matrix_plaintext[3][3]};
            end


            ByteSub: begin                                                             //check
                
                for(i=0;i<=3;i=i+1) begin
                    for(j=0;j<=3;j=j+1) begin

                        matrix_plaintext[i][j] <= s_box(matrix_plaintext[i][j]);
                    end
                end

                curr_state <= INTER;
            end


            ShiftRow: begin                                                            //check
                
				// Row 0: no shift
                matrix_plaintext[0][0] <= matrix_plaintext[0][0];
                matrix_plaintext[0][1] <= matrix_plaintext[0][1];
                matrix_plaintext[0][2] <= matrix_plaintext[0][2];
                matrix_plaintext[0][3] <= matrix_plaintext[0][3];
                
                // Row 1: shift left by 1
                matrix_plaintext[1][0] <= matrix_plaintext[1][1];
                matrix_plaintext[1][1] <= matrix_plaintext[1][2];
                matrix_plaintext[1][2] <= matrix_plaintext[1][3];
                matrix_plaintext[1][3] <= matrix_plaintext[1][0];
                
                // Row 2: shift left by 2
                matrix_plaintext[2][0] <= matrix_plaintext[2][2];
                matrix_plaintext[2][1] <= matrix_plaintext[2][3];
                matrix_plaintext[2][2] <= matrix_plaintext[2][0];
                matrix_plaintext[2][3] <= matrix_plaintext[2][1];
                
                // Row 3: shift left by 3 
                matrix_plaintext[3][0] <= matrix_plaintext[3][3];
                matrix_plaintext[3][1] <= matrix_plaintext[3][0];
                matrix_plaintext[3][2] <= matrix_plaintext[3][1];
                matrix_plaintext[3][3] <= matrix_plaintext[3][2];


                curr_state <= round_counter == 9 ? Encryption : MixCol;

            end


            MixCol: begin                                                              //check

                for(j = 0; j < 4; j = j + 1) begin
                    temp_matrix[0][j] = matrix_plaintext[0][j]				  ;
                    temp_matrix[1][j] = matrix_plaintext[1][j]				  ;
                    temp_matrix[2][j] = matrix_plaintext[2][j]				  ;
                    temp_matrix[3][j] = matrix_plaintext[3][j]				  ;
                    
                    
                    matrix_plaintext[0][j] <= gf_mult_by_2(temp_matrix[0][j]) ^ 
                                              gf_mult_by_3(temp_matrix[1][j]) ^ 
                                              temp_matrix[2][j] 			  ^ 
                                              temp_matrix[3][j]				  ;
                    
                    matrix_plaintext[1][j] <= temp_matrix[0][j] 			  ^ 
                                              gf_mult_by_2(temp_matrix[1][j]) ^ 
                                              gf_mult_by_3(temp_matrix[2][j]) ^ 
                                              temp_matrix[3][j]				  ;
                    
                    matrix_plaintext[2][j] <= temp_matrix[0][j] 			  ^ 
                                              temp_matrix[1][j] 			  ^ 
                                              gf_mult_by_2(temp_matrix[2][j]) ^ 
                                              gf_mult_by_3(temp_matrix[3][j]) ;
                    
                    matrix_plaintext[3][j] <= gf_mult_by_3(temp_matrix[0][j]) ^ 
                                              temp_matrix[1][j] 			  ^ 
                                              temp_matrix[2][j] 			  ^ 
                                              gf_mult_by_2(temp_matrix[3][j]) ;
                end

                curr_state <= Encryption;
                
            end

            Encryption: begin														   //check		


				if(key_expansion_done == 0) begin                               	   //check
					// Expand the key when the first time
					for(i=0; i<4; i=i+1) begin
						word[i] = {matrix_key[0][i],matrix_key[1][i],matrix_key[2][i],matrix_key[3][i]};
					end

					for(i=4; i<44; i=i+1) begin
						if(i % 4 == 0) begin
							word[i] = word[i-4] ^ (SubByte(RotByte(word[i-1])) ^ Rcon[i/4]);
						end
						else begin
							word[i] = word[i-4] ^ word[i-1];
                        end
                    end

					words[31:0] = word[10];

					key_expansion_done <= 1'b1;
				end



                // Get the new Round key from the word
                for(i=0; i<4; i=i+1) begin
                    matrix_key[0][i] <= word[4*round_counter + i+4][31:24]  ;
                    matrix_key[1][i] <= word[4*round_counter + i+4][23:16]  ;
                    matrix_key[2][i] <= word[4*round_counter + i+4][15:8]   ;
                    matrix_key[3][i] <= word[4*round_counter + i+4][7:0]    ;
                end


				round_counter <= round_counter + 1;
                curr_state <= ROUND;  
            end

        endcase
    end
end









//debug module

always@(posedge clk) begin

	case(curr_state)

		IDLE: 		$display("IDLE")                        ;
		LOAD: 		$display("LOAD")                        ;
		OUTPUT: 	$display("OUTPUT")                      ;
		ROUND: 		$display("ROUND = %d", round_counter)   ;
		ByteSub: 	$display("ByteSub")                     ;
		ShiftRow: 	$display("ShiftRow")                    ;
		MixCol: 	$display("MixCol")                      ;
		Encryption: $display("Encryption")                  ;
        INTER:      $display("INTER")                       ;
	endcase
end





endmodule
