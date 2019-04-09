FILE struc
	fname db 15 dup(0)
	fhandle dw ?
ENDS


HEADER struc
	; head_size dw ?
	cs_offset dw ?
	data_numeric dw ?
	ds_offset dw ?
ENDS


;COMMANDS
t_MOV db "MOV", 0
t_PUSH db "PUSH", 0
t_POP db "POP", 0
t_ADD db "ADD", 0
t_INC db "INC", 0
t_SUB db "SUB", 0
t_DEC db "DEC", 0
t_CMP db "CMP", 0
t_MUL db "MUL", 0
t_DIV db "DIV", 0
t_CALL db "CALL", 0
t_RET db "RET", 0
t_RETF db "RETF", 0
t_JMP db "JMP", 0
;
t_JA db "JA", 0
t_JAE db "JAE", 0 ; JNC
t_JNAE db "JNAE", 0 ; JC
t_JNA db "JNA"
t_JZ db "JZ", 0
t_JNZ db "JNZ", 0
t_JG db "JG", 0 ; JNLE
t_JGE db "JGE", 0
t_JNGE db "JNGE", 0 ; JL
t_JNG db "JNG", 0 ; JLE
t_JS db "JS", 0
t_JNS db "JNS", 0
t_JO db "JO", 0
t_JNO db "JNO", 0
t_JP db "JP", 0
t_JNP db "JNP", 0
t_JCXZ db "JCXZ", 0
;
t_LOOP db "LOOP", 0
t_INT db "INT", 0
;
; EXTRA
t_OR db "OR", 0
t_ADC db "ADC", 0
t_SBB db "SBB", 0
t_AND db "AND", 0
t_NOP db "NOP", 0
t_INT3 db "INT 3", 0
t_INTO db "INTO", 0
;
t_NONE db "UNKNOWN", 0
;
byte_ptr db "byte ptr ", 0
word_ptr db "word ptr ", 0
	t_byte_ptr dw byte_ptr
	t_word_ptr dw word_ptr
;
t_EXT db "?", 0 ;indication, that addresses byte has to be read to find name
	__ext_opk dw t_EXT




t_data db "@data", 0
;REGISTERS (only those found in address byte table)
t_AL db "AL", 0
t_AX db "AX", 0
t_CL db "CL", 0
t_CX db "CX", 0
t_DL db "DL", 0
t_DX db "DX", 0
t_BL db "BL", 0
t_BX db "BX", 0
t_AH db "AH", 0
t_SP db "SP", 0
t_CH db "CH", 0
t_BP db "BP", 0
t_DH db "DH", 0
t_SI db "SI", 0
t_BH db "BH", 0
t_DI db "DI", 0


;PREFIXES
t_ES db "ES", 0
t_CS db "CS", 0
t_SS db "SS", 0
t_DS db "DS", 0
;numeric values
n_ES EQU 0 ;00 (0)
n_CS EQU 1 ;01 (1)
n_SS EQU 2 ;10 (2)
n_DS EQU 3 ;11 (3)

;addresses to segment registers (for 'sr' part in commands)
label sregs word
	dw t_ES ; 0
	dw t_CS ; 1
	dw t_SS ; 2
	dw t_DS ; 3


;r/m
t_rm_000 db "BX+SI", 0
t_rm_001 db "BX+DI", 0
t_rm_010 db "BP+SI", 0
t_rm_011 db "BP+DI", 0
t_rm_100 db "SI", 0
t_rm_101 db "DI", 0 
t_rm_110 db "BP", 0
t_rm_111 db "BX", 0


;addresses to reg (from address byte)
label regs word
	t_reg_000_w0 dw t_AL
	t_reg_000_w1 dw t_AX
	t_reg_001_w0 dw t_CL
	t_reg_001_w1 dw t_CX
	t_reg_010_w0 dw t_DL
	t_reg_010_w1 dw t_DX
	t_reg_011_w0 dw t_BL
	t_reg_011_w1 dw t_BX
	t_reg_100_w0 dw t_AH
	t_reg_100_w1 dw t_SP
	t_reg_101_w0 dw t_CH
	t_reg_101_w1 dw t_BP
	t_reg_110_w0 dw t_DH
	t_reg_110_w1 dw t_SI
	t_reg_111_w0 dw t_BH
	t_reg_111_w1 dw t_DI


; addresses to r/m
label rms word
	dw t_rm_000 ; 0
	dw t_rm_001 ; 1
	dw t_rm_010 ; 2
	dw t_rm_011 ; 3
	dw t_rm_100 ; 4
	dw t_rm_101 ; 5
	dw t_rm_110 ; 6
	dw t_rm_111 ; 7



; addresses to command names based on reg (in commands that containt sw)
label sw word
	dw t_ADD ;000 (0)
	dw t_OR  ;001 (1)
	dw t_ADC ;010 (2)
	dw t_SBB ;011 (3)
	dw t_AND ;100 (4)
	dw t_SUB ;101 (5)
	dw ?	 ;110 (6) t_XOR
	dw t_CMP ;111 (7)

; addresses to command names based on reg (in commands that have FF as OPK)
label ff word
	dw t_INC ;000 (0)
	dw t_DEC ;001 (1)
	dw t_CALL;010 (2)
	dw t_CALL;011 (3)
	dw t_JMP ;100 (4)
	dw t_JMP ;101 (5)
	dw t_PUSH ;110 (6)


;========================================================
;CONSTANTS FOR FORMATS
f_aByte_YES EQU 1
f_aByte_NO EQU 0

f_w_bit_0 EQU 0
f_w_bit_1 EQU 1
f_w_bit_NO EQU 2


;FORMAT TABLE:
f_unknown EQU 0 ; unknown command
f_prefix EQU 1
f_1 EQU 2 ; XXXX wreg  bet.op [bet.op] (MOV reg<-bet.op)
f_2 EQU 3 ; XXXX XXdw mod reg r/m [posl] (MOV reg<->r/m, ADD, SUB, CMP)
f_3 EQU 4 ; XXXX XXXw mod 000 r/m [posl] bojb [bovb] (MOV r/m<-bet.op)
f_4 EQU 5 ; XXXX XXXw bojb [bovb] (ADD akumuliatorius<-bet.op, SUB, CMP)
f_5 EQU 6 ; 1010 00xw ajb avb (MOV akumuliatorius<->mem) (x bit specifies direction)
f_6 EQU 7 ; 1000 11d0 mod 0sr r/m [posl] (MOV seg reg<->r/m)
f_7 EQU 8 ; 1000 00sw mod XXX r/m [posl] bojb [bovb] (ADD r/m<-bet.op, SUB, CMP)
f_8 EQU 9 ; XXXs rXXX (PUSH sreg, POP)
f_9 EQU 10 ; XXXX Xreg (PUSH wreg, POP, INC, DEC)
f_10 EQU 11 ; XXXX XXXX mod XXX r/m [posl] (POP r/m, PUSH, CALL(abu netiesioginiai), JMP(abu netiesioginiai), INC, DEC )
f_11 EQU 12 ; XXXX XXXw mod XXX r/m [posl] (MUL r/m, DIV)
f_12 EQU 13 ; XXXX XXXX poslinkis (All conditional jumps, JMP(vidinis artimas), LOOP)
f_13 EQU 14 ; XXXX XXXX posl.jb posl.vb (JMP(vidinis tiesioginis), CALL)
f_14 EQU 15 ; XXXX XXXX bojb bovb (RET (su stacko islyginimu), RETF)
f_15 EQU 16 ; XXXX XXXX ((vieno baito komanda), RET, RETF, NOP)
f_16 EQU 17 ; XXXX XXXX number (INT)
f_17 EQU 18 ; XXXX XXXX ajb avb srjb srvb (far JMP, CALL)



;FORMATS
FORMAT struc
	f_t_opName dw ? ;address to OPK name
	f_aByte db 0 ; is address byte present?
	f_w_bit db 0 ; w bit (if there is one)
	f_format_nr db 0 ; format number
ENDS

label formats FORMAT
	FORMAT<t_ADD, f_aByte_YES, f_w_bit_0, f_2> ; 0x0 (ADD reg<->r/m)
	FORMAT<t_ADD, f_aByte_YES, f_w_bit_1, f_2> ; 0x1
	FORMAT<t_ADD, f_aByte_YES, f_w_bit_0, f_2> ; 0x2
	FORMAT<t_ADD, f_aByte_YES, f_w_bit_1, f_2> ; 0x3
	FORMAT<t_ADD, f_aByte_NO, f_w_bit_0, f_4> ; 0x4 (ADD akum<-bet.op)
	FORMAT<t_ADD, f_aByte_NO, f_w_bit_1, f_4> ; 0x5
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_NO, f_8> ; 0x6 (PUSH sreg)
	FORMAT<t_POP, f_aByte_NO, f_w_bit_NO, f_8> ; 0x7 (POP sreg)
	FORMAT<t_OR, f_aByte_YES, f_w_bit_0, f_2> ; 0x8 (OR reg<->r/m)
	FORMAT<t_OR, f_aByte_YES, f_w_bit_1, f_2> ; 0x9
	FORMAT<t_OR, f_aByte_YES, f_w_bit_0, f_2> ; 0xa
	FORMAT<t_OR, f_aByte_YES, f_w_bit_1, f_2> ; 0xb
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_NO, f_8> ; 0xe (PUSH sreg)
	FORMAT<t_POP, f_aByte_NO, f_w_bit_NO, f_8> ; 0xf (POP sreg)
	FORMAT<t_ADC, f_aByte_YES, f_w_bit_0, f_2> ; 0x10 (ADC reg<->r/m)
	FORMAT<t_ADC, f_aByte_YES, f_w_bit_1, f_2> ; 0x11
	FORMAT<t_ADC, f_aByte_YES, f_w_bit_0, f_2> ; 0x12
	FORMAT<t_ADC, f_aByte_YES, f_w_bit_1, f_2> ; 0x13
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x14
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x15
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_NO, f_8> ; 0x16 (PUSH sreg)
	FORMAT<t_POP, f_aByte_NO, f_w_bit_NO, f_8> ; 0x17 (POP sreg)
	FORMAT<t_SBB, f_aByte_NO, f_w_bit_0, f_2> ; 0x18 (SBB reg<->r/m)
	FORMAT<t_SBB, f_aByte_NO, f_w_bit_1, f_2> ; 0x19
	FORMAT<t_SBB, f_aByte_NO, f_w_bit_0, f_2> ; 0x1a
	FORMAT<t_SBB, f_aByte_NO, f_w_bit_1, f_2> ; 0x1b
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x1c
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x1d
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_NO, f_8> ; 0x1e (PUSH sreg)
	FORMAT<t_POP, f_aByte_NO, f_w_bit_NO, f_8> ; 0x1f (POP sreg)
	FORMAT<t_AND, f_aByte_YES, f_w_bit_0, f_2> ; 0x20 (AND reg<->r/m)
	FORMAT<t_AND, f_aByte_YES, f_w_bit_1, f_2> ; 0x21
	FORMAT<t_AND, f_aByte_YES, f_w_bit_0, f_2> ; 0x22
	FORMAT<t_AND, f_aByte_YES, f_w_bit_1, f_2> ; 0x23
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x24
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x25
	FORMAT<t_ES, f_aByte_NO, f_w_bit_NO, f_prefix> ; 0x26 (ES prefix)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x27
	FORMAT<t_SUB, f_aByte_YES, f_w_bit_0, f_2> ; 0x28 (SUB reg<->r/m)
	FORMAT<t_SUB, f_aByte_YES, f_w_bit_1, f_2> ; 0x29
	FORMAT<t_SUB, f_aByte_YES, f_w_bit_0, f_2> ; 0x2a
	FORMAT<t_SUB, f_aByte_YES, f_w_bit_1, f_2> ; 0x2b
	FORMAT<t_SUB, f_aByte_NO, f_w_bit_0, f_4> ; 0x2c (SUB akum<-bet.op)
	FORMAT<t_SUB, f_aByte_NO, f_w_bit_1, f_4> ; 0x2d
	FORMAT<t_CS, f_aByte_NO, f_w_bit_NO, f_prefix> ; 0x2e (CS prefix)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x2f
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x30
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x31
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x32
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x33
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x34
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x35
	FORMAT<t_SS, f_aByte_NO, f_w_bit_NO, f_prefix> ; 0x36 (SS prefix)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x37
	FORMAT<t_CMP, f_aByte_YES, f_w_bit_0, f_2> ; 0x38 (CMP reg<->r/m)
	FORMAT<t_CMP, f_aByte_YES, f_w_bit_1, f_2> ; 0x39
	FORMAT<t_CMP, f_aByte_YES, f_w_bit_0, f_2> ; 0x3a
	FORMAT<t_CMP, f_aByte_YES, f_w_bit_1, f_2> ; 0x3b
	FORMAT<t_CMP, f_aByte_NO, f_w_bit_0, f_4> ; 0x3c (CMP akum<-bet.op)
	FORMAT<t_CMP, f_aByte_NO, f_w_bit_1, f_4> ; 0x3d
	FORMAT<t_DS, f_aByte_NO, f_w_bit_NO, f_prefix> ; 0x3e (DS prefix)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x3f
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x40 (INC wreg)
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x41
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x42
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x43
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x44
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x45
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x46
	FORMAT<t_INC, f_aByte_NO, f_w_bit_1, f_9> ; 0x47
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x48 (DEC wreg)
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x49
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4a
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4b
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4c
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4d
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4e
	FORMAT<t_DEC, f_aByte_NO, f_w_bit_1, f_9> ; 0x4f
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x50 (PUSH wreg)
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x51
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x52
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x53
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x54
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x55
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x56
	FORMAT<t_PUSH, f_aByte_NO, f_w_bit_1, f_9> ; 0x57
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x58 (POP wreg)
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x59
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5a
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5b
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5c
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5d
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5e
	FORMAT<t_POP, f_aByte_NO, f_w_bit_1, f_9> ; 0x5f
	; NOTE: command doesn't actually have w bit
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x60
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x61
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x62
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x63
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x64
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x65
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x66
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x67
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x68
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x69
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6a
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6b
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6c
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6d
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6e
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x6f
	FORMAT<t_JO, f_aByte_NO, f_w_bit_0, f_12> ; 0x70 (Salyginiai JMP)
	FORMAT<t_JNO, f_aByte_NO, f_w_bit_0, f_12> ; 0x71
	FORMAT<t_JNAE, f_aByte_NO, f_w_bit_0, f_12> ; 0x72
	FORMAT<t_JAE, f_aByte_NO, f_w_bit_0, f_12> ; 0x73
	FORMAT<t_JZ, f_aByte_NO, f_w_bit_0, f_12> ; 0x74
	FORMAT<t_JNZ, f_aByte_NO, f_w_bit_0, f_12> ; 0x75
	FORMAT<t_JNA, f_aByte_NO, f_w_bit_0, f_12> ; 0x76
	FORMAT<t_JA, f_aByte_NO, f_w_bit_0, f_12> ; 0x77
	FORMAT<t_JS, f_aByte_NO, f_w_bit_0, f_12> ; 0x78
	FORMAT<t_JNS, f_aByte_NO, f_w_bit_0, f_12> ; 0x79
	FORMAT<t_JP, f_aByte_NO, f_w_bit_0, f_12> ; 0x7a
	FORMAT<t_JNP, f_aByte_NO, f_w_bit_0, f_12> ; 0x7b
	FORMAT<t_JNGE, f_aByte_NO, f_w_bit_0, f_12> ; 0x7c
	FORMAT<t_JGE, f_aByte_NO, f_w_bit_0, f_12> ; 0x7d
	FORMAT<t_JNG, f_aByte_NO, f_w_bit_0, f_12> ; 0x7e
	FORMAT<t_JG, f_aByte_NO, f_w_bit_0, f_12> ; 0x7f ---
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_0, f_7> ; 0x80 (FORMAT 7)
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_1, f_7> ; 0x81
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_0, f_7> ; 0x82
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_1, f_7> ; 0x83
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x84
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x85
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x86
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x87
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_0, f_2> ; 0x88
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_1, f_2> ; 0x89 (MOV reg<->r/m)
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_0, f_2> ; 0x8a
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_1, f_2> ; 0x8b 
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_1, f_6> ; 0x8c (MOV seg reg<->r/m) 
	;Note: this format doesn't have 'w_bit', but we set it because we will always have word size regs
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x8d
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_1, f_6> ; 0x8e (MOV seg reg<->r/m)
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_1, f_10> ; 0x8f (POP mem)
	FORMAT<t_NOP, f_aByte_NO, f_w_bit_NO, f_15> ; 0x90 (NOP)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x91
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x92
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x93
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x94
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x95
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x96
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x97
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x98
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x99
	FORMAT<t_CALL, f_aByte_NO, f_w_bit_1, f_17> ; 0x9a (far CALL)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x9b
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x9c
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x9d
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x9e
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0x9f
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_5> ; 0xa0 (MOV akum<-mem)
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_5> ; 0xa1
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_5> ; 0xa2 (MOV mem<-akum)
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_5> ; 0xa3
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa4
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa5
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa6
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa7
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa8
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xa9
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xaa
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xab
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xac
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xad
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xae
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xaf
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb0
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb1
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb2
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb3
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb4
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb5
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb6
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_0, f_1> ; 0xb7
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xb8 (MOV reg<-bet.op, w=1, reg=000)
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xb9
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xba
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xbb
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xbc
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xbd
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xbe
	FORMAT<t_MOV, f_aByte_NO, f_w_bit_1, f_1> ; 0xbf
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc0
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc1
	FORMAT<t_RET, f_aByte_NO, f_w_bit_1, f_14> ; 0xc2 (RET su stack islyg)
	FORMAT<t_RET, f_aByte_NO, f_w_bit_NO, f_15> ; 0xc3 (RET)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc4
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc5
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_0, f_3> ; 0xc6 (MOV r/m<-bet op.)
	FORMAT<t_MOV, f_aByte_YES, f_w_bit_1, f_3> ; 0xc7
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc8
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xc9
	FORMAT<t_RETF, f_aByte_NO, f_w_bit_1, f_14> ; 0xca (RETF su stack islyg)
	FORMAT<t_RETF, f_aByte_NO, f_w_bit_NO, f_15> ; 0xcb (RETF)
	FORMAT<t_INT3, f_aByte_NO, f_w_bit_NO, f_15> ; 0xcc (INT 3)
	FORMAT<t_INT, f_aByte_NO, f_w_bit_0, f_16> ; 0xcd (INT number)
	FORMAT<t_INTO, f_aByte_NO, f_w_bit_NO, f_15> ; 0xce (INTO)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xcf
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd0
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd1
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd2
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd3
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd4
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd5
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd6
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd7
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd8
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xd9
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xda
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xdb
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xdc
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xdd
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xde
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xdf
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe0
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe1
	FORMAT<t_LOOP, f_aByte_NO, f_w_bit_0, f_12> ; 0xe2 (LOOP)
	FORMAT<t_JCXZ, f_aByte_NO, f_w_bit_0, f_12> ; 0xe3 (JCXZ)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe4
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe5
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe6
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xe7
	FORMAT<t_CALL, f_aByte_NO, f_w_bit_1, f_13> ; 0xe8 (CALL vidinis tiesiogins)
	FORMAT<t_JMP, f_aByte_NO, f_w_bit_1, f_13> ; 0xe9 (JMP vidinis tiesioginis)
	FORMAT<t_JMP, f_aByte_NO, f_w_bit_1, f_17> ; 0xea (far JMP)
	FORMAT<t_JMP, f_aByte_NO, f_w_bit_0, f_12> ; 0xeb (JMP vidinis artimas)
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xec
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xed
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xee
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xef
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf0
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf1
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf2
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf3
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf4
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf5
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_0, f_11> ; 0xf6 (DIV r/m, MUL)
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_1, f_11> ; 0xf7
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf8
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xf9
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xfa
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xfb
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xfc
	FORMAT<t_NONE, f_aByte_NO, f_w_bit_NO, f_unknown> ; 0xfd
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_0, f_10> ; 0xfe (INC r/m, DEC)
	FORMAT<t_EXT, f_aByte_YES, f_w_bit_1, f_10> ; 0xff (FF: INC, DEC, CALL, JMP, POP)