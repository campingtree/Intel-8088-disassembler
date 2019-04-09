
.MODEL small

.STACK 100h

.DATA
	include core.inc

	;TABLES
	hex_base db "0123456789ABCDEF"

	; MESSAGES
	help_mess db "disass.exe file.exe output.asm", "$"
	args_mess db "Unknown arguments...", "$"
	overflow_mess db "One the the arguments is to long!", "$"
	error_mess db "Error occurred: ", "$"
	error_ip db "  [at CS:", "$"
	nl db 10
	tab db 9

	;FILES
	file1 FILE <0>
	file2 FILE <0>
	header1 HEADER <0>

	;BUFFERS
	read_buff db 30 dup(?)
	read_buff_index dw 0
	current_byte db ?
	opk_byte db 0
	temp_buff db ?

	debug_buff db 10 dup(?) ; temp buffer used for debugging


	;COMMAND VARS
	c_opName dw ?	; address to operation name
	c_aByte db 0	; does it need address byte
	c_format_nr db 0		; command type
	c_prefix dw 0	; address of prefix name if present

	c_mod db 0
	c_reg db 0
	c_t_reg dw 0	; address to 'c_reg' text representation
	c_rm db 0
	c_t_rm dw 0 	; address to 'c_rm' text representation
	c_op1 dw 0 		; operand 1
	c_op2 dw 0		; operand 2 (kartais raw, kartais adresas) (bad design!)
	c_pos dw 0
	c_pos_set db 0	; 1=set, 0=not

	c_w_bit db 0	
	c_d_bit db 0

	c_IP dw 0		; IP value (offset in CS)
	bytes_left dw ?	; number of bytes left to read in a segment



.CODE
	include other.inc ; magical macros and functions

S:
	MOV ax, @data
	MOV ds, ax
	MOV AH, 004Ch

	CALL check_help
	CALL get_args
	CALL open_files
	CALL parse_header

	; seek to start of Code segment
	MOV dx, [header1.cs_offset]
	CALL seek_set

	MOV cx, [header1.ds_offset]
	SUB cx, dx ; CX = cs size in bytes
	MOV [bytes_left], cx


MAIN_LOOP:
	CMP [bytes_left], 0
	LJLE end_job

	CALL print_ip_ascii
	print_symbol tab

	CALL clear_vars ; clear vars from last command
main2:

	CALL pull_format ; reads byte / gets the format
	CALL parse_format ; parses basic information from format struct

	; CHECK FOR PREFIX
	MOV al, c_format_nr
	CMP al, f_prefix
	JNE skip_prefix

save_prefix:
	MOV ax, c_opName
	MOV c_prefix, ax
	JMP main2

; CALL parse proc according to format 
skip_prefix:
	CMP [c_aByte], f_aByte_YES ; check if addr byte needs to be parsed
	CALLE parse_addr_byte

	MOV ax, [c_opName]
	CMP [__ext_opk], ax
	CALLNE print_name ; only call if we know command name from first byte
	
	; find FORMAT
	CMP [c_format_nr], f_unknown
	LJE continue; because there's nothing to parse here

	CMP [c_format_nr], f_1
	CALLE parse_f_1

	CMP [c_format_nr], f_2
	CALLE parse_f_2

	CMP [c_format_nr], f_3
	CALLE parse_f_3

	CMP [c_format_nr], f_4
	CALLE parse_f_4
	
	CMP [c_format_nr], f_5
	CALLE parse_f_5

	CMP [c_format_nr], f_6
	CALLE parse_f_6

	CMP [c_format_nr], f_7
	CALLE parse_f_7

	CMP [c_format_nr], f_8
	CALLE parse_f_8

	CMP [c_format_nr], f_9
	CALLE parse_f_9

	CMP [c_format_nr], f_10
	CALLE parse_f_10

	CMP [c_format_nr], f_11
	CALLE parse_f_11

	CMP [c_format_nr], f_12
	CALLE parse_f_12

	CMP [c_format_nr], f_13
	CALLE parse_f_13

	CMP [c_format_nr], f_14
	CALLE parse_f_14

	CMP [c_format_nr], f_15
	JE continue ; one byte command, nothing more to print

	CMP [c_format_nr], f_16
	CALLE parse_f_16

	CMP [c_format_nr], f_17
	CALLE parse_f_17

continue:
	print_symbol tab
	print_symbol tab
	CALL print_mach_code
	print_symbol nl
	MOV [c_prefix], 0 ; clear prefix
	JMP MAIN_LOOP

end_job:
	CALL close_files
.EXIT


; ====================F PARSE PROCEDURES====================
parse_f_1 PROC
	PUSHREGS <ax, bx, dx>

	MOV al, [opk_byte] ; move current command byte

	CALL parse_bet_op

	AND al, 111b
	MOV [c_reg], al

	CALL print_f_1
	POPREGS <dx, bx, ax>
	RET
parse_f_1 ENDP


parse_f_2 PROC
	
	CALL parse_d_bit
	CALL parse_by_mod ; parse required parts based on mod field
	
	CMP [c_d_bit], 0
	CALLE print_d0
	CMP [c_d_bit], 1
	CALLE print_d1


	RET
parse_f_2 ENDP

parse_f_3 PROC

	CALL parse_by_mod
	CALL parse_bet_op
	CALL print_regmem
	print_symbol ","
	print_symbol " "
	CALL print_bet_op

	RET
parse_f_3 ENDP

parse_f_4 PROC
	
	print_symbol " "
	CALL parse_accumulator
	print_reg ; print accumulator
	print_symbol ","
	print_symbol " "
	CALL parse_bet_op
	CALL print_bet_op

	RET
parse_f_4 ENDP

parse_f_5 PROC
	PUSH ax

	print_symbol " "
	CALL parse_accumulator

	MOV cx, 2
	CALL parse_posl

	MOV al, [opk_byte]
	SHR al, 1
	AND al, 01h
	CMP al, 1
	LJE __f5_x_1 ; print according to (mem<-akum)
	print_reg ; print accumulator
	print_symbol ","
	print_symbol " "
	MOV [c_d_bit], 1 ; so we print 'byte ptr' if needed
	CALL print_if_ptr
	print_if_prefix
	CMP [c_prefix], 0
	CALLE print_ds
	print_symbol "["
	CALL print_posl
	print_symbol "]"
	JMP __return_parse_f_5

__f5_x_1:
	CALL print_if_ptr
	print_if_prefix
	CMP [c_prefix], 0
	CALLE print_ds
	print_symbol "["
	CALL print_posl
	print_symbol "]"
	print_symbol ","
	print_symbol " "
	print_reg

__return_parse_f_5:
	POP ax
	RET
parse_f_5 ENDP

parse_f_6 PROC
	PUSHREGS <ax, bx>

	CALL parse_d_bit
	CALL parse_by_mod

	;overwrite 'c_t_reg' part with custom one for 0SR format
	MOV al, size sregs
	MOV bl, [c_reg]
	MUL bl

	MOV bx, offset sregs
	ADD bx, ax ; calculate address to string address
	MOV ax, [bx]
	MOV [c_t_reg], ax ; save new txt representation of 'reg' field (sreg)
	;

	MOV dx, [c_t_reg] ; prepare for c_t_reg printing
	MOV cx, 2 ; could just be 'strlen dx' (more consistent)

	CMP [c_d_bit], 0
	LJE parse_6_d0

	print_symbol " "
	CALL write_chunk ; print sreg
	print_symbol ","
	CALL print_regmem
	JMP parse_6_leave

parse_6_d0:
	CALL print_regmem
	print_symbol ","
	print_symbol " "
	MOV dx, [c_t_reg]
	MOV cx, 2
	CALL write_chunk ; print sreg

parse_6_leave:
	POPREGS <bx, ax>
	RET
parse_f_6 ENDP

parse_f_7 PROC
	
	; parse and print command name (based on 'reg' field)
	MOV bl, [c_reg]
	MOV al, size sw
	MUL bl
	MOV bx, offset sw
	ADD bx, ax
	MOV ax, [bx]
	MOV [c_opName], ax
	CALL print_name

	CALL parse_by_mod

	;check if sw=11
	MOV al, [opk_byte]
	AND al, 03h
	CMP al, 3
	JE __parse_7_sw11
	CALL parse_bet_op
	JMP __parse_7_print


__parse_7_sw11: ; parse only byte for bet.op despite w bit being = 1
	MOV ah, 0
	MOV al, [c_w_bit]
	PUSH ax
	MOV [c_w_bit], 0
	CALL parse_bet_op
	POP ax
	MOV [c_w_bit], al
	; print_symbol "!" ; (debugging) show where sw=11


__parse_7_print:
	CALL print_regmem
	print_symbol ","
	print_symbol " "
	CALL print_bet_op

	RET
parse_f_7 ENDP

parse_f_8 PROC

	;parse sr part
	MOV al, [opk_byte]
	SHR al, 3
	AND al, 03h
	MOV bl, size sregs
	MUL bl
	MOV bx, offset sregs
	ADD bx, ax
	MOV ax, [bx]
	MOV [c_t_reg], ax

	print_symbol " "
	MOV dx, [c_t_reg]
	strlen dx
	CALL write_chunk

	RET
parse_f_8 ENDP

parse_f_9 PROC
	
	; parse reg
	MOV al, [opk_byte]
	AND al, 07h
	MOV [c_reg], al
	print_symbol " "
	print_reg

	RET
parse_f_9 ENDP

parse_f_10 PROC

	CALL parse_by_mod
	
	CMP [opk_byte], 8Fh ; check if this is POP
	JE __parse_10_pop
	JMP __parse_10_ff

__parse_10_pop:
	MOV ax, offset t_POP
	MOV [c_opName], ax
	CALL print_name
	JMP __parse_10_print

__parse_10_ff:
	MOV al, [c_reg]
	MOV bl, size ff
	MUL bl
	MOV bx, offset ff
	ADD bx, ax
	MOV ax, [bx]
	MOV [c_opName], ax
	CALL print_name

__parse_10_print:
	MOV [c_d_bit], 1 ; so we print "byte ptr" if needed
	CALL print_regmem

	RET
parse_f_10 ENDP

; This PROC is written so it only parses 2 required commands from this format (DIV and MUL)!!!
; So reg parts (100, 110) are hardcoded
parse_f_11 PROC

	CALL parse_by_mod ; could be moved to each _div and _mul so we don't parse a cluster of bytes and still write "UNKNOWN"

	;find command name and print it
	CMP [c_reg], 4 ; reg=100
	JE __parse_11_mul
	CMP [c_reg], 6 ; reg=110
	JE __parse_11_div

	JMP __parse_11_unknown 

__parse_11_div:
	MOV [c_opName], offset t_DIV
	CALL print_name
	JMP __parse_11_print

__parse_11_mul:
	MOV [c_opName], offset t_MUL
	CALL print_name
	JMP __parse_11_print

__parse_11_unknown:
	MOV [c_opName], offset t_NONE
	CALL print_name
	JMP __parse_11_leave


__parse_11_print:
	MOV [c_d_bit], 1
	CALL print_regmem
__parse_11_leave:
	RET
parse_f_11 ENDP

parse_f_12 PROC

	CALL parse_bet_op ; read one byte (because w bit is set to "0")
	MOV ax, [c_IP]
	MOV dx, [c_op2]
	XCHG dh, dl ; because after 'parse_bet_op' bytes are switched

	; praplesti pagal zenkla (for correct address calculation)
	CMP dl, 0A0h
	JAE __parse_12_extend
	JMP __parse_12_print

__parse_12_extend:
	MOV dh, 0FFh

__parse_12_print:
	ADD ax, dx
	print_symbol " "
	MOV dx, offset t_CS
	MOV cx, 2
	CALL write_chunk
	print_symbol ":"
	print_symbol "["
	print_ascii ah
	print_ascii al
	print_symbol "h"
	print_symbol "]"

	RET
parse_f_12 ENDP

parse_f_13 PROC

	CALL parse_bet_op ; read 2 posl bytes
	MOV ax, [c_IP]
	MOV dx, [c_op2]
	XCHG dh, dl

	ADD ax, dx
	print_symbol " "
	MOV dx, offset t_CS
	MOV cx, 2
	CALL write_chunk
	print_symbol ":"
	print_symbol "["
	print_ascii ah
	print_ascii al
	print_symbol "h"
	print_symbol "]"

	RET
parse_f_13 ENDP

parse_f_14 PROC
	
	print_symbol " "
	CALL parse_bet_op
	CALL print_bet_op

	RET
parse_f_14	ENDP

parse_f_16 PROC

	CALL parse_bet_op
	print_symbol " "
	CALL print_bet_op

	RET
parse_f_16 ENDP

parse_f_17 PROC

	print_symbol " "
	
	MOV cx, 2
	CALL parse_posl
	MOV ax, [c_pos]
	PUSH ax

	MOV cx, 2
	CALL parse_posl
	MOV al, byte ptr [c_pos]
	print_ascii al
	MOV al, byte ptr [c_pos+1]
	print_ascii al

	print_symbol ":"
	POP ax
	print_ascii al
	print_ascii ah

	RET
parse_f_17 ENDP

; ====================F PRINT PROCEDURES (optional)====================
print_f_1 PROC
	
	print_symbol " "
	print_reg
	print_symbol ","
	print_symbol " "

	; Check if bet.op was @data
	MOV bx, [header1.data_numeric]
	XCHG bh, bl
	CMP bx, [c_op2]
	JE __print_data
	CALL print_bet_op
	JMP __returnPrint_f_1

__print_data:
	MOV dx, offset t_data
	strlen dx
	CALL write_chunk

__returnPrint_f_1:
	RET
print_f_1 ENDP

print_f_2 PROC
	RET
print_f_2 ENDP

; ==========================================================

; check for '/?' in args
check_help PROC
	PUSHREGS <ax, cx, dx, di>
	XOR cx, cx
	MOV cl, es:0080h
	CMP cl, 0
	JLE returnCheck_help

	MOV ax, " "
	MOV di, 0081h
	CLD ; DF=0
	REPE SCASB ; get rid of spaces
	JE returnCheck_help

	DEC di ; because DI will point one too many
	CMP byte ptr es:[di], "/" ; if first char after spaces is not /
	JNE returnCheck_help

	MOV ax, "?/"
	CMP cl, 0
	JLE returnCheck_help ; to fix 'antra.exe /'
	CLD
	REPNE SCASW ; repeat till ZF=0
	JNE returnCheck_help ; if ZF=0 still (cx=0 already)

print_help:
	MOV ah, 09h
	LEA dx, help_mess
	INT 21h
	.EXIT

returnCheck_help:
	POPREGS <di, dx, cx, ax>
	RET
check_help ENDP


; get both file names from args
get_args PROC
	PUSHREGS <ax, cx, dx, si, di>

	XOR cx, cx
	MOV cl, es:[0080h]
	CMP cl, 0
	JLE failGet_args

	; Space skipping (same as in check_help)
	MOV ax, " "
	MOV di, 0081h
	CLD
	REPE SCASB
	JE failGet_args

	DEC di
	MOV dx, di ; save current offset (start of first arg)
	CLD
	REPNE SCASB ; repeat until you find a space
	JNE failGet_args ; no space found (no second arg)
	;
	DEC di
	PUSHREGS <di, si, cx>
	MOV si, dx ; destination offset for DS
	SUB di, dx ; args last char offset - first char offset
	MOV cx, di ; number of bytes to copy
	CMP cl, 28 ; check for potential overflow (both names came be up to 14 bytes + byte for \0)
	JG overflowGet_args
	MOV di, offset file1.fname
	CALL swap_es_ds ; change ES and DS for copying  (because of oposite dirrections ES->DS)
	REP MOVSB
	CALL swap_es_ds
	POPREGS <cx, si, di>
	;
	INC di ; make it point to start of second arg
	INC cl ; so if only one byte is left to copy, we don't fail
	MOV si, di
	MOV di, offset file2.fname
	CMP cl, 14 ; check for potential overflow 
	JG overflowGet_args
	CALL swap_es_ds
	REP MOVSB
	CALL swap_es_ds
	JMP returnGet_args

failGet_args:
	MOV ah, 09h
	LEA dx, args_mess
	INT 21h
	.EXIT

overflowGet_args:
	MOV ah, 09h
	LEA dx, overflow_mess
	INT 21h
	.EXIT

returnGet_args:
	POPREGS <di, si, dx, cx, ax>
	RET
get_args ENDP


open_files PROC
	PUSHREGS <ax, dx>
	
	; open file1 (.exe)
	MOV ah, 3Dh
	MOV al, 0 ; read mode
	LEA dx, file1.fname
	INT 21h
	JC failOpen_files
	MOV [file1.fhandle], ax ; save file handle

	; open file2 (.asm)
	MOV ah, 3ch
	MOV cx, 0 ; normal attribute
	LEA dx, file2.fname
	INT 21h
	JC failOpen_files
	MOV [file2.fhandle], ax

	POPREGS <dx, ax>
	RET

failOpen_files:
	CALL error
open_files ENDP


error PROC
	;print 'error_mess' first
	PUSH ax
	MOV ah, 09h
	LEA dx, error_mess
	INT 21h
	POP ax

	;print errno
	PUSH ax
	MOV dl, ah
	ADD dl, 30h
	MOV ah, 02h
	INT 21h
	POP ax
	MOV ah, 02h
	MOV dl, al
	ADD dl, 30h
	INT 21h


	; print 'error_ip'
	MOV ah, 09h
	LEA dx, error_ip
	INT 21h

	POP bx ; get IP
	SUB bx, 3 ; because (vidinis tiesioginis CALL) takes up 3 bytes, so during CALL, IP points 3 bytes further from actual command
	PUSH bx

	; first byte (left most one)
	SHR bx, 8
	PUSH bx
	SHR bl, 4
	PRTNIB bl

	POP bx
	SHL bl, 4
	SHR bl, 4
	PRTNIB bl

	; second byte (right most one)
	POP bx
	MOV bh, 0
	PUSH bx
	SHR bl, 4
	PRTNIB bl

	POP bx
	SHL bl, 4
	SHR bl, 4
	PRTNIB bl

	; print ']'
	MOV ah, 02h
	MOV dl, "]"
	INT 21h

	.EXIT
error ENDP


close_files PROC
	
	; close file1
	MOV ah, 3Eh
	MOV bx, [file1.fhandle]
	INT 21h
	JC failClose_files

	; close file2
	MOV ah, 3Eh
	MOV bx, [file2.fhandle]
	INT 21h
	JC failClose_files

	RET

failClose_files:
	CALL error
close_files ENDP


parse_header PROC

	; Get header size in paragraphs
	MOV dx, 8h
	CALL seek_set

	MOV ah, 3Fh
	MOV bx, [file1.fhandle]
	MOV cx, 2 ; 2 bytes to read (header size is 1 word)
	LEA dx, read_buff
	INT 21h
	JC failParse_header


	; Calculate CS offset based on header size
	MOV ax, word ptr [read_buff]
	XOR dx, dx
	MOV cx, 16 ; because paragraph size is 16 bytes (10h)
	MUL cx ; AX=header size in bytes
	MOV [header1.cs_offset], ax


	;; Find DS offset
	; SEEK to relocation table offset
	MOV dx, 18h ;
	CALL seek_set 

	; read relocation table offset word
	MOV ah, 3Fh
	MOV bx, [file1.fhandle]
	MOV cx, 2
	LEA dx, read_buff
	INT 21h
	JC failParse_header

	; SEEK to relocation table
	MOV dx, word ptr [read_buff] ; where to SEEK to
	CALL seek_set

	; read OFFSET:SEGMENT
	MOV ah, 3Fh
	MOV bx, [file1.fhandle]
	MOV cx, 4 ; because both offset and segment are words
	LEA dx, read_buff
	INT 21h  ; in 'read_buff', first two bytes=OFFSET, second two bytes=SEGMENT
	JC failParse_header


	; SEGMENT*16+OFFSET
	MOV ax, word ptr [read_buff+2] ; SEGMENT value
	XOR dx, dx
	MOV cx, 16
	MUL cx
	MOV bx, word ptr [read_buff] ; OFFSET value
	ADD ax, bx

	;cs_offset + ax = @data numeric value
	ADD ax, [header1.cs_offset] ; AX=@data offset from CS
	; based on this offset, get numeric value of @data
	MOV dx, ax ; offset
	CALL seek_set 

	; read @data numeric value and save it
	MOV ah, 3Fh
	MOV bx, [file1.fhandle]
	MOV cx, 2
	LEA dx, read_buff
	INT 21h
	JC failParse_header
	MOV ax, word ptr [read_buff]
	MOV [header1.data_numeric], ax ; save @data

	; @data*16+cs_offset = ds_offset
	XOR dx, dx
	MOV cx, 16
	MUL cx
	ADD ax, [header1.cs_offset]
	MOV [header1.ds_offset], ax ; AX=ds_offset


	RET

failParse_header:
	CALL error
parse_header ENDP


;RETURN:
;al = byte read
read_byte PROC
	PUSHREGS <bx, cx, dx>

	MOV ah, 3Fh
	MOV bx, [file1.fhandle]
	MOV cx, 1
	LEA dx, current_byte
	INT 21h
	JC failRead_byte

	MOV al, byte ptr [current_byte]
	MOV bx, [read_buff_index]
	MOV [read_buff+bx], al
	INC [read_buff_index] ; move to next byte in buffer

	INC [c_IP]
	DEC [bytes_left]

	POPREGS <dx, cx, bx>
	RET
failRead_byte:
	CALL error
read_byte ENDP


;RETURN:
;BX = format address
pull_format PROC
	PUSHREGS <ax, dx>

	CALL read_byte

	MOV al, [current_byte]
	MOV [opk_byte], al

	MOV dl, size FORMAT
	MUL dl
	MOV bx, offset formats
	ADD bx, ax ; find the FORMAT struct needed (address)

	POPREGS <dx, ax>
	RET
pull_format ENDP


;REQUIREMENTS:
;BX = address to FORMAT struct
parse_format PROC
	PUSH AX

	MOV ax, [bx].f_t_opName
	MOV [c_opName], ax

	MOV al, [bx].f_aByte
	MOV [c_aByte], al

	MOV al, [bx].f_w_bit
	MOV [c_w_bit], al

	MOV al, [bx].f_format_nr
	MOV [c_format_nr], al

	POP ax
	RET
parse_format ENDP


;Parse betarpiskas operandas
;REQUIREMENTS:
;c_w_bit has to be set
;! we store them in reverse order because of how memory layout in this arch works
parse_bet_op PROC
	PUSH ax

	CMP [c_w_bit], f_w_bit_NO
	LJE leaveParse_bet_op

	CMP c_w_bit, 0
	JA __get_two
	CALL read_byte
	MOV byte ptr [c_op2], 0
	MOV byte ptr [c_op2+1], al
	JMP leaveParse_bet_op

__get_two:
	CALL read_byte
	MOV byte ptr [c_op2+1], al
	CALL read_byte
	MOV byte ptr [c_op2], al

leaveParse_bet_op:
	POP ax
	RET
parse_bet_op ENDP


;Print betarpiskas operandas using 'print_ascii' macro
print_bet_op PROC
	
	CMP byte ptr [c_op2], 0
	JNE __print_bet_op_both	
; print 1 byte
	CMP byte ptr [c_op2+1], 0A0h
	JAE __print_bet_op_extrazero_1
__print_bet_op_single_continue:
	MOV bl, byte ptr [c_op2+1]
	print_ascii bl
	JMP __print_bet_op_leave

	__print_bet_op_extrazero_1:
		print_symbol "0"
		JMP __print_bet_op_single_continue


; print 2 bytes 
__print_bet_op_both:
	CMP byte ptr [c_op2], 0A0h
	JAE __print_bet_op_extrazero_2
__print_bet_op_both_continue:
	MOV bl, byte ptr [c_op2]
	print_ascii bl
	MOV bl, byte ptr [c_op2+1]
	print_ascii bl
	JMP __print_bet_op_leave

	; print extra zero (e.g 0FFFFh)
	__print_bet_op_extrazero_2:
		print_symbol "0"
		JMP __print_bet_op_both_continue

__print_bet_op_leave:
	print_symbol "h"
	RET
print_bet_op ENDP


;Print command name
;REQUIREMENTS:
;c_opName has to be set
print_name PROC
	PUSHREGS <ax, cx, dx, si>

	;Find name length
	strlen c_opName
	MOV dx, [c_opName]

	CALL write_chunk

	POPREGS <si, dx, cx, ax>
	RET
print_name ENDP


print_ip_ascii PROC
	PUSHREGS <si, ax, bx, cx, dx>

	MOV ax, [c_IP]
	print_ascii ah
	print_ascii al

	MOV [temp_buff], ":"
	LEA dx, temp_buff
	MOV cx, 1
	CALL write_chunk

	POPREGS <dx, cx, bx, ax, si>
	RET
print_ip_ascii ENDP


;Get address to ASCII representation of 'c_reg'
;RETURNS:
;'c_t_reg' = address to txt representation
get_t_reg PROC
	PUSHREGS <ax, bx, dx>

	XOR ax, ax
	XOR bx, bx
	MOV al, size regs ;2
	ADD al, 2 ; because need to jump over 2x2 bytes
	MOV bl, [c_reg]
	MUL bl

	MOV bx, offset regs
	ADD bx, ax

	;add +2 if c_w_bit=1
	MOV ah, 0
	MOV al, [c_w_bit]
	MOV dl, 2
	MUL dl
	ADD bx, ax ; BX = address to dw holding address to textual representation

	MOV ax, [bx]
	MOV [c_t_reg], ax

	POPREGS <dx, bx, ax>
	RET
get_t_reg ENDP


;Clear command vars
clear_vars PROC
	MOV [c_opName], 0
	MOV [c_aByte], 0
	MOV [c_format_nr], 0
	; dont clear prefix
	MOV [c_mod], 0
	MOV [c_reg], 0
	MOV [c_t_reg], 0
	MOV [c_rm], 0
	MOV [c_t_rm], 0
	MOV [c_op1], 0
	MOV [c_op2], 0
	MOV [c_pos], 0
	MOV [c_pos_set], 0
	MOV [c_w_bit], 0
	MOV [c_d_bit], 0

	MOV [read_buff_index], 0 ; reset index 

	RET
clear_vars ENDP


;Print machine code according to 'read_buff_index'
;REQUIREMENTS:
;'read_buff' has to contain machine code
;'read_buff_index' has to know command length
print_mach_code PROC
	PUSHREGS <ax, bx, cx>

	MOV cx, [read_buff_index] ; how much to write
	MOV bx, offset read_buff ; where to write from
__print_mach:
	MOV al, [bx]
	print_ascii al
	INC bx ; make dx point to next byte
	LOOP __print_mach

	POPREGS <cx, bx, ax>
	RET
print_mach_code ENDP


; Parse address byte
;REQUIREMENTS:
;[c_aByte] = f_aByte_YES 
parse_addr_byte PROC
	PUSHREGS <ax>
	
	CALL read_byte ; read address byte (al=address byte on return)
	PUSHREGS <ax, ax> ; save untouched address byte for other parses

	; parse mod
	SHR al, 6
	MOV [c_mod], al

	; parse reg
	POP ax
	SHR al, 3
	AND al, 07h
	MOV [c_reg], al

	; parse r/m
	POP ax
	AND al, 07h
	MOV [c_rm], al

	POPREGS <ax>
	RET
parse_addr_byte ENDP

parse_d_bit PROC
	PUSH ax

	MOV al, [opk_byte]
	SHR al, 1
	AND al, 01h
	MOV [c_d_bit], al

	POP ax
	RET
parse_d_bit ENDP


;Get textual representation of r/m
;RETURNS:
;[c_t_rm] = txt representation of r/m field
get_t_rm PROC
	PUSHREGS <ax, bx, dx>

	XOR ax, ax
	MOV al, [c_rm]
	MOV dl, size rms
	MUL dl
	MOV bx, offset rms
	ADD bx, ax ; bx points where we need
	MOV ax, [bx]
	MOV [c_t_rm], ax

	POPREGS <dx, bx, ax>
	RET
get_t_rm ENDP


;REQUIREMENTS:
;CX = number of bytes to parse for poslinkis
parse_posl PROC
	PUSH ax

	CMP cx, 1
	JA __get_two_posl
	CALL read_byte
	MOV byte ptr [c_pos], 0
	MOV byte ptr [c_pos+1], al
	JMP leaveParse_posl

__get_two_posl:
	CALL read_byte
	MOV byte ptr [c_pos+1], al
	CALL read_byte
	MOV byte ptr [c_pos], al

leaveParse_posl:
	MOV [c_pos_set], 1
	POP ax
	RET
parse_posl ENDP

print_posl PROC
	PUSH bx
	
	MOV bl, byte ptr [c_pos]
	print_ascii bl
	MOV bl, byte ptr [c_pos+1]
	print_ascii bl

	print_symbol "h"

	POP bx
	RET
print_posl ENDP


;Print '+' if r/m and posl are both present
print_plus_if_both PROC
	PUSH si

	MOV si, 0
	CMP [c_t_rm], 0
	JE __plus_2
	INC si

__plus_2:
	CMP [c_pos_set], 0
	JE __plus_3
	INC si

__plus_3:
	CMP si, 2
	JE __plus_print
	JMP leavePrint_plus

__plus_print:
	print_symbol "+"

leavePrint_plus:
	POP si
	RET
print_plus_if_both ENDP


;Print command with address byte according to d=1 (reg <- r/m)
print_d1 PROC

	print_symbol " "
	print_reg
	print_symbol ","

	CALL print_regmem

	RET
ENDP

;Print according to d=0 (r/m <- reg)
print_d0 PROC

	CALL print_regmem

	print_symbol ","
	print_symbol " "
	print_reg

	RET
ENDP

; Accordingly print r/m field (with pointer directives, posl, etc...)
print_regmem PROC

	print_symbol " "
	CALL print_if_ptr
	print_if_prefix
	CMP [c_prefix], 0
	CALLE print_ds
	print_if_lb
	print_if_rm
	CALL print_plus_if_both
	print_if_posl
	print_if_rb

	RET
print_regmem ENDP


; God help you, that who shall insist on reading what's bellow
;Parse appropriate '_t' fields based on mod
parse_by_mod PROC
	PUSHREGS <ax, cx>

	CMP [c_mod], 0
	LJE __f2_mod00
	CMP [c_mod], 1
	LJE __f2_mod01
	CMP [c_mod], 2
	LJE __f2_mod10
	CMP [c_mod], 3
	LJE __f2_mod11


__f2_mod00:
	CMP [c_rm], 6
	LJE __f2_rm110

	CALL get_t_reg
	CALL get_t_rm
	JMP __f2_leave

	__f2_rm110:
		MOV cx, 2
		CALL parse_posl
		CALL get_t_reg
		JMP __f2_leave


__f2_mod01:
	MOV cx, 1
	CALL parse_posl
	CALL get_t_reg
	CALL get_t_rm
	JMP __f2_leave

__f2_mod10:
	MOV cx, 2
	CALL parse_posl
	CALL get_t_reg
	CALL get_t_rm
	JMP __f2_leave

__f2_mod11:
	; get c_t_reg, then use get_t_reg PROC to get one for c_t_rm
	CALL get_t_reg
	PUSH [c_t_reg]
	MOV ah, 0
	MOV al, [c_reg]
	PUSH ax ; preserve, so we can reset it

	MOV al, [c_rm]
	MOV [c_reg], al
	CALL get_t_reg
	MOV ax, [c_t_reg]
	MOV [c_t_rm], ax
	POP ax
	MOV [c_reg], al
	POP [c_t_reg]

__f2_leave:
	POPREGS <cx, ax>
	RET
parse_by_mod ENDP


;Put either AL or AX to 'c_t_reg' according to 'w' bit
parse_accumulator PROC
	PUSH ax

	CMP [c_w_bit], 0
	JE __parse_al
	MOV ax, offset t_AX
	MOV [c_t_reg], ax
	JMP __parse_accum_leave

__parse_al:
	MOV ax, offset t_AL
	MOV [c_t_reg], ax

__parse_accum_leave:
	POP ax
	RET
parse_accumulator ENDP

;Simply prints "ds:"
;Used for FORMAT 5 (MOV akum<->mem) because when using bytes, not variable name, compiler needs to know the segment
print_ds PROC

	CMP [c_t_rm], 0
	JNE __print_ds_leave ; if 'c_t_rm', no need to print 'ds:'

	MOV dx, offset t_DS
	MOV cx, 2
	CALL write_chunk
	print_symbol ":"

__print_ds_leave:
	RET
print_ds ENDP

END S