PUSHREGS MACRO regs
	IRP var, <regs>
		PUSH var
	ENDM
ENDM


POPREGS MACRO regs
	IRP var, <regs>
		POP var
	ENDM
ENDM


swap_es_ds PROC ; SWAP ES and DS regs
	PUSHREGS <ax, bx>
	MOV ax, ds
	MOV bx, es
	MOV ds, bx
	MOV es, ax
	POPREGS <bx, ax>
	RET
swap_es_ds ENDP


MOVSREG MACRO sreg, reg ;; MOV sreg, any_word_reg
	PUSH ax
	MOV ax, reg
	MOV sreg, ax
	POP ax
ENDM


PRTNIB MACRO breg ;; print lower nibble of byte sized reg (not for standalone use)
	local @@number, @@exit
	PUSHREGS <ax, dx>
	MOV ah, 02h
	CMP breg, 09h
	JLE @@number
	MOV dl, breg
	ADD dl, 37h
	INT 21h
	JMP @@exit

@@number:
	MOV dl, breg
	ADD dl, 30h
	INT 21h
@@exit:
	POPREGS <dx, ax>
ENDM


;Requirements:
;[file1.fhandle] has to contain .exe file handle
;DX=offset from SEEK_SET 
seek_set PROC
	PUSHREGS <ax, bx, cx, dx>

	MOV ah, 42h
	MOV al, 0 ; seek_set
	MOV bx, [file1.fhandle]
	XOR cx, cx
	INT 21h
	JC failSeek_set

	POPREGS <dx, cx, bx, ax>
	RET
failSeek_set:
	CALL error
seek_set ENDP


; Call equal
CALLE MACRO procedure
	local jump, leave
	JE jump
	JMP leave
jump:
	CALL procedure
leave:
ENDM

; Call not equal
CALLNE MACRO procedure
	local jump, leave
	JNE jump
	JMP leave
jump:
	CALL procedure
leave:
ENDM

; long JLE
LJLE MACRO dest
	local jump, leave
	JLE jump
	JMP leave
jump:
	JMP dest
leave:
ENDM

; long JE
LJE MACRO dest
	local jump, leave
	JE jump
	JMP leave
jump:
	JMP dest
leave:
ENDM

;Write chunk to file2
;REQUIREMENTS:
;CX=number of bytes to write
;DX=address from where to write
write_chunk PROC
	PUSHREGS <ax, bx>

	MOV ah, 40h
	MOV bx, [file2.fhandle]
	INT 21h

	POPREGS <bx, ax>
	RET
failWrite_chunk:
	CALL error
write_chunk ENDP


;string has to be ASCII-Z
;RETURNS:
;CX = length
strlen MACRO addr
	local find_zero
	PUSHREGS <si, ax>
	MOV si, addr
	MOV cx, si
find_zero:
	LODSB
	CMP al, 0
	JNE find_zero

	DEC si ;; because SI will point one too many
	SUB si, cx
	MOV cx, si

	POPREGS <ax, si>
ENDM


; Print hex byte in ascii
print_ascii MACRO pbyte
	PUSHREGS <si, bx, cx, dx>

	MOV si, offset hex_base
	MOV bh, 0 
	MOV bl, pbyte
	MOV cx, 1
	PUSH bx

	SHR bl, 4
	ADD bx, si
	MOV dx, bx
	CALL write_chunk

	POP bx
	AND bl, 0Fh
	ADD bx, si
	MOV dx, bx
	CALL write_chunk

	POPREGS <dx, cx, bx, si>
ENDM


; Moves sym to 'temp_buf' and then print's it from there
; sym can be both raw value and byte register
print_symbol MACRO sym
	PUSHREGS <cx, dx>
	MOV cl, sym
	MOV [temp_buff], cl
	MOV cx, 1
	LEA dx, temp_buff
	CALL write_chunk
	POPREGS <dx, cx>
ENDM


; Wrapper macro to print reg
;REQUIREMENTS:
;'c_reg' has to be set (via CALL to parse_addr_byte)
print_reg MACRO
	CALL get_t_reg ;;get txt representation
	MOV dx, [c_t_reg]
	MOV cx, 2 ; can be replaced with "strlen dx"
	CALL write_chunk
ENDM


; NOT USED RIGHT NOW
; Wrapper macro to print r/m
print_t_rm MACRO
	CALL get_t_rm
	MOV dx, [c_t_rm]
	strlen dx
	CALL write_chunk
ENDM

; print prefix if present
print_if_prefix MACRO
	local no
	PUSHREGS <dx, cx>
	CMP [c_prefix], 0
	JE no
	MOV dx, [c_prefix]
	strlen dx
	CALL write_chunk
	print_symbol ":"
no:
	POPREGS <cx, dx>
ENDM

; print rm if needed
print_if_rm MACRO
	local no
	CMP [c_t_rm], 0 ;; check if address is set
	JE no
	MOV dx, [c_t_rm]
	strlen dx
	CALL write_chunk
no:
ENDM ; can just call 'print_rm' if not deleted here instead of calling 'write_chunk'

print_if_posl MACRO
	local no
	CMP [c_pos_set], 0
	JE no
	CALL print_posl
no:
ENDM


; Print '[' (Left Bracket) if mod!=11(3)
print_if_lb MACRO
	local no
	CMP [c_mod], 3
	JE no
	print_symbol "["
no:
ENDM

; Print ']' (Right Bracket) if mod!=11(3)
print_if_rb MACRO
	local no
	CMP [c_mod], 3
	JE no
	print_symbol "]"
no:
ENDM  


; Print pointer directive if required
print_if_ptr PROC
	PUSHREGS <dx, cx>

	CMP [c_w_bit], 1
	JE __print_word_ptr
	CMP [c_d_bit], 1
	JE __print_byte_ptr

	JMP __ptr_leave

__print_word_ptr:
	CMP [c_mod], 3
	JE __ptr_leave
	MOV dx, [t_word_ptr]
	strlen dx
	CALL write_chunk
	JMP __ptr_leave


__print_byte_ptr:
	CMP [c_mod], 3
	JE __ptr_leave
	MOV dx, [t_byte_ptr]
	strlen dx
	CALL write_chunk

__ptr_leave:
	POPREGS <cx, dx>
	RET
print_if_ptr ENDP


; TEMP macro for debugging!!!!!!!!!!!!!!!!!
print_nr_screen MACRO byt
	PUSHREGS <ax, dx>
	MOV dl, byt
	ADD dl, 30h
	MOV ah, 02h
	INT 21h
	POPREGS <dx, ax>
ENDM
