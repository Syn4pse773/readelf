format ELF64 executable 3
entry start
macro write fd, buffer, size {
	mov     rax, 1
	mov     rdi, fd
	mov     rsi, buffer
	mov     rdx, size
	syscall

}
; ELF Magic & Identification Constants
	ELF_MAGIC             =       0x464C457F       ; "\x7FELF" (little-endian)
	ELFCLASS32            =       1                ; 32-bit objects
	ELFCLASS64            =       2                ; 64-bit objects
	ELFDATA2LSB           =       1                ; 2's complement, little-endian
	ELFDATA2MSB           =       2                ; 2's complement, big-endian

struc   Elf64_Ehdr {
	.e_ident              rb      16               ; ELF identification
	.e_type               rw      1                ; Object file type
	.e_machine            rw      1                ; Machine architecture
	.e_version            rd      1                ; File version
	.e_entry              rq      1                ; Entry point VMA
	.e_phoff              rq      1                ; Program header table offset
	.e_shoff              rq      1                ; Section header table offset
	.e_flags              rd      1                ; Processor-specific flags
	.e_ehsize             rw      1                ; ELF header size
	.e_phentsize          rw      1                ; Program header entry size
	.e_phnum              rw      1                ; Program header entry count
	.e_shentsize          rw      1                ; Section header entry size
	.e_shnum              rw      1                ; Section header entry count
	.e_shstrndx           rw      1                ; Section name string table index
}
virtual at 0
	Elf64_Ehdr Elf64_Ehdr
	sizeof.Elf64_Ehdr     =       $
end virtual

struc   Elf64_Phdr {
	.p_type               rd      1                ; Segment type
	.p_flags              rd      1                ; Segment flags
	.p_offset             rq      1                ; Segment file offset
	.p_vaddr              rq      1                ; Segment virtual address
	.p_paddr              rq      1                ; Segment physical address
	.p_filesz             rq      1                ; Segment size in file
	.p_memsz              rq      1                ; Segment size in memory
	.p_align              rq      1                ; Segment alignment
}
virtual at 0
	Elf64_Phdr Elf64_Phdr
	sizeof.Elf64_Phdr     =       $
end virtual

struc   Elf64_Shdr {
	.sh_name              rd      1                ; Section name (string table offset)
	.sh_type              rd      1                ; Section type
	.sh_flags             rq      1                ; Section flags
	.sh_addr              rq      1                ; Section virtual address
	.sh_offset            rq      1                ; Section file offset
	.sh_size              rq      1                ; Section size in bytes
	.sh_link              rd      1                ; Link to another section
	.sh_info              rd      1                ; Additional section info
	.sh_addralign         rq      1                ; Section alignment
	.sh_entsize           rq      1                ; Section entry size
}
virtual at 0
	Elf64_Shdr Elf64_Shdr
	sizeof.Elf64_Shdr     =       $
end virtual
segment readable executable

start:
	mov     rdi, [rsp]
	cmp     rdi, 2
	jl      argserror



	mov     rdi, [rsp + 16]
	mov     rax, 2
	mov     rsi, 0
	mov     rdx, 0
	syscall
	cmp     rax, 0
	jl      openerror
	mov     r14, rax
	lea     r12, [buffer]
	; mov     rax, 8
	; mov     rdi, r14
	; mov     rsi, 0
	; mov     rdx, 2
	; syscall
	; mov     r15, rax
	; mov     rax, 8
	; mov     rdi, r14
	; mov     rsi, 0
	; mov     rdx, 0
	; syscall
.readloop:
	mov     rax, 0
	mov     rdi, r14
	mov     rsi, r12
	mov     rdx, 65536
	syscall
	cmp	rax, 0
	jle	.readdone
	add	r12, rax
	jmp	.readloop
.readdone:
	mov     rax, 3
	mov     rdi, r14
	syscall
	cmp     dword [buffer + Elf64_Ehdr.e_ident], ELF_MAGIC
	jne     fileisnotELF
	write   1, ELFbuff, ELFbuff_len

	cmp     byte [buffer + Elf64_Ehdr.e_ident + 4], ELFCLASS32
	je      .fileis32bit

	write   1, fileis64bitmsg, fileis64bitmsglen
	write   1, ELFCLASS64msg, ELFCLASS64msglen
	movzx   rax, byte [buffer + Elf64_Ehdr.e_ident + 4]
	mov     [elf64classaddr], al
	call    print_hex
	jmp     aftercheck

.fileis32bit:
	write   1, fileis32bitmsg, fileis32bitmsglen
	jmp     aftercheck

aftercheck:
	mov     al, [buffer + Elf64_Ehdr.e_ident + 5]
	cmp     al, ELFDATA2MSB
	je      big_endian

	write   1, fileislittleendianmsg, fileislittleendianmsglen
	write   1, ELFDATA2LSBmsg, ELFDATA2LSBmsglen
	jmp     skipshit
big_endian:
	write   1, fileisbigendianmsg, fileisbigendianmsglen
	jmp     skipshit

skipshit:
	movzx   rax, byte [buffer + Elf64_Ehdr.e_ident + 5]
	mov     byte [littleEndianOrBig], al
	call    print_hex

e_shoffcalc:
	write   1, e_shoffmsg, e_shoffmsglen
	mov     rax, qword [buffer + Elf64_Ehdr.e_shoff]
	mov     [e_shoffaddr], rax
	lea     r14, [buffer]
	add     r14, rax                               ;14 = buffer + e_shoff
	call    print_hex
e_shnumcalc:
	write   1, E_SHNUMMSG, E_SHNUMMSGlen
	movzx   rax, word [buffer + Elf64_Ehdr.e_shnum]
	mov     [e_shnum], ax
	call    print_hex
e_shstrndxcalc:
	write   1, E_SHSTRNDXMSG, E_SHSTRNDXMSGlen
	movzx   rax, word [buffer + Elf64_Ehdr.e_shstrndx]
	mov     [e_shstrndx], ax
	call    print_hex
sh_offsetcalc:
	write   1, SH_OFFSETMSG, SH_OFFSETMSGlen
	movzx   rbx, word [e_shstrndx]
	imul    rbx, sizeof.Elf64_Shdr
	add     rbx, [e_shoffaddr]
	lea	rbx, [buffer + rbx]
	mov     rax, qword [rbx + Elf64_Shdr.sh_offset]
	mov     [sh_offset], rax
	call    print_hex
shstrtabcalc:
	write   1, SHSTRTABMSG, SHSTRTABMSGlen
	mov     rbx, [sh_offset]
	lea     rax, [buffer + rbx]
	mov     [shstrtab], rax
	call    print_hex
e_phoffcalc:
	write   1, E_PHOFFMSG, E_PHOFFMSGlen
	mov     rax, qword [buffer + Elf64_Ehdr.e_phoff]
	mov     [e_phoff], rax
	call    print_hex
e_phnumcalc:
	write   1, E_PHNUMMSG, E_PHNUMMSGlen
	movzx   rax, word [buffer + Elf64_Ehdr.e_phnum]
	mov     [e_phnum], ax
	call    print_hex
	cmp     rcx, 0
	je      exit                                   ; no_sections
	write   1, SEGMENTinfomsg, SEGMENTinfomsglen
	mov     rax, [e_phoff]
	lea     rbx, [buffer + rax]
	movzx   rcx, word [e_phnum]

.segmentloop:
	push    rcx
	push    rbx

	mov     eax, dword [rbx + Elf64_Phdr.p_type]
	call    print_hex
	mov     rax, qword [rbx + Elf64_Phdr.p_vaddr]
	pop     rbx
	pop     rcx

	add     rbx, sizeof.Elf64_Phdr
	dec     rcx
	jnz     .segmentloop


print_sections:
	movzx   rcx, word [e_shnum]
	test    rcx, rcx
	jz      hexdumpPreparation

	mov     rax, [e_shoffaddr]
	lea     rbx, [buffer + rax]                    ; rbx = elf64 shdr
.section_loop:
	push    rcx
	push    rbx

	mov     rax, qword [rbx + Elf64_Shdr.sh_addr]
	call    print_hex_no_nl
	write   1, bracket_open, 2
	mov     eax, dword [rbx + Elf64_Shdr.sh_name]
	mov     rsi, [shstrtab]
	add     rsi, rax

	call    print_string_null
	write   1, bracket_close, 2

	pop     rbx
	pop     rcx

	add     rbx, sizeof.Elf64_Shdr
	dec     rcx
	jnz     .section_loop


hexdumpPreparation:
	write   1, doyouwanna, doyouwanna_len
	mov     rax, 0
	xor     edi, edi
	mov     rsi, readbuff
	mov     rdx, 2
	syscall
	movzx   r15, byte [readbuff]
	or      r15, 0x20

	cmp     r15, 'y'
	je      preparation
	jmp     exit


preparation:
	mov     rsi, buffer
	mov     rcx, 16

dump_loop:
	push    rsi rcx
	mov     rax, [rsi]
	cmp     rax, 0
	je      .skip
	call    print_hex
	pop     rcx rsi
	add     rsi, 8
	loop    dump_loop

	jmp     exit
.skip:
	pop     rcx rsi
	add     rsi, 8
	loop    dump_loop
	jmp     exit

openerror:
	mov     rax, 1
	mov     rdi, 2
	mov     rsi, openerrormsg
	mov     rdx, openerrormsg_len
	syscall

	jmp     exit

fileisnotELF:
	mov     rax, 1
	mov     rdi, 1
	mov     rsi, notELF
	mov     rdx, notELF_LEN
	syscall
	jmp     exit
print_hex:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi

	mov     rbx, rax
	mov     rcx, 16                                ; 16 hex
	mov     rdi, out_buf                           ; ptr to buff

.loop:
	rol     rbx, 4
	mov     rax, rbx
	and     rax, 0x0F
	mov     dl, [hex_chars + rax]
	mov     [rdi], dl
	inc     rdi
	loop    .loop

	; \n
	mov     byte [rdi], 10
	; syswrite
	write   1, out_buf, 17

	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret
print_hex_no_nl:
	push    rax rbx rcx rdx rsi rdi
	mov     rbx, rax
	mov     rcx, 16
	mov     rdi, out_buf
.l:
	rol     rbx, 4
	mov     rax, rbx
	and     rax, 0x0F
	mov     dl, [hex_chars + rax]
	mov     [rdi], dl
	inc     rdi
	loop    .l
	write   1, out_buf, 16
	pop     rdi rsi rdx rcx rbx rax
	ret

print_string_null:
	push    rsi rdi rdx rax
	mov     rdi, rsi
.find_len:
	cmp     byte [rsi], 0
	je      .done
	inc     rsi
	jmp     .find_len
.done:
	mov     rdx, rsi
	sub     rdx, rdi
	jz      .empty
	mov	rax, 1
	mov	rsi, rdi
	mov	rdi, 1
	syscall
.empty:
	pop     rax rdx rdi rsi
	ret

argserror:
	write   1, argserrormsg, argserrormsglen

exit:
	mov     rax, 60
	xor     rdi, rdi
	syscall

segment readable writeable
	bracket_open db ' ['
	bracket_close db ']', 10
	hex_chars             db      '0123456789ABCDEF'
	out_buf               rb      17               ; 16+1 (\n)
	ELFbuff               db      'THIS IS ELF!', 0, 10
	ELFbuff_len           =       $ - ELFbuff
	notELF                db      'this isnt ELF. :(', 0, 10
	notELF_LEN            =       $ - notELF
	openerrormsg          db      'ERROR WHILE TRYING TO OPEN FILE'
	openerrormsg_len      =       $ - openerrormsg
	doyouwanna            db      'Do you wanna print hexdump?(y/N)', 0, 10
	doyouwanna_len        =       $ - doyouwanna
	e_shoffmsg            db      'E_SHOFF = ', 0
	e_shoffmsglen         =       $ - e_shoffmsg
	ELFCLASS64msg         db      'ELFCLASS64 = ', 0
	ELFCLASS64msglen      =       $ - ELFCLASS64msg

	fileis32bitmsg        db      'FILE IS 32 BIT!', 0, 10
	fileis32bitmsglen     =       $ - fileis32bitmsg
	fileis64bitmsg        db      'FILE IS 64 BIT!', 0, 10
	fileis64bitmsglen     =       $ - fileis64bitmsg

	ELFDATA2LSBmsg        db      'ELFDATA2LSB = ', 0
	ELFDATA2LSBmsglen     =       $ - ELFDATA2LSBmsg

	fileislittleendianmsg db      'FILE IS LITTLE ENDIAN!', 0, 10
	fileislittleendianmsglen= $ - fileislittleendianmsg
	fileisbigendianmsg    db      'FILE IS BIG ENDIAN!', 0, 10
	fileisbigendianmsglen =       $ - fileisbigendianmsg

	E_SHNUMMSG            db      'E_SHNUM = ', 0
	E_SHNUMMSGlen         =       $ - E_SHNUMMSG

	E_SHSTRNDXMSG         db      'E_SHSTRNDX = ', 0
	E_SHSTRNDXMSGlen      =       $ - E_SHSTRNDXMSG

	SH_OFFSETMSG          db      'SH_OFFSET = ', 0
	SH_OFFSETMSGlen       =       $ - SH_OFFSETMSG

	SHSTRTABMSG           db      'SHSTRTAB = ', 0
	SHSTRTABMSGlen        =       $ - SHSTRTABMSG

	E_PHOFFMSG            db      'E_PHOFF = ', 0
	E_PHOFFMSGlen         =       $ - E_PHOFFMSG

	E_PHNUMMSG            db      'E_PHNUM = ', 0
	E_PHNUMMSGlen         =       $ - E_PHNUMMSG

	SEGMENTinfomsg        db      'SEGMENTS: ', 0, 10
	SEGMENTinfomsglen     =       $ - SEGMENTinfomsg

	argserrormsg          db      'ERROR WHILE TRING TO OPEN FILE (ARGS ERROR)', 0, 10
	argserrormsglen       =       $ - argserrormsg

	sh_offset             rq      1
	e_phoff               rq      1
	e_phnum               rw      1
	shstrtab              rq      1
	readbuff              rb      2                ; y/N + \n = byte
	e_shoffaddr           rq      1
	elf64classaddr        rb      1
	littleEndianOrBig     rb      1
	e_shnum               rw      1
	e_shstrndx            rw      1
	buffer                rb      524288
