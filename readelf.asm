format ELF64 executable 3
entry start
macro write fd, buffer, size {
	mov     rax, 1
	mov     rdi, fd
	mov     rsi, buffer
	mov     rdx, size
	syscall

}
; yea i copy it from AI.
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

	; fstat
	mov     rax, 5
	mov     rdi, r14
	mov     rsi, stat_buf
	syscall
	cmp     rax, 0
	jl      openerror

	mov     rax, qword [stat_buf + 48]
	mov     [file_size], rax

	; mmap
	mov     rax, 9
	xor     rdi, rdi
	mov     rsi, [file_size]
	mov     rdx, 1                                 ; PROT_READ
	mov     r10, 2                                 ; MAP_PRIVATE
	mov     r8, r14
	xor     r9, r9
	syscall
	cmp     rax, 0
	jl      openerror
	mov     [buffer], rax
	mov     r15, rax

	; close
	mov     rax, 3
	mov     rdi, r14
	syscall

	cmp     dword [r15 + Elf64_Ehdr.e_ident], ELF_MAGIC
	jne     fileisnotELF
	write   1, ELFbuff, ELFbuff_len

	cmp     byte [r15 + Elf64_Ehdr.e_ident + 4], ELFCLASS32
	je      .fileis32bit

	write   1, fileis64bitmsg, fileis64bitmsglen
	write   1, ELFCLASS64msg, ELFCLASS64msglen
	movzx   rax, byte [r15 + Elf64_Ehdr.e_ident + 4]
	mov     [elf64classaddr], al
	call    print_hex
	jmp     aftercheck

.fileis32bit:
	write   1, fileis32bitmsg, fileis32bitmsglen
	jmp     aftercheck

aftercheck:
	mov     al, [r15 + Elf64_Ehdr.e_ident + 5]
	cmp     al, ELFDATA2MSB
	je      big_endian

	write   1, fileislittleendianmsg, fileislittleendianmsglen
	write   1, ELFDATA2LSBmsg, ELFDATA2LSBmsglen
	jmp     skipshit
big_endian:
	write   1, fileisbigendianmsg, fileisbigendianmsglen
	jmp     skipshit

skipshit:
	movzx   rax, byte [r15 + Elf64_Ehdr.e_ident + 5]
	mov     byte [littleEndianOrBig], al
	call    print_hex

e_shoffcalc:
	write   1, e_shoffmsg, e_shoffmsglen
	mov     rax, qword [r15 + Elf64_Ehdr.e_shoff]
	mov     [e_shoffaddr], rax
	call    print_hex

e_shnumcalc:
	write   1, E_SHNUMMSG, E_SHNUMMSGlen
	movzx   rax, word [r15 + Elf64_Ehdr.e_shnum]
	mov     [e_shnum], ax
	call    print_hex

e_shstrndxcalc:
	write   1, E_SHSTRNDXMSG, E_SHSTRNDXMSGlen
	movzx   rax, word [r15 + Elf64_Ehdr.e_shstrndx]
	mov     [e_shstrndx], ax
	call    print_hex

sh_offsetcalc:
	write   1, SH_OFFSETMSG, SH_OFFSETMSGlen
	movzx   rbx, word [e_shstrndx]
	imul    rbx, sizeof.Elf64_Shdr
	add     rbx, [e_shoffaddr]
	lea     rbx, [r15 + rbx]
	mov     rax, qword [rbx + Elf64_Shdr.sh_offset]
	mov     [sh_offset], rax
	call    print_hex

shstrtabcalc:
	write   1, SHSTRTABMSG, SHSTRTABMSGlen
	mov     rbx, [sh_offset]
	lea     rax, [r15 + rbx]
	mov     [shstrtab], rax
	call    print_hex

e_phoffcalc:
	write   1, E_PHOFFMSG, E_PHOFFMSGlen
	mov     rax, qword [r15 + Elf64_Ehdr.e_phoff]
	mov     [e_phoff], rax
	call    print_hex

e_phnumcalc:
	write   1, E_PHNUMMSG, E_PHNUMMSGlen
	movzx   rax, word [r15 + Elf64_Ehdr.e_phnum]
	mov     [e_phnum], ax
	call    print_hex
	movzx   rcx, word [e_phnum]
	cmp     rcx, 0
	je      print_sections                         ; no_sections
	write   1, SEGMENTinfomsg, SEGMENTinfomsglen
	movzx   rcx, word [e_phnum]
	mov     rax, [e_phoff]
	lea     rbx, [r15 + rax]

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
	lea     rbx, [r15 + rax]
	xor     r12, r12


.section_loop:
	push    rcx
	push    rbx
	push    r12

	write   1, bracket_open, 1
	mov     rax, r12
	call    print_dec
	write   1, bracket_close_space, 2

	mov     rax, qword [rbx + Elf64_Shdr.sh_addr]
	call    print_hex_no_nl
	write   1, bracket_open_space, 2
	mov     eax, dword [rbx + Elf64_Shdr.sh_name]
	mov     rsi, [shstrtab]
	add     rsi, rax

	call    print_string_null
	write   1, bracket_close, 2

	pop     r12
	pop     rbx
	pop     rcx

	inc     r12
	add     rbx, sizeof.Elf64_Shdr
	dec     rcx
	jnz     .section_loop



hexdumpPreparation:
	write   1, doyouwanna, doyouwanna_len
	mov     rax, 0
	xor     edi, edi
	mov     rsi, readbuff
	mov     rdx, 16
	syscall
	cmp     rax, 0
	jle     exit

	movzx   rax, byte [readbuff]
	cmp     al, 'n'
	je      exit
	cmp     al, 'N'
	je      exit
	cmp     al, 'q'
	je      exit
	cmp     al, 10
	je      exit

	cmp     al, 'a'
	je      .dump_all
	cmp     al, 'A'
	je      .dump_all

	xor     rax, rax
	xor     rcx, rcx



.parse_num:
	movzx   rdx, byte [readbuff + rcx]
	cmp     dl, 10
	je      .num_parsed
	cmp     dl, 0
	je      .num_parsed
	cmp     dl, ' '
	je      .num_parsed
	cmp     dl, '0'
	jl      exit
	cmp     dl, '9'
	jg      exit
	sub     dl, '0'
	imul    rax, 10
	add     rax, rdx
	inc     rcx
	jmp     .parse_num



.num_parsed:
	movzx   rcx, word [e_shnum]
	cmp     rax, rcx
	jae     exit

	imul    rax, sizeof.Elf64_Shdr
	add     rax, [e_shoffaddr]
	lea     rbx, [r15 + rax]

	mov     rax, [rbx + Elf64_Shdr.sh_offset]
	mov     [dump_start], rax
	mov     rax, [rbx + Elf64_Shdr.sh_size]
	mov     [dump_len], rax
	jmp     ppreparation


.dump_all:
	mov     qword [dump_start], 0
	mov     rax, [file_size]
	mov     [dump_len], rax



ppreparation:
	mov     r12, [dump_len]
	test    r12, r12
	jz      exit
	xor     rbx, rbx
	mov     byte [is_dup], 0
	mov     byte [has_prev], 0




.dump_line:
	cmp     rbx, r12
	jge     exit

	lea     rax, [rbx + 16]
	cmp     rax, r12
	ja      .print_current_line

	cmp     byte [has_prev], 0
	je      .print_current_line

	mov     rax, [dump_start]
	add     rax, rbx
	lea     rsi, [r15 + rax]
	lea     rdi, [prev_line]
	mov     rax, [rsi]
	cmp     rax, [rdi]
	jne     .not_dup
	mov     rax, [rsi + 8]
	cmp     rax, [rdi + 8]
	jne     .not_dup

	cmp     byte [is_dup], 1
	je      .skip_line

	write   1, star_line, 2
	mov     byte [is_dup], 1
	jmp     .skip_line



.not_dup:
	mov     byte [is_dup], 0

.print_current_line:
	mov     rax, [dump_start]
	add     rax, rbx
	lea     rsi, [r15 + rax]
	lea     rdi, [prev_line]
	xor     rcx, rcx



.copy_prev:
	lea     rax, [rbx + rcx]
	cmp     rax, r12
	jae     .pad_prev
	mov     al, [rsi + rcx]
	mov     [rdi + rcx], al
	jmp     .next_copy



.pad_prev:
	mov     byte [rdi + rcx], 0





.next_copy:
	inc     rcx
	cmp     rcx, 16
	jl      .copy_prev

	mov     byte [has_prev], 1

	mov     rax, [dump_start]
	add     rax, rbx
	call    print_hex_no_nl
	write   1, colon_space, 2                      ; :

	xor     r13, r13



.hex_bytes:
	lea     rax, [rbx + r13]
	cmp     rax, r12
	jge     .pad_hex

	mov     rax, [dump_start]
	add     rax, rbx
	add     rax, r13
	movzx   rax, byte [r15 + rax]
	call    print_byte_hex
	jmp     .next_hex



.pad_hex:
	write   1, pad_spaces, 3                       ; align



.next_hex:
	inc     r13
	cmp     r13, 16
	jl      .hex_bytes

	write   1, bar_open, 3                         ; |
	xor     r13, r13


.ascii_bytes:
	lea     rax, [rbx + r13]
	cmp     rax, r12
	jge     .line_done

	mov     rax, [dump_start]
	add     rax, rbx
	add     rax, r13
	movzx   rax, byte [r15 + rax]
	cmp     al, 32
	jl      .dot
	cmp     al, 126
	jg      .dot
	mov     [ascii_char], al
	jmp     .print_char
.dot:
	mov     byte [ascii_char], '.'




.print_char:
	write   1, ascii_char, 1

	inc     r13
	cmp     r13, 16
	jl      .ascii_bytes



.line_done:
	write   1, bar_close_nl, 2                     ; \n




.skip_line:
	add     rbx, 16
	jmp     .dump_line







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

print_dec:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi
	push    r11

	mov     rdi, dec_buf + 15
	mov     byte [rdi], 0
	mov     rbx, 10
.dec_loop:
	xor     rdx, rdx
	div     rbx
	add     dl, '0'
	dec     rdi
	mov     [rdi], dl
	test    rax, rax
	jnz     .dec_loop

	mov     rsi, rdi
	call    print_string_null

	pop     r11
	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

print_hex:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi
	push    r11

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

	pop     r11
	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

print_hex_no_nl:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi
	push    r11

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

	pop     r11
	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

print_string_null:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi
	push    r11

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
	mov     rax, 1
	mov     rsi, rdi
	mov     rdi, 1
	syscall


.empty: ; godbless func
	pop     r11
	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

argserror:
	write   1, argserrormsg, argserrormsglen

print_byte_hex:
	push    rax
	push    rbx
	push    rcx
	push    rdx
	push    rsi
	push    rdi
	push    r11

	mov     bl, al
	shr     al, 4
	and     al, 0x0F
	movzx   rax, al

	mov     dl, [hex_chars + rax]
	mov     [byte_buf], dl

	mov     al, bl
	and     al, 0x0F
	movzx   rax, al
	mov     dl, [hex_chars + rax]
	mov     [byte_buf + 1], dl
	mov     byte [byte_buf + 2], ' '

	write   1, byte_buf, 3

	pop     r11
	pop     rdi
	pop     rsi
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
	ret

exit:
	mov     rax, 60
	xor     rdi, rdi
	syscall

segment readable writeable
	colon_space           db      ': ', 0
	pad_spaces            db      '   ', 0
	bar_open              db      ' | ', 0
	bar_close_nl          db      '|', 10
	star_line             db      '*', 10
	byte_buf              rb      3
	ascii_char            rb      1
	bracket_open          db      '['
	bracket_open_space    db      ' ['
	bracket_close         db      ']', 10
	bracket_close_space   db      '] '
	hex_chars             db      '0123456789ABCDEF'
	out_buf               rb      17               ; 16+1 (\n)
	dec_buf               rb      16
	prev_line             rb      16
	is_dup                rb      1
	has_prev              rb      1
	stat_buf              rb      144

	ELFbuff               db      'THIS IS ELF!', 0, 10
	ELFbuff_len           =       $ - ELFbuff
	notELF                db      'this isnt ELF. :(', 0, 10
	notELF_LEN            =       $ - notELF
	openerrormsg          db      'ERROR WHILE TRYING TO OPEN FILE', 10
	openerrormsg_len      =       $ - openerrormsg
	doyouwanna            db      'Select section to dump (0-99, a=all, n=skip): ', 0
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

	buffer                rq      1
	file_size             rq      1
	dump_start            rq      1
	dump_len              rq      1
	sh_offset             rq      1
	e_phoff               rq      1
	shstrtab              rq      1
	e_shoffaddr           rq      1
	e_phnum               rw      1
	e_shnum               rw      1
	e_shstrndx            rw      1
	elf64classaddr        rb      1
	littleEndianOrBig     rb      1
	readbuff              rb      16
