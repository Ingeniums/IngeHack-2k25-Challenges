[bits 16]
[org 0x7c00]

	cld		
	xor dx, dx
  mov word [data_ptr], tape

repl_loop:

	mov di, input
  mov word [pc], input

  mov al, '>'
  call putch
  mov al, ' '
  call putch

.read_chr:

  call getch

  cmp al, 0x7f
  je .backspace

  stosb

  cmp al, 0x0d
  je .run_code

  cmp al, 0x0a
  je .run_code

  jmp .read_chr

.backspace:
  cmp di, input
  je .read_chr

  dec di
  mov al, 0x8
  call putch
  mov al, ' '
  call putch
  mov al, 0x8
  call putch
  jmp .read_chr

.run_code:

  mov al, 0xa
  call putch

  dec word [pc]

.next_instr:
  inc word [pc]
  mov si, word [pc]

  cmp byte [si], '+'
  je .increment_value_at

  cmp byte [si], '-'
  je .decrement_value_at

  cmp byte [si], '>'
  je .increment_ptr

  cmp byte [si], '<'
  je .decrement_ptr

  cmp byte [si], '.'
  je .print_at

  cmp byte [si], ','
  je .read_at

  cmp byte [si], '['
  je .jump_fwd

  cmp byte [si], ']'
  je .jump_bck

.eol:
  mov al, 0xa
  call putch

  jmp repl_loop


.increment_value_at:
  mov si, word [data_ptr]
  inc byte [si]
  jmp .next_instr

.decrement_value_at:
  mov si, word [data_ptr]
  dec byte [si]
  jmp .next_instr

.increment_ptr:
  inc word [data_ptr]
  jmp .next_instr

.decrement_ptr:
  dec word [data_ptr]
  jmp .next_instr

.print_at:
  mov si, word [data_ptr]
  mov al, byte [si]

  call putch

  jmp .next_instr

.read_at:
  call getch
  mov si, word [data_ptr]
  mov byte [si], al

  mov al, 0xa
  call putch

  jmp .next_instr

.jump_fwd:
  mov si, word [data_ptr]
  cmp byte [si], 0
  jne .next_instr
  mov cx, 1

.jump_fwd_loop:

  inc word [pc]
  mov si, word [pc]
  cmp byte [si], '['
  jne .jump_fwd_not_open
  inc cx

.jump_fwd_not_open:
  cmp byte [si], ']'
  jne .jump_fwd_not_close
  dec cx

.jump_fwd_not_close:
  cmp cx, 0
  jne .jump_fwd_loop
  jmp .next_instr


.jump_bck:
  mov si, word [data_ptr]
  cmp byte [si], 0
  je .next_instr
  mov cx, 1

.jump_bck_loop:
  dec word [pc]
  mov si, word [pc]
  cmp byte [si], ']'
  jne .jump_bck_not_close
  inc cx

.jump_bck_not_close:
  cmp byte [si], '['
  jne .jump_bck_not_open
  dec cx

.jump_bck_not_open:
  cmp cx, 0
  jne .jump_bck_loop
  jmp .next_instr
  

putch:
  mov dx, 0x3F8
  out dx, al
  ret

getch:
  mov dx, 0x3F8 + 5
  in al, dx
  test al, 1
  je getch
  sub dl, 5
  in al, dx
  out dx, al
  ret

data_ptr:
  dw 0
pc:
  dw 0
tape:
  times 0x30 db 0
input:

	times 510 - ($ - $$) db 0
	dw 0xaa55

sector_end:
  db 'ingehack{debugging_real_mode_apps_sucks_man}'
