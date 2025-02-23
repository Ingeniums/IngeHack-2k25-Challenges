putch equ 0x7D0F

[org 0x7D26]

	mov ax, 0x0201
	mov cx, 0x0002
	mov dx, 0x80
	mov bx, 0x7E00
	int 0x13
	push bx
	pop si
.puts_loop:
	lodsb
	cmp al, 0
.hang:
	je .hang
	call putch
	jmp .puts_loop
