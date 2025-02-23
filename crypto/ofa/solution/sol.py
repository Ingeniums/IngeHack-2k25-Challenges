#!/usr/bin/python3

from Crypto.Util.number import * 
import random
import time 
from pwn import * 


def init(i):
    random.seed(i)


io = remote('localhost' , 16001)
seed_asm = int(time.time())

io.sendlineafter(b'>' , b'2')
flag = io.recvline().decode().strip()


for i in range(-20 , 20):
    io.sendlineafter(b'>' , b'1')
    init(seed_asm + i)
    nonce = long_to_bytes(random.getrandbits(8*8)).hex()
    io.sendlineafter(b'plaintext(hex) : ' , flag.encode() )
    io.sendlineafter(b'nonce(hex) :' , nonce.encode() )
    out = bytes.fromhex(io.recvline().decode().strip())
    if b'ingehack' in out : 
        print((i , out))
        break 



io.interactive()