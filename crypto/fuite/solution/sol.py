#!/usr/bin/python3
from Crypto.Util.number import * 
from pwn import * 

#io = process('./leaky.py')

bits = 896
io = remote('localhost' , 3333)
p = [ '1' for _ in range(bits)]

def decrypt(msg , p , q):
    d = pow(0x10001 , -1 , (p-1)*(q-1))
    return long_to_bytes(pow(msg , d , p*q))

for i in range(6):
    io.recvline()

for i in range(9):
    io.recvuntil(b'enter choice : ')
    io.sendline(b'1')
    io.recvuntil(b'enter r : ')
    r = int('1'*(bits) , 2 ) 
    io.sendline(str(r).encode())
    leak = int(io.recvline().decode()) ^ r # (p | leaky) 
    leak_list = [ i for i in bin(leak)[2:]]
    for i in range(bits):
        if leak_list[i] == '0' : p[i] = '0'  


io.recvuntil(b'enter choice : ')
io.sendline(b'2')
n = int(io.recvline().decode().split('=')[1])
flag = int(io.recvline().decode().split('=')[1])
p_known = int(''.join(p) + '0'*128 , 2)

result = subprocess.run(["sage", "coppersmith.sage",  str(n) , str(p_known)], capture_output=True, text=True).stdout
p , q = eval(result)

assert n == q*p
print(decrypt(flag , q , p))



io.close()








