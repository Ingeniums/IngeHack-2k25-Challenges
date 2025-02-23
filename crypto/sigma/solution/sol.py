#!/usr/bin/python3
from pwn  import * 
from Crypto.Util.number import *
from math import isqrt


# r = process('./src_ver.py')

r = remote('localhost' , 1026)


def get_phi(y , e , n):
    diff1 = (y[1] - y[0]) % n
    diff2 = (e[1] - e[0]) % n 
    inv  = pow(diff2 , -1 , n )
    a = (diff1 * inv ) % n 
    return a 



def decrypt(flag , phi , n ):
    e = 0x10001
    d = pow(e , -1 , phi) 
    return long_to_bytes(pow(flag , d , n))
e = [15 , 40]
y = []
ans = ['n' , 'y']

r.recvuntil(b'factorization of n = ')

n = int(r.recvline().decode().strip())
for i in range(2):
    r.sendlineafter(b'your e : ' , str(e[i]).encode() )
    y.append(int(r.recvline().decode().split(':')[1].strip()))
    r.sendlineafter(b'factorization of n ? (y/n)' , ans[i].encode())

flag = int(r.recvline().decode().split(':')[1].strip())

phi = n - get_phi(y , e , n)


print(decrypt(flag , phi , n))
r.interactive()
