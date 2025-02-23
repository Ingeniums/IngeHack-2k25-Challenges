#!/usr/bin/python3
import random
from Crypto.Util.number import *
from pwn import *  


def recover_Kj_from_Ii(Ii, Ii1, Ii2, i):
    # Ii => I[i]
    # Ii1 => I[i-1]
    # Ii2 => I[i-2]
    # Ji => J[i]
    # Ji1 => J[i-1]
    Ji = recover_Ji_from_Ii(Ii, Ii1, i)
    Ji1 = recover_Ji_from_Ii(Ii1, Ii2, i-1)
    return recover_kj_from_Ji(Ji, Ji1, i)

def recover_Ji_from_Ii(Ii, Ii1, i):
    # Ii => I[i]
    # Ii1 => I[i-1]
    ji = (Ii + i) ^ ((Ii1 ^ (Ii1 >> 30)) * 1566083941)
    ji &= 0xffffffff
    # return J[i]
    return ji
def init_genrand(seed):
        MT = [0] * 624
        MT[0] = seed & 0xffffffff
        for i in range(1, 623+1): # loop over each element
            MT[i] = ((0x6c078965 * (MT[i-1] ^ (MT[i-1] >> 30))) + i) & 0xffffffff
        return MT

def recover_kj_from_Ji(ji, ji1, i):
    # ji => J[i]
    # ji1 => J[i-1]
    const = init_genrand(19650218)
    key = ji - (const[i] ^ ((ji1 ^ (ji1 >> 30))*1664525))
    key &= 0xffffffff
    # return K[j] + j
    return key

def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ res >> shift
    return res

def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ (res << shift & mask)
    return res

def untemper(v):
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v
def invertStep(si, si227):
    # S[i] ^ S[i-227] == (((I[i] & 0x80000000) | (I[i+1] & 0x7FFFFFFF)) >> 1) ^ (0x9908b0df if I[i+1] & 1 else 0)
    X = si ^ si227
    # we know the LSB of I[i+1] because MSB of 0x9908b0df is set, we can see if the XOR has been applied
    mti1 = (X & 0x80000000) >> 31
    if mti1:
        X ^= 0x9908b0df
    # undo shift right
    X <<= 1
    # now recover MSB of state I[i]
    mti = X & 0x80000000
    # recover the rest of state I[i+1]
    mti1 += X & 0x7FFFFFFF
    return mti, mti1

def getseed(S):
    S = [ untemper(s) for s in S]
    I_227_, I_228 = invertStep(S[0], S[3])
    I_228_, I_229 = invertStep(S[1], S[4])
    I_229_, I_230 = invertStep(S[2], S[5])
    I_228 += I_228_
    I_229 += I_229_

    # two possibilities for I_230
    seed1 = recover_Kj_from_Ii(I_230, I_229, I_228, 230)
    seed2 = recover_Kj_from_Ii(I_230+0x80000000, I_229, I_228, 230)
    # only the MSB differs
    return seed1, seed2




# s = process('./casino.py')

s = remote('localhost' , 13005)

out = b'0,1,2,227,228,229'

s.sendlineafter(b' preview (e.g., 0,10,100):',out)
S = []
s.recvline()
for i in range(6):
    o = int(s.recvline().strip().decode().split(':')[1])
    S.append(o)

seed1 , seed2 = getseed(S)
random.seed(seed1)
rand = []
for idx in range(1000):
    rand.append(random.getrandbits(32))

random.seed(seed2)
rand_ = []
for idx in range(1000):
    rand_.append(random.getrandbits(32))


if  rand_[:3] == S[:3] :
    final = rand_ 
elif rand[:3] == S[:3]:
    final = rand 
else : print('wrong')


for i in range(1000) :
    s.sendlineafter(b'number: ' , str(final[i]).encode())


s.interactive()