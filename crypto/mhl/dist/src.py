#!/usr/bin/env python3

from Crypto.Util.number import inverse  , bytes_to_long as bl
from ecdsa.ecdsa import generator_256  
import os
n = int(generator_256.order())
G = generator_256
FLAG  = b'someflag here'

class ECDSASigner:
    def __init__(self , key):
        self.n = int(generator_256.order())
        self.G = generator_256
        self.d = bl(key)
        self.Q = self.d * self.G

    def generate_nonces(self):
        nonces = []
        sec = os.urandom(9)
        for _ in range(5):
            nonce1 = int((sec + os.urandom(23)).hex(), 16)
            nonce2 = int((sec + os.urandom(23)).hex(), 16)
            nonces.append([nonce1, nonce2])
        return nonces

    def sign(self, msg, nonces):
        k1, k2 = nonces[0], nonces[1]
        r1 = (k1 * self.G).x()
        r2 = (k2 * self.G).y()
        h = msg
        s = inverse(k1, self.n) * (h * r1 + r2 * self.d) % self.n
        return (int(r1), int(r2), int(s))

    def verify(self, msg, sig):
        r1, r2, s = sig
        h = msg
        v1 = h * r1 * inverse(s, self.n) * self.G
        v2 = r2 * inverse(s, self.n) * self.Q
        return ((v1 + v2).x() - r1) % self.n == 0

if __name__ == "__main__":
    signer = ECDSASigner(FLAG)
    nonces = signer.generate_nonces()
    msgs = [bl(os.urandom(30)) for _ in range(5)]
    sigs = [signer.sign(msg,nonce) for msg , nonce  in zip(msgs,nonces)]
    print([signer.verify(msg , sig) for msg , sig in zip(msgs , sigs)])
    with open('out.txt' , 'w') as f :
        f.write(f"msgs = {msgs}\n") 
        f.write(f"sigs = {sigs}") 
    



