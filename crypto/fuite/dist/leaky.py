#! /usr/bin/python3 

from Crypto.Util.number import * 
from random import SystemRandom
from secret import FLAG
rng = SystemRandom()

MENU = """
MENU : 
    1 - get leak 
    2 - encrypt flag 

"""

class Leakage:
    def __init__(self , bits):
        self.bits = bits
        self.p = getPrime(bits)
        self.q = getPrime(bits)
        self.e = 0x10001
        self.n = self.q * self.p
        self.TRIES = 10
        self.hidden = 128

    def encrypt(self , msg):
        self.TRIES -= 1 
        return pow(bytes_to_long(msg) , self.e , self.n)


    def leak(self , r):
        self.TRIES -= 1 
        leaky = [ str(int(rng.random() > 0.8)) for _ in range(self.bits - self.hidden) ]
        leaky = int(''.join(leaky) , 2)
        partial_p = self.get_chapeau()
        return ((partial_p&r) | leaky) ^ r
    
    def get_chapeau(self):
        x = bin(self.p)[2:]
        partial_p = x[:-self.hidden]
        return int(partial_p , 2)

def main():
    chall = Leakage(1024)
    print(MENU)
    while (chall.TRIES):
        print(f"---------------------------------------- You have {chall.TRIES} tries left -----------------------------------------")
        choice = int(input('enter choice : '))
        if ( choice == 1 ):
                try :
                    r = int(input('enter r : '))
                    print(chall.leak(r))
                except  :
                    pass
                    
        elif (choice == 2 ) : 
                print(f"n = {chall.n}")
                print(f"flag_enc = {chall.encrypt(FLAG)}")
        else :
            print(MENU)  
    print(f'Bye ')
    exit()

if __name__ == '__main__':
    main()
