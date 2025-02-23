#!/usr/bin/python3 
from Crypto.Util.number import *  
from math import gcd  
from random import * 
from secrets import *
from secret import FLAG


 
class Prover : 
    def __init__(self , p , q): 
        self.n = p*q 
        self.p = p 
        self.q = q 
        self.K = 10  
        self.A = self.n.bit_length()
        self.B = 128
        self.r = getrandbits(2048 - 128)
        self.x_s = []
        self.z_s = []

    def generate(self):
        for _ in range(self.K):
            z = randbelow(self.n)
            while( gcd(z, self.n) != 1 ) :
                z = randbelow(self.n)
            self.z_s.append(z) 
            x_i = pow( z , self.r , self.n) 
            self.x_s.append(x_i)
    
    def check_e(self , e ):
        if (0 < e < 2 ** self.B) :
            self.e = e 
            return True
        return False

    
    def calculate_y(self):
        phi = (self.p-1) * (self.q -1 )
        y = self.r + (self.n - phi) * self.e
        return y 


 
class Challenge : 
    def __init__(self , FLAG): 
        self.p = getPrime(1024) 
        self.q = getPrime(1024) 
        self.n = self.p * self.q  
        self.e = 0x10001
        self.flag = FLAG 
 
    def get_flag(self): 
        return pow(bytes_to_long(self.flag) , self.e , self.n)  
      
    def initial_message(self): 
        print(f'Your Goal is to verify That the prover knows the factorization of n = {self.n}  ') 
    



 
verifier_rules = """
Hello , You are the Verifier For this ZKP protocol Here's some rules that u should follow :
    1. Don’t Pretend to Know the Factors (Stay Honest): As the verifier, you don’t know p and q, and that’s fine. You’re here to make sure the prover really knows them without actually getting the answer.
    2. Don’t Cheat (Don’t Peek for Secrets): Your job is to test, not to try and secretly learn the factors. You’re verifying that the prover knows them without revealing them—so no shortcuts, no guessing or ‘peeking’.
    3. Check the Prover’s Math (Actually Do the Work): The prover will send back some fancy math stuff. You need to plug it into whatever the ZKP protocol says to check. Make sure their response holds up mathematically (no ‘close enough’ here).
    4. Accept or Reject (Don’t Be Lenient): At the end of your rounds, either accept that they know p and q or reject their proof if they failed. There’s no middle ground—either they proved it without revealing the secret, or they didn’t.
    5. No flag for you: There is no way you can get the flag since you don't know p and q, so don't even try.

--------------------------------------------------------------------------- Let's Begin ---------------------------------------------------------------------------------------------------
"""
 
def main(): 
    print(verifier_rules)
    challenge = Challenge(FLAG) 
    prover = Prover(challenge.p , challenge.q) 
    while True :
        try :
            prover.generate()
            challenge.initial_message()
            print(f"Here is The prover's x_s list : {prover.x_s} ")
            print(f"Here is The prover's z_s list : {prover.z_s} ")
            e = int(input('> Enter your e : '))
            if not (prover.check_e(e)):
                print('I said Be Honest ..... I am disappointed ')
            y = prover.calculate_y()
            print(f"Here is My y : {y}")

            print('-----------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
            
            again = input('Does The prover rlly knows the factorization of n ? (y/n)')
            if (again.lower() == 'y' ):
                print(f'Here is the encrypted Flag :{challenge.get_flag()}')
                exit(0)
            
        except :
            print('Something Went Wrong')
            exit()
    
 
if __name__ == "__main__": 
    main()


