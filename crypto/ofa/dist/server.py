#!/usr/bin/python3 
from Crypto.Cipher import AES
from Crypto.Util.number import * 
import random
import os 
import time 
from secret import FLAG 

key = os.urandom(16)


def init():
    random.seed(int(time.time()))


def encrypt_plain(plaintext , nonce=None ):
    if nonce == None :
        nonce = long_to_bytes(random.getrandbits(8*8)).hex()
    plain , nonce = bytes.fromhex(plaintext) , bytes.fromhex(nonce)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plain)
    return ciphertext.hex()


def menu():
    print("1. encrypt message")
    print("2. get flag")
    option = input("> ")
    return option


def main():
    init()
    while True :
        choice = menu()
        if choice == '1':
            plain = input('enter your plaintext(hex) : ')
            nonce = None if not (nonce := input('enter your nonce(hex) :')) else nonce
            print(encrypt_plain(plain , nonce) ) 
        elif choice == '2':
            print(encrypt_plain(FLAG.hex()))
        else:
            pass

if __name__ == '__main__':
    main()

