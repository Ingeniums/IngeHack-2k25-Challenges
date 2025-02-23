#!/usr/local/bin/python

import os
import hashlib
from functools import reduce


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


secret = os.urandom(16)

target = hashlib.sha256(secret).digest()
print(target.hex())

hashes = set()

while True:
    s = input("Enter a payload as hex (q to exit): ")

    if s == "q":
        break

    try:
        s = bytes.fromhex(s)
    except:
        print("invalid hex string")
        continue

    if len(s) == 0:
        print("empty payload")
        continue

    hash = hashlib.sha256(secret + s).digest()
    hashes.add(hash)


if len(hashes) > 0:
    result = reduce(xor, hashes)

    if result == target:
        with open("flag.txt") as f:
            print(f.read())
