from pwn import *

import ctypes
import itertools
import math


def encrypt(plaintext, key):
    if not plaintext:
        return ""

    v = _str2vec(plaintext)
    k = _str2vec(key[:16])

    bytearray = b"".join(_vec2str(_encipher(chunk, k)) for chunk in _chunks(v, 2))

    return bytearray


def decrypt(ciphertext, key):
    if not ciphertext:
        return ""

    k = _str2vec(key[:16])
    v = _str2vec(ciphertext)

    return b"".join(_vec2str(_decipher(chunk, k)) for chunk in _chunks(v, 2))


def _encipher(v, k):
    y, z = [ctypes.c_uint32(x) for x in v]
    sum = ctypes.c_uint32(0)
    delta = 0x9E3779B9

    for _ in range(32, 0, -1):
        sum.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]

    return [y.value, z.value]


def _decipher(v, k):
    y, z = [ctypes.c_uint32(x) for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for _ in range(32, 0, -1):
        z.value -= (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        sum.value -= delta

    return [y.value, z.value]


def _chunks(iterable, n):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


def _str2vec(value, l=4):
    n = len(value)

    # Split the string into chunks
    num_chunks = math.ceil(n / l)
    chunks = [value[l * i : l * (i + 1)] for i in range(num_chunks)]

    return [
        sum([character << 8 * j for j, character in enumerate(chunk)])
        for chunk in chunks
    ]


def _vec2str(vector, l=4):
    return bytes(
        (element >> 8 * i) & 0xFF for element in vector for i in range(l)
    ).replace(b"\x00", b"")


key = b"".join(p32(x) for x in [0xBABAB01, 0xCAFEBABE, 0xDEADBEEF, 0x12344321])

enc = [
    0xC90C664,
    0xBE5424AB,
    0x69098A34,
    0x771E526D,
    0x6EBB4C7C,
    0x9835011E,
    0xB69C60E0,
    0xC749896F,
    0xD494438A,
    0xD26DAA41,
    0x8AB2B4C4,
    0xD7818B8D,
    0x70E4EE31,
    0x7DBBABA,
    0x8928EA5,
    0x7E402D6B,
    0x79C35BBA,
    0x23A9D90E,
    0x44F84739,
    0x9977E1AD,
]

enc = [p32(enc[i]) + p32(enc[i + 1]) for i in range(0, len(enc), 2)]

for x in enc:
    print(decrypt(x, key).decode(), end="")
