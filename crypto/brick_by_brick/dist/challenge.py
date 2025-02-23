from Crypto.Util.number import getPrime, bytes_to_long

FLAG = bytes_to_long(b"fake_flag_lol")

p = getPrime(512)
q = getPrime(512)
n = p * q

phi = (p - 1) * (q - 1)

e = 0x10001
d = pow(e, -1, phi)


def powmod(base, exponent, mod):
    result = 1
    base = base % mod

    leak = []

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % mod
            leak.append(120)

        base = (base * base) % mod
        leak.append(50)
        exponent //= 2

    return result, leak


enc, _ = powmod(FLAG, e, n)

dec, leak = powmod(enc, d, n)

assert dec == FLAG

print(f"{n = }")
print(f"{e = }")
print(f"{enc = }")
print(f"{leak = }")
