from pwn import *
import HashTools


def bytes2bits(data):
    return vector(
        GF(2), sum([list(map(int, format(byte, "08b"))) for byte in data], [])
    )


p = remote("hashes.ctf.ingeniums.club", 1337, ssl=True)
assert p

target = p.recvline().strip().decode()
log.info(f"target: {target}")

magic = HashTools.new("sha256")
assert type(magic) == HashTools.SHA256


vecs = []
data = []

for i in range(10000):
    if len(vecs) == 256:
        break

    new_data, new_sig = magic.extension(
        secret_length=int(16),
        original_data=b"",
        append_data=str(i).encode(),
        signature=target,
    )

    new_sig = bytes.fromhex(new_sig)

    v = bytes2bits(new_sig)

    m = matrix(GF(2), vecs + [v]).transpose()
    if m.rank() == len(vecs) + 1:
        print(f"{new_sig.hex()} is linearly independent")
        data.append(new_data)
        vecs.append(v)

target_vec = bytes2bits(bytes.fromhex(target))

m = matrix(GF(2), vecs).transpose()
solved = m.solve_right(target_vec)

for i, bit in enumerate(solved):
    if bit == 1:
        p.sendline(data[i].hex().encode())

p.sendline(b"q")

p.interactive()
