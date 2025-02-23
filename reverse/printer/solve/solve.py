import numpy as np
import struct

data = open("./enc", "rb").read()

enc = []
for i in range(0, len(data), 16):
    rl, im = struct.unpack("<dd", data[i : i + 16])
    enc.append(np.complex128(rl, im))

dec = np.fft.ifft(enc)

with open("res.png", "wb") as f:
    for v in dec:
        f.write(struct.pack("B", round(v.real)))
