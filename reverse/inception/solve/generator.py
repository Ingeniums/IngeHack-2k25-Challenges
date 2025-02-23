import random
from enum import Enum

FLAG = b"ingehack{making_this_challenge_was_more_painful_than_solving_it_trust_me}"


class Ops(Enum):
    NOP = 0
    ADD = 1
    SUB = 2
    XOR = 3


print("VM_PUSH(0),")
for c in FLAG:
    ops = [Ops(random.randint(0, len(Ops) - 1)) for _ in range(8)]
    ops_rands = [random.randint(0, 255) for i in range(8) if ops[i] != Ops.NOP]

    for r in ops_rands:
        print(f"VM_PUSH({r}),")

    print("OP_GETCH,")

    for op in ops:
        if op == Ops.ADD:
            print(f"OP_ADD,")
        elif op == Ops.SUB:
            print(f"OP_SUB,")
        elif op == Ops.XOR:
            print(f"OP_XOR,")

    for op, r in zip([o for o in ops if o != Ops.NOP], ops_rands[::-1]):
        if op == Ops.ADD:
            c = (c + r) % 256
        elif op == Ops.SUB:
            c = (c - r) % 256
        elif op == Ops.XOR:
            c = c ^ r
    print(f"VM_PUSH({c}),")
    print("OP_XOR,")
    print("OP_OR,")

print("OP_ASSERT")
