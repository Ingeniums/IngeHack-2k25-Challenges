
import sys
if len(sys.argv) != 3:
    print("Usage: sage coppersmith.sage <n> <p_known>")
    sys.exit(1)

n = int(sys.argv[1])
known_p = int(sys.argv[2])

P.<x> = PolynomialRing(Zmod(n))
f = known_p+x 
found_p = f.small_roots(X=2^128, beta=128/1024)[0]
p = known_p + (found_p)
q = int(n)//int(p)

print((int(p) , int(q)))