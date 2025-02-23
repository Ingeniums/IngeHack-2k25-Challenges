from Pwn4Sage.pwn import remote
from sage.all import crt, discrete_log, EllipticCurve, factor, GF
from Crypto.Util.number import long_to_bytes as lb

p = 1942668892225729070919461906823518906642406839052139521251812409738904285205208498723
F = GF(p)

a1 = F(0)
a2 = F(560069405746973935236942 // 2)  
a3 = F(310558460761504284968136)
a4 = F(485862889966917787468710)

def get(a6):
    curve = EllipticCurve(F, [a1, a2, a3, a4, F(a6)])
    order = curve.order()
    factors = factor(order)
    G = curve.gens()[0]
    conn = remote('localhost', 13002)
    conn.recvuntil(b'Your Point:')
    conn.sendline(str(G.xy()).encode())
    conn.recvuntil(b'result: ')
    P = eval(conn.recvline().decode())
    conn.close()
    
    return order, G, factors, curve(P)

def mini_pohling(P, G, order, factors_subset, moduli, dlogs):
    for prime, exponent in factors_subset:
        modulus = prime ** exponent
        t = order // modulus
        dlog = discrete_log(t * P, t * G, operation='+')
        moduli.append(modulus)
        dlogs.append(dlog)

order0, G0, factors0, P0 = get(1)
order1, G1, factors1, P1 = get(4)
order2, G2, factors2, P2 = get(5)
order3, G3, factors3, P3 = get(52)
order4, G4, factors4, P4 = get(21)

cleaned = [
    (factors0[:-2], order0, P0, G0),
    (factors1[:2] + factors1[3:-2], order1, P1, G1),
    (factors2[1:-3], order2, P2, G2),
    (factors3[2:-2], order3, P3, G3),
    (factors4[1:-2], order4, P4, G4),
]
moduli = []
dlogs = []

for factors_subset, order, point, G in cleaned:
    mini_pohling(point, G, order, factors_subset, moduli, dlogs)
flag = crt(dlogs, moduli)
print(lb(flag).decode())

