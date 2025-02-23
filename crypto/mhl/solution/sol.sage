
from Crypto.Util.number import inverse as inv , long_to_bytes as lb


B = 2^190
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

out =  open('../dist/out.txt' , 'r').readlines()

msgs = eval(out[0].split('=')[1])
sigs = eval(out[1].split('=')[1])

r1s = [sig[0] for sig in sigs] 
r2s = [sig[1] for sig in sigs] 
ss =  [sig[2] for sig in sigs] 

depth = len(ss)
ts , a_s = [] , []

for i in range(depth) :
    ts.append( r2s[i] * inv(ss[i],n) )
    a_s.append( inv(ss[i],n) * r1s[i] * msgs[i])

tn , an = ts.pop(), a_s.pop()
tmsb , amsb = [] , []

for t  , a in zip(ts,a_s) :
    tmsb.append((t-tn)%n)
    amsb.append((a-an)%n)


matrix = [[0]*i + [n] + [0]*(depth-1-i+1) for i in range(depth-1)]
matrix.append(tmsb+[ B/n, 0])
matrix.append(amsb+[0,B])

M = Matrix(QQ , matrix)
out = M.LLL()

print(int(B).bit_length())

#get d from Bd/n
for row in out:
    if row[-1] == B:
        potential_nonce_diff = row[0]
        d = ((QQ((row[-2])) * n) / B) % n
        print(lb(int(d)))


# get d from (k0-kn)
for row in out:
    if row[-1] == B :
        diff = row[0]%n
        diff -= (a_s[0] - an)%n
        d = Integer(diff) * Integer(inv(ts[0] - tn , n)) 
        print(lb(int(d%n)))