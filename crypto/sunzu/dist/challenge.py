from Crypto.Util.number import * 


flag  =  open('flag.txt' , 'rb').read()

keys = [getPrime(1024) for _ in range(6)]
n_s = [ keys[i] * keys[i+1] for i in range(0 , 6 , 2)]
e = 3

c_s = [ pow(bytes_to_long(flag) , e , n_s[i]) for i in range(3)]


with open('out.txt' , 'w') as f :
    f.write(f"n_s = {n_s}\n")
    f.write(f"c_s = {c_s}")


