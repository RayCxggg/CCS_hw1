# vul32攻击记录

## 32-bit机器

1字节（byte）= 8 bit
16进制数（0xa）= 4 bit 
16进制数（0xaa）= 8 bit

char = 1 byte
int = 4 byte
32位内存空间 = 4 byte

## 返回地址覆盖

main函数栈：
```
$ebp: 0xffffd108
$esp: 0xffffd104
```

dovuln函数栈：
```
$ebp: 0xffffd0f8
$esp: 0xffffd0b0
```

dovuln()反汇编结果如下，存在漏洞的函数是read()。read()每次向buf中读取1字节，之后填入v3对应的位置，则我们利用v3进行栈溢出。
v3与ebp相距0x43，则v3[43]对应的栈处为ebp，高于ebp 4字节处即为返回地址。即我们应该将跳转地址写入v3[47]，参考dovuln()代码可知，我们将v4的值覆盖为0x47，ASCII对应为'G'。

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

注意到v4低于ebp 0x10，v3低于ebp 0x43，则v4高于v3[0] 0x33。则我们首先填写0x33个'a'，随后覆盖v4为'G'。首先构造一个输入，观察返回地址是否被正确覆盖：

```




## system, /bin/sh地址获取

利用ROPgadget搜索发现，代码中没有`system`和`/bin/sh/`可用，因此我们只能调`libc`中的函数来获取shell。

```
$ ROPgadget --binary vul32 --string '/bin/sh'
Strings information
============================================================

$ ROPgadget --binary vul32 --string 'system'
Strings information
============================================================

```