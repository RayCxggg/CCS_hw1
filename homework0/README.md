# Homework 0: Stack Overflow Exploition

This repository contains the code for Homework 0. It is a simple Stack Overflow Exploition mission.

## Tutorial

Build `example1.c` to executable file:
```
gcc -m32 -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0 -o example1 example1.c
```

This is what the different compile switches do:

- -m32: compile for 32-bit
- -fno-stack-protector: disable stack canaries
- -z execstack: ensure the stack is executable (disable NX bit protection)
- -D_FORTIFY_SOURCE=0: disable FORTIFY_SOURCE

Check the security properties of the output file `example`:
```
checksec --file=example1
```

To disable ASLR:
```
sudo sysctl -w kernel.randomize_va_space=0
```
To renable ASLR:
```
sudo sysctl -w kernel.randomize_va_space=2
```

查看设置情况：
```
cat /proc/sys/kernel/randomize_va_space
```

Build to  generate assembly code output:
```
gcc -S -o example1.s example1.c
```