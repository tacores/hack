# Scripting CTF

https://tryhackme.com/room/scripting

## [Easy] Base64

Base64 を50回繰り返した文字列を復号する。

shell

```sh
#!/bin/bash

DEC64=$(cat ./b64.txt)

for i in {1..50} ; do
    DEC64=$(echo "$DEC64" | base64 -d)
done

echo $DEC64
```

python

```python
import base64

with open("b64.txt", "r", encoding="utf-8") as f:
    content = f.read()

for _ in range(50):
    content = base64.b64decode(content).decode()

print(content)
```


## [Medium] Gotta Catch em All

タスク説明を読んでも理解できなかったが、1337ポートから開始する必要がある。

```python
import socket
import time
import re

HOST = '10.10.62.78'    # The remote host
INITIAL_PORT = 1337

def http_get(ip, port, path="/"):
    # HTTPリクエストを作成
    request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"

    # ソケットを作成して接続
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.sendall(request.encode())

        # レスポンスを受信
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

    try:
        header, body = response.split(b"\r\n\r\n", 1)
    except ValueError:
        print(ValueError)
        exit()

    # バイト列を文字列に変換
    return body.decode("utf-8", errors="replace")


next_port = INITIAL_PORT
answer = 0.0
# STOP が出るまで繰り返す
while True:

    print("connnecting port: " + str(next_port))
    while True:
        try:
            res = http_get(HOST, int(next_port))
            print(res)
            break
        except ConnectionRefusedError:
            time.sleep(1)

    if "STOP" in res:
        break

    op, num, next_port = res.split()
    if op == "add":
        answer += float(num)
    elif op == "minus":
        answer -= float(num)
    elif op == "multiply":
        answer *= float(num)
    elif op == "divide":
        answer /= float(num)
    else:
        print("未定義のオペレータ:" + op)
        break
    print(answer)

print("最終結果: " + str(answer))
                                 
```

## [Hard] Encrypted Server Chit Chat

タスク説明が分かりにくいが、次の仕様。

1. hello を送ったら、ready を送れという指示が返る
2. ready を送ったら、key, iv, checksum が返る
3. final を送ったら、暗号化されたフラグが返る。もう一度finalを送ったら、対応するtagが返る。
4. finalを送るたびに異なるフラグが返る。チェックサムが一致するまで繰り返す。

```sh
send : hello
recv : You've connected to the super secret server, send a packet with the payload ready to receive more information
send : ready
recv : key:thisisaverysecretkeyl337 iv:secureivl337 to decrypt and find the flag that has a SHA256 checksum of ]w�▒ҿwx`T�U�Ms��'�΁n�h�]rbc�� send final in the next payload to receive all the encrypted flags
```

```python
import socket
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes
            )
from cryptography.exceptions import InvalidTag

server = ('10.10.156.148', 4000)

def send_recv(s, msg):
    s.sendto(msg, server)
    return s.recv(256)


def decrypt(key, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key),
                   modes.GCM(iv, tag),
                   backend=default_backend()
                   ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

res = send_recv(s, b"ready")
words = res.split(b" ")
key = words[0][4:]
iv = words[1][3:]
checksum = words[14]

print("key: " + key.decode())
print("iv : " + iv.decode())

while True:
    encrypted = send_recv(s, b"final")
    tag = send_recv(s, b"final")

    try:
        plain_bytes = decrypt(key, iv, encrypted, tag)
        print("calculated flag: " + plain_bytes.decode())
    except (ValueError, InvalidTag) as e:
        continue

    calculated = hashlib.sha256(plain_bytes).digest()

    if calculated == checksum:
        print("found a flag! " + plain_bytes.decode())
        break
```
