# Flip CTF

https://tryhackme.com/room/flip

```text
The server is listening on port 1337 via TCP. You can connect to it using Netcat or any other tool you prefer.
```

## 添付コード

```python
import socketserver
import socket, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from binascii import unhexlify

flag = open('flag','r').read().strip()

def encrypt_data(data,key,iv):
    padded = pad(data.encode(),16,style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC,iv)
    enc = cipher.encrypt(padded)
    return enc.hex()

def decrypt_data(encryptedParams,key,iv):
    cipher = AES.new(key, AES.MODE_CBC,iv)
    paddedParams = cipher.decrypt( unhexlify(encryptedParams))
    if b'admin&password=sUp3rPaSs1' in unpad(paddedParams,16,style='pkcs7'):
        return 1
    else:
        return 0

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server,username,password,key,iv):
        message = 'access_username=' + username +'&password=' + password
        send_message(server, "Leaked ciphertext: " + encrypt_data(message,key,iv)+'\n')
        send_message(server,"enter ciphertext: ")

        enc_message = server.recv(4096).decode().strip()

        try:
                check = decrypt_data(enc_message,key,iv)
        except Exception as e:
                send_message(server, str(e) + '\n')
                server.close()

        if check:
                send_message(server, 'No way! You got it!\nA nice flag for you: '+ flag)
                server.close()
        else:
                send_message(server, 'Flip off!')
                server.close()

def start(server):
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        send_message(server, 'Welcome! Please login as the admin!\n')
        send_message(server, 'username: ')
        username = server.recv(4096).decode().strip()

        send_message(server, username +"'s password: ")
        password = server.recv(4096).decode().strip()

        message = 'access_username=' + username +'&password=' + password

        if "admin&password=sUp3rPaSs1" in message:
            send_message(server, 'Not that easy :)\nGoodbye!\n')
        else:
            setup(server,username,password,key,iv)

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

## 静的解析

- まずユーザー名とパスワードを入力。「access_username=USER&password=PW」文字列が pkcs7 パディングされ、暗号化された後に hex 表示される。
- 次に暗号文字列を入力。復号化後の文字列をアンパディングし、「admin&password=sUp3rPaSs1」が含まれていたらクリア。
- 暗号化の 16 バイトキーと、 16 バイト iv が ランダムに生成される。

### pkcs7 パディング

- 16 バイトの倍数にそろえる。
- 16 バイトの倍数でない場合、足りないバイト数 N に応じて N バイトの N の値（0xNN）を追加する。
- 16 バイトの倍数の場合、16 バイトの 0x10（16） を追加する。

目的の文字列は "access_username=admin&password=sUp3rPaSs1" だが、これは 41 バイトなので、足りない 7 バイトが追加され、b'access_username=admin&password=sUp3rPaSs1\x77\x77\x77\x77\x77\x77\x77' これが暗号化される形となる。

### 暗号の特性

- 16 バイトのブロックごとに暗号化される。キーと iv を固定すれば、暗号結果の最初の 16 バイト（「access_username=」に対応する部分）は不変になる。
- 同じ 16 バイトのブロックでも、位置が変われば暗号結果も変わる。
- 16 バイトのうち 1 バイトでも変われば、暗号結果は全く別にものになる。

## ビットフリッピング攻撃

https://younestasra-r4z3rsw0rd.github.io/posts/Flip/

AES-CBC 暗号化方式では、  
最初の 16 バイトと iv の XOR を取り、それとキーを使い暗号文の最初の 16 バイトとする。  
その暗号文 16 バイトと、次の 16 バイトの XOR を取り、・・・という処理を繰り返す。

つまり、暗号文の最初の 1 バイトを操作することで、17 文字目に影響を与えることが可能になる。

```shell
$ nc 10.10.134.19 1337
Welcome! Please login as the admin!
username: bdmin&password=sUp3rPaSs1
bdmin&password=sUp3rPaSs1's password: pw
Leaked ciphertext: 5d58c823ca5d3f8492482f620b987b8b31cb04701f78e73fcf8cb32e8cf85d186da4c2187a6f54d9dbadc439fbf7e3abcf262875625ae9371e098e0814ddd731
enter ciphertext: 5e58c823ca5d3f8492482f620b987b8b31cb04701f78e73fcf8cb32e8cf85d186da4c2187a6f54d9dbadc439fbf7e3abcf262875625ae9371e098e0814ddd731
No way! You got it!
A nice flag for you: THM{Fl.....}
```

## 振り返り

- 難解。知らなければ考えて分かるものではなかった。
- AES-CBC にはビットフリッピング攻撃の脆弱性があることは覚えておく必要がある。

### 整理

```text
復号時のプレーンテキスト P は、次のように求められる。

𝑃 = AES_Decrypt(𝐶) ⊕ 𝐶prev

ここで：
C は現在のブロックの暗号文
C_prev は前のブロックの暗号文（またはIV）
AES_Decrypt(C) はブロック単位のAES復号結果（中間状態の P'）

復号した後にXORを取る、という点が肝要。

変更前：
C_prev[2] = 0x64 (d)
P'[17] ⊕ 0x64 = 0x62（b）

変更後：
C_prev[2] = 0x65 (e)
P'[17] ⊕ 0x65 = 0x61（a）
```

ただ、0x65 の数学的な導出方法が分からない。代数的に解こうとすると 0x67 になる。  
感覚的には、b の最右ビットを 1 から 0 に変えればよいから、XOR マスクである d に 1 を足した e にするのは理解できるのだが。
