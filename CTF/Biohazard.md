# Biohazard CTF

https://tryhackme.com/room/biohazard

## Enumeration

```shell
TARGET=10.201.12.251
sudo bash -c "echo $TARGET   biohazard.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### FTP

Anonymousログインは不可。

## HTTP

### /mansionmain

```html
<!-- It is in the /diningRoom/ -->
```

### /diningRoom

```html
<!-- SG93IGFib3V0IHRoZSAvdGVhUm9vbS8= -->
```

```sh
$ echo 'SG93IGFib3V0IHRoZSAvdGVhUm9vbS8=' | base64 -d            
How about the /teaRoom/
```

/diningRoom/emblem.php

```
emblem{[REDACTED]}

Look like you can put something on the emblem slot, refresh /diningRoom/
```

### /teaRoom

/teaRoom/master_of_unlock.html

```
lock_pick{[REDACTED]}
```

### /artRoom

/artRoom/MansionMap.html

```
Look like a map

Location:
/diningRoom/
/teaRoom/
/artRoom/
/barRoom/
/diningRoom2F/
/tigerStatusRoom/
/galleryRoom/
/studyRoom/
/armorRoom/
/attic/
```

### /barRoom

```
Look like a music note

NV2XG2LDL5ZWQZL[REDACTED]
```

base32でデコード

/barRoom357162e3db904857963e6e0b64b96ba7/barRoomHidden.php

/barRoom357162e3db904857963e6e0b64b96ba7/gold_emblem.php

```
gold_emblem{[REDACTED]}

Look like you can put something on the emblem slot, refresh the previous page
```

1つ前に戻って、`emblem{[REDACTED]}` を入力

```
rebecca
```

### /diningRoom2F/

```html
<!-- Lbh trg gur oyhr trz ol chfuvat gur fgnghf gb gur ybjre sybbe. Gur trz vf ba gur qvavatEbbz svefg sybbe. Ivfvg fnccuver.ugzy -->  
```

ROT13

```
You get the blue gem by pushing the status to the lower floor. The gem is on the diningRoom first floor. Visit sapphire.html
```

### /diningRoom

`gold_emblem{[REDACTED]}` を入れる。

```
klfvg ks r wimgnd biz mpuiui ulg fiemok tqod. Xii jvmc tbkg ks tempgf tyi_hvgct_jljinf_kvc
```

Vigenere Cipher。rebeccaをパスワードとしても、きれいに復号できない。

```
3here is a shield tey inside the diwing roov. The htmu page is called the_great_2hield_ke8
```

/diningRoom/the_great_shield_key.html としてアクセス。

```
shield_key{[REDACTED]}
```

/diningRoom/sapphire.html

```
blue_jewel{[REDACTED]}
```

### /tigerStatusRoom/

`blue_jewel{[REDACTED]}` を入れる。

```
crest 1:
[REDACTED]
Hint 1: Crest 1 has been encoded twice
Hint 2: Crest 1 contanis 14 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

base64, base32 デコード

### /galleryRoom/note.txt

```
crest 2:
[REDACTED]
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 18 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

base32, base58 デコード

### /studyRoom/

helmet のキー不明。

### /armorRoom/

`shield_key{[REDACTED]}` を入れる。

```
crest 3:
[REDACTED]
Hint 1: Crest 3 has been encoded three times
Hint 2: Crest 3 contanis 19 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

### /attic/

`shield_key{[REDACTED]}` を入れる。

```
crest 4:
[REDACTED]
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 17 characters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```

全部合わせてBase64デコードすると、FTPユーザーとパスワードが出てくる。

```
$ echo [REDACTED] | base64 -d
FTP user: [REDACTED], FTP pass: [REDACTED]
```

### FTP2

FTPで全ファイルダウンロード。helmetがここに出てきた。

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||39037|)
150 Here comes the directory listing.
drwxrwxrwx    2 1002     1002         4096 Sep 20  2019 .
drwxrwxrwx    2 1002     1002         4096 Sep 20  2019 ..
-rw-r--r--    1 0        0            7994 Sep 19  2019 001-key.jpg
-rw-r--r--    1 0        0            2210 Sep 19  2019 002-key.jpg
-rw-r--r--    1 0        0            2146 Sep 19  2019 003-key.jpg
-rw-r--r--    1 0        0             121 Sep 19  2019 helmet_key.txt.gpg
-rw-r--r--    1 0        0             170 Sep 20  2019 important.txt
```

```sh
$ cat important.txt 
Jill,

I think the helmet key is inside the text file, but I have no clue on decrypting stuff. Also, I come across a /hidden_closet/ door but it was locked.

From,
Barry
```

#### key1

```sh
$ stegseek ./001-key.jpg                                                        
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "key-001.txt".
[i] Extracting to "001-key.jpg.out".

$ cat 001-key.jpg.out 
[REDACTED]
```

#### key2

```sh
$ exiftool ./002-key.jpg
...
Comment                         : [REDACTED]
```

#### key3

```sh
$ binwalk -Me ./003-key.jpg 

Scan Time:     2025-10-20 10:38:56
Target File:   /home/kali/ctf/bio/003-key.jpg
MD5 Checksum:  5c407556b6956ba74cda5ce98f8acf08
Signatures:    436

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1930          0x78A           Zip archive data, at least v2.0 to extract, uncompressed size: 14, name: key-003.txt

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented


Scan Time:     2025-10-20 10:38:56
Target File:   /home/kali/ctf/bio/_003-key.jpg.extracted/key-003.txt
MD5 Checksum:  64898577b7faba946a96cbcd702db862
Signatures:    436

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

$ ls -al _003-key.jpg.extracted                          
total 16
drwxrwxr-x 2 kali kali 4096 Oct 20 10:38 .
drwxrwxr-x 3 kali kali 4096 Oct 20 10:38 ..
-rw-rw-r-- 1 kali kali  216 Oct 20 10:38 78A.zip
-rw-r--r-- 1 kali kali   14 Sep 19  2019 key-003.txt

$ cat _003-key.jpg.extracted/key-003.txt                  
[REDACTED]
```

3つを結合してBase64デコードすると、パスワードになる。

パスワードを使ってgpgファイルを復号。

```sh
$ gpg --decrypt-files ./helmet_key.txt.gpg 
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase

$ cat ./helmet_key.txt                  
helmet_key{[REDACTED]}
```

### /hidden_closet

```
wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk
```

これが近いと思われるが、正確なパスワードが分からない。

```
ALBERX	weastar logis pass6trd, staws_membar2_are_ry_guiwaa_yig
```

SSHパスワード

```
SSH password: [REDACTED]
```

### /studyRoom

SSHユーザー

```sh
$ tar -zxvf ./doom.tar.gz 
eagle_medal.txt

$ cat eagle_medal.txt       
SSH user: [REDACTED]
```

## SSH

```sh
umbrella_guest@umbrella_corp:~$ ls -al .jailcell/
total 12
drwxr-xr-x 2 umbrella_guest umbrella 4096 Sep 20  2019 .
drwxr-xr-x 8 umbrella_guest umbrella 4096 Sep 20  2019 ..
-rw-r--r-- 1 umbrella_guest umbrella  501 Sep 20  2019 chris.txt
```

```sh
umbrella_guest@umbrella_corp:~$ cat .jailcell/chris.txt 
Jill: Chris, is that you?
Chris: Jill, you finally come. I was locked in the Jail cell for a while. It seem that weasker is behind all this.
Jil, What? Weasker? He is the traitor?
Chris: Yes, Jill. Unfortunately, he play us like a damn fiddle.
Jill: Let's get out of here first, I have contact brad for helicopter support.
Chris: Thanks Jill, here, take this MO Disk 2 with you. It look like the key to decipher something.
Jill: Alright, I will deal with him later.
Chris: see ya.

MO disk 2: albert
```

```sh
umbrella_guest@umbrella_corp:~$ ls -al ../hunter/
total 36
drwxr-xr-x 4 hunter hunter 4096 Sep 19  2019 .
drwxr-xr-x 5 root   root   4096 Sep 20  2019 ..
-rw-r--r-- 1 hunter hunter  220 Sep 19  2019 .bash_logout
-rw-r--r-- 1 hunter hunter 3771 Sep 19  2019 .bashrc
drwxr-xr-x 3 hunter hunter 4096 Sep 19  2019 .config
drwxrwxrwx 2 hunter hunter 4096 Sep 20  2019 FTP
-rw-r--r-- 1 hunter hunter  807 Sep 19  2019 .profile
-rw-r--r-- 1 hunter hunter 1600 Sep 19  2019 .Xdefaults
-rw-r--r-- 1 hunter hunter   14 Sep 19  2019 .xscreensaver

umbrella_guest@umbrella_corp:~$ ls -al ../weasker/
total 80
drwxr-xr-x  9 weasker weasker 4096 Sep 20  2019 .
drwxr-xr-x  5 root    root    4096 Sep 20  2019 ..
-rw-------  1 weasker weasker   18 Sep 20  2019 .bash_history
-rw-r--r--  1 weasker weasker  220 Sep 18  2019 .bash_logout
-rw-r--r--  1 weasker weasker 3771 Sep 18  2019 .bashrc
drwxrwxr-x 10 weasker weasker 4096 Sep 20  2019 .cache
drwxr-xr-x 11 weasker weasker 4096 Sep 20  2019 .config
drwxr-xr-x  2 weasker weasker 4096 Sep 19  2019 Desktop
drwx------  3 weasker weasker 4096 Sep 19  2019 .gnupg
-rw-------  1 weasker weasker  346 Sep 20  2019 .ICEauthority
drwxr-xr-x  3 weasker weasker 4096 Sep 19  2019 .local
drwx------  5 weasker weasker 4096 Sep 19  2019 .mozilla
-rw-r--r--  1 weasker weasker  807 Sep 18  2019 .profile
drwx------  2 weasker weasker 4096 Sep 19  2019 .ssh
-rw-r--r--  1 weasker weasker    0 Sep 20  2019 .sudo_as_admin_successful
-rw-r--r--  1 root    root     534 Sep 20  2019 weasker_note.txt
-rw-------  1 weasker weasker  109 Sep 20  2019 .Xauthority
-rw-------  1 weasker weasker 5548 Sep 20  2019 .xsession-errors
-rw-------  1 weasker weasker 6749 Sep 20  2019 .xsession-errors.old
```

```sh
umbrella_guest@umbrella_corp:/home/weasker$ cat ./weasker_note.txt 
Weaker: Finally, you are here, Jill.
Jill: Weasker! stop it, You are destroying the  mankind.
Weasker: Destroying the mankind? How about creating a 'new' mankind. A world, only the strong can survive.
Jill: This is insane.
Weasker: Let me show you the ultimate lifeform, the Tyrant.

(Tyrant jump out and kill Weasker instantly)
(Jill able to stun the tyrant will a few powerful magnum round)

Alarm: Warning! warning! Self-detruct sequence has been activated. All personal, please evacuate immediately. (Repeat)
Jill: Poor bastard
```

この解読が必要。

```
wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk
```

albertがキーのようだが、きれいに復号できない。

```
weaster logiw pass6xrd, sta1s_member2_are_vy_guiwea_yig
```

https://cryptii.com/pipes/vigenere-cipher で復号するとうまくいった。なぜ・・・？

```
weasker login password, [REDACTED]
```

## 権限昇格

```sh
weasker@umbrella_corp:/home/umbrella_guest$ sudo -l
[sudo] password for weasker: 
Matching Defaults entries for weasker on umbrella_corp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weasker may run the following commands on umbrella_corp:
    (ALL : ALL) ALL
```

```sh
weasker@umbrella_corp:/home/umbrella_guest$ sudo bash -p
root@umbrella_corp:/home/umbrella_guest# id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
root@umbrella_corp:/home/umbrella_guest# cat /root/root.txt
In the state of emergency, Jill, Barry and Chris are reaching the helipad and awaiting for the helicopter support.

Suddenly, the Tyrant jump out from nowhere. After a tough fight, brad, throw a rocket launcher on the helipad. Without thinking twice, Jill pick up the launcher and fire at the Tyrant.

The Tyrant shredded into pieces and the Mansion was blowed. The survivor able to escape with the helicopter and prepare for their next fight.

The End

flag: [REDACTED]
```

## 振り返り

- 技術的に学べることはあまりなかったものの、非常に面白かった。vigenere暗号については新しい知見が得られてよかった。
- vigenere暗号で、  
https://www.dcode.fr/vigenere-cipher ではうまくいかず  
https://cryptii.com/pipes/vigenere-cipher で復号するとうまくいったのは何故か？

→ アルファベットから数字を削除し、「ABCDEFGHIJKLMNOPQRSTUVWXYZ」にすると同じ結果になった。
