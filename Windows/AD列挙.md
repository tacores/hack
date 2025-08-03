# AD 列挙

https://tryhackme.com/room/adbasicenumeration

## 認証なしの列挙

### ネットワークマッピング

#### ホスト検出

```shell
fping -agq 10.211.11.0/24
```

### nmap

```shell
# Kerberos, PRC, 従来のSMB, LDAP, 最新のSMB, kpasswd
nmap -p 88,135,139,389,445 -sV -sC -iL hosts.txt

# フルポート
nmap -sS -p- -T3 -iL hosts.txt -oN full_port_scan.txt
```

### SMB 列挙

```sh
# 列挙（-N : NoPassword）
smbclient -L //10.211.11.10 -N

# 接続
smbclient //10.211.11.10/SharedFiles -N

# 多彩な情報
enum4linux -a TARGET_IP > enum4linux.txt

# RIDサイクリングによるユーザー名列挙
msfconsole -q -x "use scanner/smb/smb_lookupsid; set rhosts $TARGET; set SMBUser Guest; set SMBPass ''; set THREADS 10; run; exit;"
```

### ドメイン列挙

```sh
# LDAP列挙
# -x: シンプルな認証。この場合は匿名認証。
# -H: LDAP サーバーを指定。
# -s: クエリを基本オブジェクトのみに制限し、サブツリーや子オブジェクトは検索しない。
ldapsearch -x -H ldap://$TARGET -s base
```

```sh
# ユーザー情報照会
ldapsearch -x -H ldap://$TARGET -b "dc=tryhackme,dc=loc" "(objectClass=person)"
```

```sh
ldapsearch -x -H ldap://$TARGET -s base -b "" namingContexts

ldapsearch -x -H ldap://$TARGET -b "dc=eu-west-1,dc=compute,dc=internal" -s sub "(objectClass=*)"

ldapwhoami -x -H ldap://$TARGET -D "cn=admin,dc=eu-west-1,dc=compute,dc=internal" -w ""

ldapsearch -x -H ldap://$TARGET -b "cn=admin,dc=eu-west-1,dc=compute,dc=internal" -s base "objectClass=*" userPassword
```

```sh
# 可能な限り多くの情報を取得
enum4linux-ng -A $TARGET -oA results.txt
```

```sh
# RPC列挙（Nullセッション）
rpcclient -U "" $TARGET -N

> enumdomusers
> help
```

```sh
# RIDサイクリング
for i in $(seq 500 2000); do echo "queryuser $i" |rpcclient -U "" -N $TARGET 2>/dev/null | grep -i "User Name"; done
```

```sh
# RIDからユーザー名
enum4linux -R 1000-1003 $TARGET
```

```sh
# Kerbruteによるユーザー名の列挙（有効なユーザー名かどうか表示される）
kerbrute userenum --dc $TARGET -d tryhackme.loc users.txt
```

https://github.com/ropnop/kerbrute/releases

### パスワードスプレー

```sh
# パスワードポリシーの照会
rpcclient -U "" $TARGET -N
rpcclient $> getdompwinfo
```

```sh
# パスワードポリシーの照会
crackmapexec smb $TARGET --pass-pol
```

```sh
# パスワードスプレー攻撃
crackmapexec smb $TARGET -u users.txt -p passwords.txt
```

```sh
# ユーザー名=パスワードのパターンを検出
crackmapexec smb $TARGET -u ./names.txt -p ./names.txt --no-bruteforce 
```

## 認証ありの列挙

### runas

ドメイン名、ユーザー名、パスワードを知っているが、ドメインに参加している PC には直接ログインできないとする。

資格情報をメモリに挿入する。  
/netonly のため、資格情報はドメイン コントローラによって直接検証されず、任意のパスワードが受け入れられることに注意

```ps
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

DNS を構成する

```ps
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip

# DNSが機能しているか確認
nslookup za.tryhackme.com
```

資格情報が正しいか確認。  
ホスト名指定すると Kerberos 認証になる。IP を指定すると NTLM 認証を強制することができ、NTLM 認証の方がステルス性が高い。

```ps
dir \\za.tryhackme.com\SYSVOL\
```

### GUI

リモート サーバー管理ツール(RSAT)  
アプリと機能から RSAT をインストールできる。

runas で起動したプロンプトから、rsat を起動。  
あとは GUI での操作。

```ps
mmc
```

### コマンドプロンプト

ドメインに参加しているマシンから実行する必要がある。

https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems

```shell
# ドメイン内の全ユーザーを列挙
net user /domain

# ユーザーの詳細情報
net user <username> /domain

# ドメインのグループを列挙
net group /domain

# グループのメンバーシップ詳細
net group "Tier 1 Admins" /domain

# パスワードポリシー
net accounts /domain
```

### Powershell

コマンドプロンプトより監視されている可能性は高いことに注意

https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

```ps
# ユーザーの詳細情報
Get-ADUser -Identity <username> -Properties *

# フォーマット例
Get-ADUser -Filter 'Name -like "*stevens"' | Format-Table Name,SamAccountName -A

# グループの列挙
Get-ADGroup -Identity Administrators

# グループメンバーシップ
Get-ADGroupMember -Identity Administrators

# 特定の日付以降
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)

Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects

# badPwdCount が 1 より大きいアカウント
Get-ADObject -Filter 'badPwdCount -gt 0'

# ドメイン
Get-ADDomain

# パスワード変更
Set-ADAccountPassword -Identity <username> -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

### BadSuccessor

https://tryhackme.com/room/adbadsuccessor

https://github.com/akamai/BadSuccessor (script)

```ps
# dMSA を作成できるアカウントを特定
# "CreateChild|GenericAll|WriteDACL|WriteOwner"
.\Get-BadSuccessorOUPermissions.ps1
```

エクスプロイト方法は、横方向移動を参照。

### Bloodhound

https://github.com/BloodHoundAD/BloodHound

SharpHound で列挙し、Bloodhound でグラフ化する。

SharpHound 列挙は大量のイベントログを生成するため、初回は All、次回以降はセッションのみといった運用が必要。セッションは頻繁に列挙しなおす必要がある。

```ps
# 全部列挙
# アウトプットとして zipファイルが作成される
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

# セッションだけ
SharpHound.exe --CollectionMethods Session --Domain za.tryhackme.com --ExcludeDCs
```

```shell
# kali に zip をコピー
scp <AD Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .
```

Bloodhound には neo4j のインストールが必要。

```shell
sudo neo4j console
```

Bloodhound を起動  
SharpHound のバージョンと一致させる必要がある点に注意。

```shell
bloodhound --no-sandbox
```

GUI に zip ファイルを D&D したらインポートされる。

### PowerView

https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

Powershell の起動とロード

```ps
powershell -ep bypass
. .\PowerView.ps1
```

```ps
# ドメインユーザーの列挙
Get-NetUser | select cn

# ドメイングループの列挙
Get-NetGroup -GroupName *admin*
```

コマンドチートシート
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
