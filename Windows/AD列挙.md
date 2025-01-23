# AD 列挙

## runas

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

## GUI

リモート サーバー管理ツール(RSAT)  
アプリと機能から RSAT をインストールできる。

runas で起動したプロンプトから、rsat を起動。  
あとは GUI での操作。

```ps
mmc
```

## コマンドプロンプト

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

## Powershell

コマンドプロンプトより監視されている可能性は高いことに注意

https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

```ps
# ユーザーの詳細情報
Get-ADUser -Identity <username> -Server za.tryhackme.com -Properties *

# フォーマット例
Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

# グループの列挙
Get-ADGroup -Identity Administrators -Server za.tryhackme.com

# グループメンバーシップ
Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com

# 特定の日付以降
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)

Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com

# badPwdCount が 1 より大きいアカウント
Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com

# ドメイン
Get-ADDomain -Server za.tryhackme.com

# パスワード変更
Set-ADAccountPassword -Identity <username> -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

## Bloodhound

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
