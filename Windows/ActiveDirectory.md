# Active Directory

## 列挙

### ユーザー列挙

```powershell
# 参加しているドメインを表示
systeminfo | findstr Domain

# 全てのADユーザーアカウントを取得
Get-ADUser  -Filter *

# 条件指定
Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"
```

### セキュリティソリューション列挙

#### ウイルス対策

```powershell
# cmd
wmic /namespace:\\root\securitycenter2 path antivirusproduct

# ps
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

#### MS Defender

```ps
# 状態確認
Get-Service WinDefend

Get-MpComputerStatus | select RealTimeProtectionEnabled

# 検出された驚異の詳細を表示する
Get-MpThreat
```

#### ファイアウォール

```ps
# 状態確認
Get-NetFirewallProfile | Format-Table Name, Enabled

# ルールの確認
Get-NetFirewallRule | select DisplayName, Enabled, Description

# 受信接続をテスト
Test-NetConnection -ComputerName 127.0.0.1 -Port 80

# 無効にする（要管理者）
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
```

#### イベントログ

```ps
# 使用可能なイベントログ一覧
Get-EventLog -List

# sysmon が使用されているか？（プロセス）
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
# サービス
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
# レジストリ
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
# sysmon構成ファイルの検索
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
```

#### EDR (Endpoint Detection and Response) 製品の列挙

https://github.com/PwnDexter/Invoke-EDRChecker
https://github.com/PwnDexter/SharpEDRChecker

### その他アプリケーション

```ps
# インストールされている全アプリケーションとバージョン
wmic product get name,version

# 隠しアイテムの検索
Get-ChildItem -Hidden -Path C:\Users\kkidd\Desktop\
```

### サービス

```ps
# 実行中サービス一覧
net start

# サービス詳細情報（実行ファイルのパス等）
wmic service where "name like 'THM Demo'" get Name,PathName

# プロセス表示
Get-Process -Name thm-demo

# プロセスのリスニングポート一覧（プロセスID指定）
netstat -noa |findstr "LISTENING" |findstr "3212"
```

### GPO

```powershell
# GPO一覧
Get-GPO -All

# GPO情報をHTML出力
Get-GPOReport -Name "SetWallpaper" -ReportType HTML -Path ".\SetWallpaper.html"

# 最近変更されたGPO
Get-GPO -All | Where-Object { $_.ModificationTime } | Select-Object DisplayName, ModificationTime
```

### ユーザー監査

```powershell
# ロックされたアカウント
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut, LastLogonDate, DistinguishedName

# 全てのユーザーとそのグループを一覧表示
Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, SamAccountName, @{Name="Groups";Expression={$_.MemberOf}}
```
