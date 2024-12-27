# Active Directory

##

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
