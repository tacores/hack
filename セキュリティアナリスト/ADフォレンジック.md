# ADフォレンジック

## ユーザーアカウント

https://tryhackme.com/room/windowsuseraccountforensics

[DSInternals](https://github.com/MichaelGrafnetter/DSInternals)

```ps
# NTDS.ditファイルとSYSTEMハイブをエクスポート
ntdsutil.exe "activate instance ntds" "ifm" "create full C:\Exports" quit quit

# ブートキー取得
$bootKey = Get-BootKey -SystemHivePath 'C:\Exports\registry\SYSTEM'

Get-ADDBAccount -All -DBPath 'C:\Exports\Active Directory\NTDS.dit' -BootKey $bootKey
```