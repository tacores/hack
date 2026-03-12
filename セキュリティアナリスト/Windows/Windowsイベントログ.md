# Windows イベントログ

https://tryhackme.com/room/windowseventlogs

## 基本

C:\Windows\System32\winevt\Logs 内に、.evt または .evtx ファイルが保存される。

## ツール

### EventViewer

GUI ツール

### wevtutil

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

```ps
# help
wevtutil.exe /?

# コマンド詳細
wevtutil qe /?

# ログ名をリストして、ログ名の数等を表示
wevtutil el | Measure-Object
```

### Get-WinEvent

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1

```ps
# 全てのログ取得（0件のログも含む）
Get-WinEvent -ListLog *

# イベントログプロバイダーとログ名を取得
Get-WinEvent -ListProvider *

# ログフィルタリング
Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }

# 大規模なログを扱う場合は、パイプより下記の方が効率的
Get-WinEvent -FilterHashtable @{
  LogName='Application'
  ProviderName='WLMS'
}

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'
```

フィルターハッシュテーブルの詳細  
https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable?view=powershell-7.5&viewFallbackFrom=powershell-7.1

## XPath

https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ms256115(v=vs.100)

- XPath イベントクエリは ' \* ' または ' Event ' で始まる。
- wevtutil と Get-WinEvent はどちらもイベント フィルターとして XPath クエリをサポートしている。

### 段階的な構築方法

EventViewer の XML を参照しながら構築すると良い

```ps
# 開始点
Get-WinEvent -LogName Application -FilterXPath '*'

# System は Event の子階層
Get-WinEvent -LogName Application -FilterXPath '*/System/'

# EventID は System の子要素
Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'

# こう書いても同じ結果になる
Get-WinEvent -LogName Application -FilterXPath '*/System[EventID=100]'

# Provider は System の子要素で、その Name 属性でフィルタリング
Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'
```

```ps
# 複数条件の例
Get-WinEvent -LogName Application -FilterXPath ‘*/System/Provider[@Name=”WLMS”] and */System/TimeCreated[@SystemTime=”2020–12–15T01:09:08.940277500Z”]’
```

## ケース別

### リモートデスクトップ

`Applications and Services Logs -> Microsoft -> Windows -> Terminal-Services-RemoteConnectionManager > Operational`

1149: リモートデスクトップ認証成功

### MS Defender

`Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational`

5001: MS Defender リアルタイム保護を無効化

### Firewall

`Applications and Services Logs > Microsoft > Windows > Windows Firewall With Advanced Security > Firewall`

2004: ルール追加  
2006: ルール削除
