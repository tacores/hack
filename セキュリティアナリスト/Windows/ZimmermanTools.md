# ZimmermanTools

https://ericzimmerman.github.io/#!index.md

### Timeline Explorer

他のツールで出力した様々な CSV ファイルを時系列で表示する GUI ツール。

### EvtxECmd

Windows イベントログの解析

```ps
# --csvは出力フォルダ、--csvfは出力ファイル名
EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```

```ps
C:\Tools\EvtxECmd\EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx --inc 4624,4625 --csv .
```

```ps
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv "C:\Users\DFIR Analyst" --csvf Logs.csv
```

```ps
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" --csv ..\..\
```

### LECmd

リンクファイルの解析

```shell
# リンクファイルを解析してCSV出力する
.\LECmd.exe -d C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent --csvf Parsed-LNK.csv --csv C:\Users\Administrator\Desktop
```

### PECmd

プリフェッチファイルの解析。無効化されている場合も普通にある。

```shell
.\PECmd.exe -d "C:\Windows\Prefetch" --csv C:\Users\Administrator\Desktop --csvf Prefetch-Parsed.csv
```

### MFTECmd

NTFS ファイルシステム情報抽出

```sh
# MFTファイルから情報抽出（MFTファイルはFTK Imagerでエクスポートできる）
MFTECmd.exe -f ..\Evidence\$MFT --csv ..\Evidence --csvf ..\Evidence\MFT_record.csv

# USNジャーナル
MFTECmd.exe -f ..\Evidence\$J --csv ..\Evidence --csvf USNJrnl.csv

# $I30
MFTECmd.exe -f ..\Evidence\$I30 --csv ..\Evidence\ --csvf i30.csv
```

### Amcache Parser

実行されたがすぐ削除されたファイルは、`UnassociatedFileEntries` に出る可能性がある。

```shell
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv
```

### AppCompatCacheParser

```shell
C:\Tools\AppCompatCacheParser\AppCompatCacheParser.exe --csv .
```

## コマンドラインの詳細を知りたい

```sh
# 出力CSVの EventID=4688 をフィルタ
# CommandLine フィールドを探す
.\EvtxECmd.exe -f "C:\Windows\System32\winevt\Logs\Security.evtx" --csv ..\
```

```sh
.\PECmd.exe -f "C:\Windows\Prefetch\PCD.EXE-*.pf" --csv ..\

.\PECmd.exe -d "C:\Windows\Prefetch" --csv ..\
```

## 機械的実行セット

管理者Powershellで実行。

```ps
#### 変数

# Zimmerman Tools のパス
$EZ = "D:\tools\Get-ZimmermanTools\net9"

# Eventlog
$LOGS = "D:\vmware\share\Artifacts\JP-BROWN-WS\C\Windows\System32\winevt\Logs"

# 解析対象の C ドライブ（マウント済み or 展開済み）
$C  = "D:\vmware\share\Artifacts\JP-BROWN-WS\C"

# 出力先
$OUT = ".\output"
New-Item -ItemType Directory -Force -Path $OUT | Out-Null

#### Registry Explorer（レジストリ全般）
# 永続化・実行痕跡
& "$EZ\RECmd\RECmd.exe" `
  -d "$C" `
  --bn "$EZ\RECmd\BatchExamples\RegistryASEPs.reb" `
  --csv "$OUT\RECmd_ASEPs" `
  --csvf RegistryASEPs.csv
# 実行された可能性のあるバイナリ
& "$EZ\RECmd\RECmd.exe" `
  -d "$C" `
  --bn "$EZ\RECmd\BatchExamples\AllRegExecutablesFoundOrRun.reb" `
  --csv "$OUT\RECmd_Exec" `
  --csvf RegExecutables.csv
# ユーザー行動（横展開・初動）
& "$EZ\RECmd\RECmd.exe" `
  -d "$C" `
  --bn "$EZ\RECmd\BatchExamples\UserActivity.reb" `
  --csv "$OUT\RECmd_UserActivity" `
  --csvf UserActivity.csv

#### Amchache（実行ファイル履歴）
# - 実行された EXE / DLL
# - パス / SHA1 / FirstRunTime
& "$EZ\AmcacheParser.exe" `
  -f "$C\Windows\AppCompat\Programs\Amcache.hve" `
  --csv "$OUT\Amcache"

#### Shimcache (AppCompatCache)
# - 実行“された可能性がある”ファイル
# - 削除済みバイナリが残ることも
& "$EZ\AppCompatCacheParser.exe" `
  -f "$C\Windows\System32\config\SYSTEM" `
  --csv "$OUT\Shimcache"

#### Prefetch（実行痕跡・実行回数）
# - 実行されたプログラム
# - 実行回数 / 最終実行時刻 / ロードDLL
& "$EZ\PECmd.exe" `
  -d "$C\Windows\Prefetch" `
  --csv "$OUT\Prefetch"

#### LNK（ショートカット＝ユーザー操作）
# - ユーザーが開いたファイル
# - 元ファイルのパス / タイムスタンプ / ボリューム情報
& "$EZ\LECmd.exe" `
  -d "$C\Users" `
  --csv "$OUT\LNK"

#### JumpList（アプリ操作履歴）
# - Office / Explorer / アプリの操作履歴
# - 最近開いたファイル
& "$EZ\JLECmd.exe" `
  -d "$C\Users" `
  --csv "$OUT\JumpList"

#### USN Journal（ファイル操作履歴）
# - ファイル作成 / 削除 / リネーム
# - マルウェア展開・痕跡隠蔽の裏取り
& "$EZ\MFTECmd.exe" `
  -f "$C\`$Extend\`$J" `
  --csv "$OUT\USN"
#  -f "$C\`$Extend\`$UsnJrnl:`$J" `

#### MFT（ファイルシステム全体）
# - すべてのファイルのメタデータ
# - 削除ファイル・タイムライン構築
& "$EZ\MFTECmd.exe" `
  -f "$C\`$MFT" `
  --csv "$OUT\MFT"

#### Event Log
$files = @(
  "Security.evtx",
  "System.evtx",
  "Application.evtx",
  "Microsoft-Windows-Sysmon%4Operational.evtx",
  "Microsoft-Windows-PowerShell%4Operational.evtx",
  "Microsoft-Windows-TaskScheduler%4Operational.evtx"
)

foreach ($f in $files) {
  & "$EZ\EvtxECmd\EvtxECmd.exe" `
    -f "$LOGS\$f" `
    --csv "$OUT\EventLogs" `
    --csvf ($f -replace '%4','_' -replace '\.evtx','.csv')
}

```
