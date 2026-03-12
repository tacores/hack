# Windows フォレンジック２（ファイルシステム）

https://tryhackme.com/room/windowsforensics2

## FAT

### データ構造

- クラスター
- ディレクトリ
- ファイルアロケーションテーブル

ファイルを構成するビットはクラスターに格納され、ファイル システム上のすべてのファイル名、その開始クラスター、およびその長さは、ディレクトリに格納される。ファイル システム上のすべてのファイル名、その開始クラスター、およびその長さは、ディレクトリに格納される。

### exFAT

デジタルデバイスメーカーで広く使われている拡張で、32GB を超える SD カードのデフォルトになっている。

## NTFS

### 機能

- ジャーナリング  
  ボリューム内のメタデータ変更のログを保持。ボリュームのルート ディレクトリの $LOGFILE に保存される。
- アクセス制御  
  ファイル・ディレクトリの所有者と各ユーザーの権限を定義するアクセス制御。
- ボリュームシャドウコピー  
  ファイルに加えられた変更を追跡し、回復やシステム復元のために以前のファイルバージョンを復元できる。
- 代替データストリーム  
  1 つのファイルに複数のデータストリームを保存できる。例えば、ブラウザは代替データストリームを使用して、インターネットからダウンロードされたファイルを識別する。

### マスターファイルテーブル（MFT）

- $MFT  
  はボリュームの最初のレコード。このファイルには、ボリューム上に存在する全てのファイルのディレクトリが含まれる。
- $LOGFILE  
  ファイルシステムのトランザクションログが保存される。
- $UsnJrnl  
  Update Sequence Number(USN)ジャーナルの略。$Extend レコードに存在する。

#### MFT Explorer

Eric Zimmerman のツールの 1 つ。CLI と GUI がある。

```shell
# $MFTファイルの解析
MFTECmd.exe -f <path-to-$MFT-file> --csv <path-to-save-results-in-csv>

# 出力したら、EZViewerツールで表示する。
```

#### LogFileParser

https://github.com/jschicht/LogFileParser

大量のCSVとsqlが出力される。

```sh
.\LogFileParser64.exe /LogFileFile:'$LogFile.copy0'
```

単にコマンドを実行すると、GUIが起動する。こっちの方が分かりやすい。

```sh
.\LogFileParser64.exe
```

## 削除されたファイルの回復

### Autopsy

https://www.autopsy.com/

### UsnJrnl

NTFS の場合、$USNJrnl を解析。（ファイルシステム.md 参照）

## 実行の証拠

### Windows プリフェッチファイル

頻繁に使用されるプログラムを素早く読み込むための機能。  
`C:\Windows\Prefetch` に保存される。拡張子は`.pf`.

最終実行時刻、実行回数、ファイルによって使用されたファイルとデバイスハンドルが含まれる。

### プリフェッチファイルの解析

Eric Zimmerman のツールの Prefetch Parser (PECmd.exe) を使用。

```shell
# プリフェッチファイルを解析
PECmd.exe -f <path-to-Prefetch-files> --csv <path-to-save-csv>

# ディレクトリ全体を解析
PECmd.exe -d <path-to-Prefetch-directory> --csv <path-to-save-csv>
```

### Powershellトランスクリプト

Documents\mmdd フォルダの中に、`PowerShell_transcript.SRV-IT-QA.KSUYD5bK.20250630182641.txt` のようなファイル名で残っている場合がある。

### Windows10 タイムライン

Windows 10 は、最近使用したアプリケーションとファイルを Windows 10 タイムラインと呼ばれる SQLite データベースに保存する。

Windows10 タイムラインの場所
`C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db`

Windows 10 タイムラインを解析するには、Eric Zimmerman の WxTCmd.exe を使用できる。

```shell
WxTCmd.exe -f <path-to-timeline-file> --csv <path-to-save-csv>
```

### Windows ジャンプリスト

ユーザーがタスク バーから最近使用したファイルに直接アクセスできるようにするリスト。

Windows ジャンプリストの場所  
`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`

ジャンプ リストを解析するには、Eric Zimmerman の JLECmd.exe を使用できる。

```shell
JLECmd.exe -f <path-to-Jumplist-file> --csv <path-to-save-csv>
```

### Powershell の履歴

```powershell
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### スケジュールされたタスク

```
C:\Windows\System32\Tasks
```

```ps
Get-ScheduledTask | Where-Object {$_.State —ne "Disabled"}

# CSV出力
schtasks.exe /query /fo CSV | findstr /V Disabled
```

```ps
# List all enabled scheduled tasks with creation date and command to be executed, sorted by date and printing all additional information
$tasks = Get-ScheduledTask | Where-Object {$_.Date —ne $null —and $_.State —ne "Disabled" —and $_.Actions.Execute —ne $null} | Sort-Object Date

foreach ($task in $tasks) {
    $taskName = $task.TaskName
    $taskDate = $task.Date
    $taskPath = $task.TaskPath
    $taskAuthor = $task.Author
    $taskCommand = $task.Actions.Execute
    $taskArgs = $task.Actions.Arguments
    $taskRunAs = $task.Principal.UserId

    # Output service information
    Write-Host "Task Name: $taskName"
    Write-Host "Task Author: $taskAuthor"
    Write-Host "Creation Date: $taskDate"
    Write-Host "Task Path: $taskPath"
    Write-Host "Command: $taskCommand $taskArgs"
    Write-Host "Run As: $taskRunAs"
    Write-Host ""
}
```

### サービス

```ps
$services = Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic"}

foreach ($service in $services) {
    $serviceName = $service.Name
    $serviceDisplayName = $service.DisplayName
    $serviceStatus = $service.Status
    $serviceWMI = (Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $serviceName })
    $servicePath = $serviceWMI.PathName
    $serviceUser = $serviceWMI.StartName

    Write-Host "Service Name: $serviceName"
    Write-Host "Display Name: $serviceDisplayName"
    Write-Host "Service Status: $serviceStatus"
    Write-Host "Executable Path: $servicePath"
    Write-Host "User Context: $serviceUser"
    Write-Host ""
}
```

## ファイル・フォルダ

### ショートカットファイル

Windows は、ローカルまたはリモートで開かれたファイルごとにショートカット ファイルを作成する。

ショートカットファイルの場所  
`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`  
`C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\`

※エクスプローラ上で「Windows\最近使った項目」のように表示されていても、コマンドプロンプトでは「Windows\Recent」でアクセスできる。

Eric Zimmerman の LECmd.exe ( Lnk Explorer)を使用してショートカット ファイルを解析できる。

```shell
LECmd.exe -f <path-to-shortcut-files> --csv <path-to-save-csv>
```

### スタートアップファイル

実行ファイル自体を配置できる

```
C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

### IE/Edge 履歴

ブラウザーを使用して開かれたかどうかに関係なく、システムで開かれたファイルも含まれる。

場所  
`C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`

アクセスされたファイル・フォルダは、`file:///*`プレフィックスで表示される。

Autopsy で、「最近のアクティビティ」を ON にすることで分析できる。

### Mark of the Web (MotW)

ファイルのダウンロード元を調べる

```sh
Get-Content -Path  "C:\Users\Tom Barry\Downloads\Service_Configuration_Guide.rar" -Stream Zone.Identifier
```

## 外部デバイス

### USB デバイスセットアップログ

`C:\Windows\inf\setupapi.dev.log`

### ショートカットファイル

上の方で記述したショートカットファイルにも接続された USB デバイスに関する情報が含まれる場合がある。

## ネットワーク分析

https://tryhackme.com/room/windowsnetworkanalysis

### SRUM (System Resource Usage Monitor)
```
C:\Windows\System32\sru\SRUDB.dat
```
※ロックされているのでライブシステムでは読めない。要エクスポート。

```sh
.\kape.exe --tsource C:\Windows\System32\sru --tdest C:\Users\CMNatic\Desktop\SRUM --tflush --mdest C:\Users\CMNatic\Desktop\MODULE --mflush --module SRUMDump --target SRUM
```

[srum-dump](https://github.com/MarkBaggett/srum-dump)で解析

### Windows Firewall Logs

```
C:\Windows\System32\LogFiles\Firewall
```

### Powershell

```ps
# TCP接続と関連プロセスを表示
Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | sort Remoteaddress -Descending | ft -wrap -autosize

# UDP接続
Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize

# DNSキャッシュ
Get-DnsClientCache | ? Entry -NotMatch "workst|servst|memes|kerb|ws|ocsp" | out-string -width 1000
```

```sh
# リモートデスクトップセッションを表示
qwinsta

# SMB共有
Get-SmbConnection
Get-SmbShare
```

### pktmon

ネットワークスタック上で動作するMicrosoft開発のパケットスニッフィングツール

```ps
pktmon /?
```

### netstat

```ps
netstat -a

# 実行可能ファイルを表示
netstat -b
```
