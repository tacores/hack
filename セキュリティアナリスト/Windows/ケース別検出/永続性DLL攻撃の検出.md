# 永続性DLL攻撃の検出

https://tryhackme.com/room/detectingpersistentdllattacks

## イメージロード

### Sysmon 7: Image Loaded

```ps
Get-WinEvent -Path 'C:\Case\DEV-WS\evtx\Sysmon-Operational.evtx' -FilterXPath "*[System[EventID=7]]" -MaxEvents 5 |
  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data }
```

| **Key Field**     | **内容**                                      |
| :---------------- | :-------------------------------------------- |
| `Image`           | 読み込みを実行したプロセスのパス              |
| `ImageLoaded`     | 読み込まれたモジュールのパス                  |
| `Signed`          | 読み込まれたモジュールが署名されているかどうか |
| `SignatureStatus` | 署名を検証できたかどうか、およびその結果      |


### Windows DLL Extension Points

Windowsが特定の時点で読み取り、 「この場所に指定されたDLLをこのプロセスにロードせよ」という命令として扱うレジストリ値のこと。

| **Host process** | **Registered at**                                                                   | **Trigger**                                  | **Write privilege**            |
| :--------------- | :---------------------------------------------------------------------------------- | :------------------------------------------- | :----------------------------- |
| `explorer.exe`   | `Software\Classes\CLSID\{GUID}\InprocServer32`, and Explorer's shell extension keys | ログオンのたび                               | **None** for the per-user hive |
| `explorer.exe`   | `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers`    | ログオンのたび                               | Admin                          |
| `spoolsv.exe`    | `Control\Print\Environments\Windows x64\Print Processors\<name>\Driver`             | スプーラーの起動時（つまり、ブートのたび）   | Admin                          |
| `spoolsv.exe`    | `Control\Print\Monitors\<name>\Driver`                                              | スプーラーの起動時                           | Admin                          |
| `svchost.exe`    | `Services\<svc>\Parameters\ServiceDll`                                              | サービスの起動時                             | Admin                          |
| `lsass.exe`      | `Control\Lsa\Security Packages`, `Authentication Packages`, `Notification Packages` | ブート時、およびパスワード変更のたび         | Admin                          |
| `netsh.exe`      | `SOFTWARE\Microsoft\Netsh`                                                          | `netsh` の実行時（オンデマンド）              | Admin                          |
| any process      | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`                 | 有効な場合、すべてのユーザーモードプロセスのロード時 | Admin                          |
| `winlogon.exe`   | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`                      | ログオンイベント時（レガシービルドのみ）     | Admin                          |

- AppInit_DLLsは、最新のビルドでは無効になっている。
- Winlogon\Notify は Vista で削除されたので Windows10 以降では存在しない。

### ベースラインと比較する

```ps
RECmd.exe -f 'C:\Case\baseline\C\Windows\System32\config\SOFTWARE' --kn "Microsoft\Netsh"
RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Windows\System32\config\SOFTWARE' --kn "Microsoft\Netsh"
```

```ps
# powershellではなくcmdで実行する
autorunsc.exe -nobanner -accepteula -a * -s -h -c -t -z C:\Work\baseline\C\Windows C:\Work\baseline\C\Users\liam.patel > C:\Work\base_sweep.csv

# 1回の起動につきオフラインスキャンが1回に制限されているので再起動が必要
autorunsc.exe -nobanner -accepteula -a * -s -h -c -t -z C:\Work\triage\C\Windows C:\Work\triage\C\Users\liam.patel > C:\Work\sweep.csv
```

```ps
$B = 'C:\Users\DFIRUser\Desktop\DFIR Tools\EZ Tools\RECmd\BatchExamples'

RECmd.exe -f 'C:\Case\baseline\C\Users\liam.patel\AppData\Local\Microsoft\Windows\UsrClass.dat' `
  --bn "$B\UserClassesASEPs.reb" --csv C:\Work --csvf base_usr.csv

RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Users\liam.patel\AppData\Local\Microsoft\Windows\UsrClass.dat' `
  --bn "$B\UserClassesASEPs.reb" --csv C:\Work --csvf inc_usr.csv
```

```ps
$base = Import-Csv C:\Work\base_usr.csv
$seen = @{}
$base | ForEach-Object { $seen["$($_.Description)|$($_.KeyPath)|$($_.ValueName)|$($_.ValueData)"] = $true }

Import-Csv C:\Work\inc_usr.csv |
  Where-Object { -not $seen["$($_.Description)|$($_.KeyPath)|$($_.ValueName)|$($_.ValueData)"] } |
  Group-Object Description
```

## COMハイジャックとUsrClass.dat

`HKCU\Software\Classes` は、`NTUSER.DAT` ではなく、`%LocalAppData%\Microsoft\Windows\UsrClass.dat` であることに注意。

```ps
# 乗っ取られたキーを読む
RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Users\liam.patel\AppData\Local\Microsoft\Windows\UsrClass.dat' `
  --kn "CLSID\{2155fee3-2419-4373-b102-6843707eb41f}\InprocServer32"
```

```ps
# マシンハイブと比較
RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Windows\System32\config\SOFTWARE' `
  --kn "Classes\CLSID\{2155fee3-2419-4373-b102-6843707eb41f}\InprocServer32"
```

```ps
# DLL作成日時。--at を指定しないと日付が空白になる可能性がある。
MFTECmd.exe -f 'C:\Case\DEV-WS\mft\$MFT' --csv C:\Work --csvf mft.csv --at
```

## プリントプロセッサ

プリントプロセッサとは、スプーラーがロードするDLLであり、スプールされたジョブを特定のプリンタが期待するデータストリームに変換するもの。  
Windows には winprint が付属しており、ベンダーが独自の DLL を登録できるようにしている。

カタログ署名されたWindowsバイナリは、真正か偽物かにかかわらず、検証されないため verified が unsigned となるが、それ以外で差分が出る可能性がある。

```ps
# ベースラインとのファイル比較
sigcheck.exe -nobanner -accepteula -a C:\Case\baseline\files\prtprocs-x64\winprint.dll

sigcheck.exe -nobanner -accepteula -a C:\Case\DEV-WS\files\prtprocs-x64\winprint.dll
```

```ps
# spoolsv.exe にロードされたDLL（時系列）
Get-WinEvent -Path 'C:\Case\DEV-WS\evtx\Sysmon-Operational.evtx' -FilterXPath "*[System[EventID=7]]" |
  Where-Object { $_.ToXml() -match 'spoolsv\.exe' } |
  ForEach-Object {
    $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ UtcTime = $d['UtcTime']; ImageLoaded = $d['ImageLoaded'] }
  } | Sort-Object UtcTime 
```

## サービス

Windowsでは数十ものサービスが実行されており、それぞれに専用のプロセスを割り当てるのはコストがかかりすぎると考えられていたため、関連するサービスはグループ化され、共有のsvchost.exeプロセス内でホストされていた。

これらのグループのいずれかに属するサービスは、実行ファイルではなくDLLとして提供され、レジストリによってsvchostがロードするDLLが指定される。検査対象となるバイナリは存在しない。ImagePathは `svchost.exe -k <group>` を指し、Parameters\ServiceDll は処理を実行するモジュール名を指定し、Startは起動時にサービスを実行するかどうかを決定する。この値を1つ変更するだけで、サービスは名前、説明、履歴全体を維持しながら、まったく異なるコードを実行する。

| **Evidence**  | **新しいサービスのインストール** | **既存サービスの参照先変更** |
| :------------ | :------------------------------- | :--------------------------- |
| System 7045   | はい                             | **いいえ**                   |
| Security 4697 | はい（監査が有効な場合）         | **いいえ**                   |
| Sysmon 13     | はい                             | はい                         |
| Sysmon 7      | 次回の起動時                     | 次回の起動時                 |

```ps
# 書き込みの確認
RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Windows\System32\config\SYSTEM' `
  --kn "ControlSet001\Services\SysMain\Parameters"

RECmd.exe -f 'C:\Case\DEV-WS\triage\C\Windows\System32\config\SYSTEM' `
  --kn "ControlSet001\Services\SysMain"
```

3033はロードが拒否されたことを意味する。3065と3066は監査モードのペアで、同じロードが観測され、許可されたことを意味する。  
LSA Protection (RunAsPPL = 1 or 2) はlsass.exeを保護されたプロセスとして実行し、保護されたプロセスは署名されていないモジュールをマッピングしない。

```ps
Get-WinEvent -Path 'C:\Case\DEV-WS\evtx\CodeIntegrity-Operational.evtx' -Oldest `
>>   -FilterXPath "*[System[EventID=3033 or EventID=3065 or EventID=3066]]" |
>>   Format-List TimeCreated, Id, Message


TimeCreated : 8/17/2026 1:57:28 AM
Id          : 3033
Message     : Code Integrity determined that a process (\Device\HarddiskVolume4\Windows\System32\lsass.exe)
              attempted to load \Device\HarddiskVolume4\Windows\System32\msvctrl.dll that did not meet the Microsoft
              signing level requirements.
```

## 根絶と検証

https://tryhackme.com/room/detectingpersistentdllattacks?taskNo=7&sharerId=674ed42e2374d1bc93db444c
