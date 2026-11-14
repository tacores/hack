# Kansa

https://tryhackme.com/room/kansalivetriage

- PowerShellで記述されたモジュール式のインシデント対応フレームワーク。
- 幅広いデータを収集できる。
- 収集されたデータに対して実行できる分析スクリプトも付属する。
- WinRM 経由でのみ動作する。

## 基礎

### フォルダ構成

- Modules：データ収集装置として機能するPowerShellスクリプトが含まれる。 
- Analysis：コレクターが返すデータを解釈するPowerShellスクリプトが含まれる。

## Modules

| **Category** | **用途**                                      | **モジュール例**                                                                                |
| ------------ | ------------------------------------------- | ----------------------------------------------------------------------------------------- |
| ASEP         | 自動起動拡張ポイント（ASEP）を収集する。永続化の仕組みが隠れている場所を対象とする | `Get-SchedTasks`, `Get-SvcFail`, `Get-SvcTrigs`, `Get-WMIEvtFilter`, `Get-WMIEvtConsumer` |
| Config       | システムおよびアカウントの構成情報を収集する                      | `Get-LocalAdmins`, `Get-Hotfix`, `Get-Products`                                           |
| Disk         | 特定のファイル、ハッシュ値、ファイルシステムの一覧を収集する              | `Get-File`, `Get-FileHashes`, `Get-DiskUsage`                                             |
| Log          | イベントログのデータを収集する                             | `Get-LogWinEvent`, `Get-LogUserAssist`                                                    |
| Net          | 現在のネットワーク状態を収集する                            | `Get-Netstat`, `Get-DNSCache`, `Get-Arp`                                                  |
| Process      | 現在実行中のプロセスおよびプログラムの実行状態を収集する                | `Get-ProcsWMI`, `Get-PrefetchListing`, `Get-WMIRecentApps`                                |

### モジュールの実行

```ps
# ターゲットホストを信頼する。ドメインに参加していれば不要。
PS C:\Kansa> Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
PS C:\Kansa> Restart-Service WinRM
```

```ps
PS C:\Kansa> $cred = New-Object System.Management.Automation.PSCredential(
    "ServiceUser",
    (ConvertTo-SecureString "DcG3w4b8" -AsPlainText -Force)
)

PS C:\Kansa> .\kansa.ps1 -Target 10.145.137.105 -Credential $cred -ModulePath .\Modules\Process\Get-Tasklistv.ps1 -Authentication Negotiate
```

- `-Authentication Negotiate` は接続をNTLMにフォールバックするためのもので、ドメイン参加している環境では使わない。
- 実行が完了したら、Kansaフォルダ直下にディレクトリが作成されて結果が出力される。

#### 複数モジュール実行

`Modules/Modules.conf` を編集し、実行するモジュール名のコメントを解除する。

```ps
PS C:\Kansa> .\kansa.ps1 -Target 10.145.137.105 -Credential $cred -Authentication Negotiate
```

## Analysis

| **Category** | **用途**                            | **スクリプト例**                                                                                        |
| ------------ | --------------------------------- | ------------------------------------------------------------------------------------------------- |
| ASEP         | 永続化に関連するデータをスタックして整理する            | `Get-SchedTasksAllStack.ps1`, `Get-SvcFailStack.ps1`, `Get-ASEPImagePathLaunchStringStack.ps1`    |
| Config       | システムおよびアカウントの構成情報をスタックして整理する      | `Get-LocalAdminStack.ps1`, `Get-AMHealthStatusStack.ps1`                                          |
| Disk         | 収集したファイルそのものを扱う                   | `Decompress-KansaOutputFile.ps1`, `Get-WebrootListingEntropyOutliers.ps1`                         |
| Log          | イベントログのデータをスタックして整理する             | `Get-LogUserAssistValueStack.ps1`, `Get-LogUserAssistValueByDate.ps1`                             |
| Meta         | 特定の1つのモジュールではなく、収集データ全体を横断して処理する  | `Get-AllFileLengths.ps1`, `Get-FileLengths.ps1`                                                   |
| Net          | 現在のネットワークデータをスタックして整理する           | `Get-NetstatStack.ps1`, `Get-DNSCacheStack.ps1`, `Get-ARPStack.ps1`                               |
| Process      | 実行中のプロセスおよびプログラムの実行データをスタックして整理する | `Get-PrefetchListingStack.ps1`, `Get-ProcsWMIProcessNameStack.ps1`, `Get-ProcsWMICLIMD5Stack.ps1` |

### 解析の実行

```ps
# 収集
PS C:\Kansa> .\kansa.ps1 -Target 10.145.137.105 -Credential $cred -ModulePath .\Modules\Net\Get-DNSCache.ps1 -Authentication Negotiate

cd .\Output_<timestamp>\DNSCache
..\..\Analysis\Net\Get-DNSCacheStack.ps1
```

#### 複数の分析スクリプトを同時に実行

`Analysis/Analysis.conf` を編集。

```ps
PS C:\Kansa> .\kansa.ps1 -Target 10.145.137.105 -Credential $cred -Authentication Negotiate -Analysis
```

## ドメイン内の複数マシンで同時実行

```ps
# ターゲットを与えなければ、自動検出してすべてをスキャンする
PS C:\Kansa> .\kansa.ps1 -Credential $cred
```

自分でターゲットを精査することもできる。

```ps
# Pulls every computer object from AD using Get-ADComputer,
# but only ones that have logged on in the last 90 days
PS C:\Users\DFIRUser\Desktop\DFIR Tools\Data Triage\Kansa> .\Get-Targets.ps1

# Shuffle the order instead of sweeping in whatever order AD returns
PS C:\Users\DFIRUser\Desktop\DFIR Tools\Data Triage\Kansa> .\Get-Targets.ps1 -Randomize

# Save the list to a file, ready to feed straight into kansa.ps1's -Target
PS C:\Users\DFIRUser\Desktop\DFIR Tools\Data Triage\Kansa> .\Get-Targets.ps1 -outfile targets.txt
```

デフォルトで同時実行できるホスト数は32だが、複数のランチャーから並列で実行することもできる。`DistributedKansa.ps1` が関与しているが詳細不明。

## カスタムスクリプト例

### Run/RunOnce

```ps1
# レジストリの Run / RunOnce キーのパスリスト
$RunPaths = @(
    "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

# 各ユーザープロファイルの NTUSER.DAT を走査してハイブを読み込む場合（必要に応じて全ユーザーを網羅）
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Path in $RunPaths) {
    if (Test-Path $Path) {
        $Key = Get-Item $Path
        foreach ($Property in $Key.Property) {
            $Value = $Key.GetValue($Property)
            $Results.Add([PSCustomObject]@{
                Category = "Registry Run Keys"
                Entry    = $Property
                Path     = $Path
                Image    = $Value
            })
        }
    }
}

# 全ユーザー（S-1-5-21-...）の NTUSER.DAT 内の Run キーも網羅的にチェック
$Profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -eq $true -and $_.LocalPath }
foreach ($Profile in $Profiles) {
    $UserSid = $Profile.SID
    $UserRunPaths = @(
        "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\Run",
        "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($Path in $UserRunPaths) {
        if (Test-Path $Path) {
            $Key = Get-Item $Path
            foreach ($Property in $Key.Property) {
                $Value = $Key.GetValue($Property)
                $Results.Add([PSCustomObject]@{
                    Category = "Registry Run Keys (User)"
                    Entry    = $Property
                    Path     = $Path
                    Image    = $Value
                })
            }
        }
    }
}

# 結果を出力（Kansaが収集・結合できるようにオブジェクトとして返す）
$Results | ForEach-Object {
    $_
}
```

### WinLogonレジストリ

```ps
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$WinlogonPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (Test-Path $WinlogonPath) {
    $Key = Get-Item $WinlogonPath
    foreach ($Property in $Key.Property) {
        $Value = $Key.GetValue($Property)
        
        # 配列や複数値の場合はカンマ区切り文字列に変換
        if ($Value -is [System.Array]) {
            $Value = $Value -join ", "
        }

        $Results.Add([PSCustomObject]@{
            Category = "Winlogon"
            Entry    = $Property
            Path     = $WinlogonPath
            Image    = $Value
        })
    }
}

# 結果をパイプラインに出力（KansaがCSVとして回収・統合するため）
$Results | ForEach-Object {
    $_
}
```

### HKCU\Environment

```ps
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# 1. 現在のユーザーの HKCU\Environment をチェック
$EnvPath = "Registry::HKEY_CURRENT_USER\Environment"
if (Test-Path $EnvPath) {
    $Key = Get-Item $EnvPath
    foreach ($Property in $Key.Property) {
        # UserInitMprLogonScript などのログロンスクリプト関連の値をターゲットにする
        if ($Property -match "User.*LogonScript" -or $Property -eq "UserInitMprLogonScript" -or $Property -eq "UserIntMprLogonScript") {
            $Value = $Key.GetValue($Property)
            $Results.Add([PSCustomObject]@{
                Category = "Environment Logon Script (HKCU)"
                Entry    = $Property
                Path     = $EnvPath
                Image    = $Value
            })
        }
    }
}

# 2. 全ユーザー（HKEY_USERS\<SID>\Environment）を網羅的にチェック
$Profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -eq $true -and $_.LocalPath }
foreach ($Profile in $Profiles) {
    $UserSid = $Profile.SID
    $UserEnvPath = "Registry::HKEY_USERS\$UserSid\Environment"
    if (Test-Path $UserEnvPath) {
        $Key = Get-Item $UserEnvPath
        foreach ($Property in $Key.Property) {
            if ($Property -match "User.*LogonScript" -or $Property -eq "UserInitMprLogonScript" -or $Property -eq "UserIntMprLogonScript") {
                $Value = $Key.GetValue($Property)
                $Results.Add([PSCustomObject]@{
                    Category = "Environment Logon Script (HKEY_USERS)"
                    Entry    = $Property
                    Path     = $UserEnvPath
                    Image    = $Value
                })
            }
        }
    }
}

# 結果を出力
$Results | ForEach-Object {
    $_
}
```

### C:\Windows\System32\Tasks　の中身を出力

```ps
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$TasksPath = "$env:SystemRoot\System32\Tasks"

if (Test-Path $TasksPath) {
    # Tasks フォルダー内にあるすべてのファイルを再帰的に取得（フォルダー構造も維持）
    $Files = Get-ChildItem -Path $TasksPath -File -Recurse

    foreach ($File in $Files) {
        # 相対パス（タスクの階層構造を把握するため）
        $RelativePath = $File.FullName.Substring($TasksPath.Length + 1)
        
        $ActionValue = ""
        $Arguments = ""

        # XML ファイルとしてパースを試みる（タスク定義は XML 形式）
        try {
            [xml]$XmlContent = Get-Content -Path $File.FullName -Raw -ErrorAction Stop
            
            # 名前空間マネージャーの設定（Task Scheduler の XML スキーマ対応）
            $Ns = New-Object System.Xml.XmlNamespaceManager($XmlContent.NameTable)
            $Ns.AddNamespace("ns", $XmlContent.DocumentElement.NamespaceURI)

            # 実行されるコマンド（Exec/Command）や引数を取得
            $CommandNode = $XmlContent.SelectSingleNode("//ns:Exec/ns:Command", $Ns)
            if ($CommandNode) {
                $ActionValue = $CommandNode.InnerText
            }

            $ArgNode = $XmlContent.SelectSingleNode("//ns:Exec/ns:Arguments", $Ns)
            if ($ArgNode) {
                $Arguments = $ArgNode.InnerText
            }
        }
        catch {
            # XML として読み込めない場合やパースエラー時はファイル名のみ記録
            $ActionValue = "[XML Parse Error]"
        }

        # 結果をリストに追加
        $Results.Add([PSCustomObject]@{
            Category     = "ScheduledTasks XML"
            TaskName     = $RelativePath
            FullPath     = $File.FullName
            LastWriteTime= $File.LastWriteTime
            Command      = $ActionValue
            Arguments    = $Arguments
        })
    }
}

# 結果を出力（Kansaが結合できるようにオブジェクトとして流す）
$Results | ForEach-Object {
    $_
}
```
