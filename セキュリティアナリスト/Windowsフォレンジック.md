# Windows フォレンジック

https://tryhackme.com/room/winincidentsurface

## 基本

```ps
# ユーザー一覧
net user

# ユーザー詳細（最終ログイン時刻等も）
net user <username>
```

## Powershellプロファイル

ライブシステムを調査する場合、Powershellプロファイルが設定されていないことを確認しなければならない。

| プロファイルの範囲         | プロファイルファイルパス                                     |
|----------------------------|---------------------------------------------------------------|
| 現在のユーザー、現在のホスト | `$HOME\Documents\WindowsPowerShell\profile.ps1`               |
| すべてのユーザー、現在のホスト | `$PSHOME\Microsoft.PowerShell_profile.ps1`                   |
| 現在のユーザー、すべてのホスト | `$HOME\Documents\profile.ps1`                                |
| すべてのユーザー、すべてのホスト | `$PSHOME\profile.ps1`                                        |

cmd.exeで実行。
```ps
# Powershellプロファイルの有無をチェック
if exist "C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

if exist "C:\Users\Administrator\Documents\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

if exist "C:\Users\Administrator\Documents\WindowsPowerShell\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

if exist "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)
```

```ps
# クリーンなプロファイルに置き換える
ren PS-DFIR-Profile.ps1 profile.ps1

ren C:\Windows\System32\WindowsPowerShell\v1.0\\profile.ps1 profile.bak

copy profile.ps1 C:\Windows\System32\WindowsPowerShell\v1.0\
```

powershell.exe で実行
```ps
# バージョンと、ロードされたモジュールを記録しておく
Get-Module | ft ModuleType, Version, Name

Get-Module -ListAvailable | select ModuleType, Version, Name
```

## ユーザーとセッション

```ps
Get-LocalUser | tee l-users.txt

Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount=True" | Format-Table  Name, PasswordRequired, PasswordExpires, PasswordChangeable | Tee-Object "user-details.txt"

Get-LocalGroup | ForEach-Object { $members = Get-LocalGroupMember -Group $_.Name; if ($members) { Write-Output "`nGroup: $($_.Name)"; $members | ForEach-Object { Write-Output "`tMember: $($_.Name)" } } } | tee gp-members.txt

.\PsLoggedon64.exe | tee sessions.txt
```

## ネットワーク

```ps
Get-NetTCPConnection | select Local*, Remote*, State, OwningProcess,` @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}},` @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}} | sort State | ft -Auto | tee tcp-conn.txt

Get-CimInstance -Class Win32_Share | tee net-shares.txt

Get-NetFirewallProfile | ft Name, Enabled, DefaultInboundAction, DefaultOutboundAction | tee fw-profiles.txt
```

## スタートアップ

### スタートアッププログラム

```shell
wmic startup get caption,command
```

### スタートアップとレジストリ

```ps
.\autorunsc64.exe -a b * -h | tee boot.txt

.\autorunsc64.exe -a l * -h | tee logon.txt

Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | fl | tee autorun-cmds.txt

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; "Userinit: $((Get-ItemProperty -Path $winlogonPath -Name 'Userinit').Userinit)"; "Shell: $((Get-ItemProperty -Path $winlogonPath -Name 'Shell').Shell)"
```

## サービスとスケジュールタスク


### スケジュールタスクをアクション込みで表示

```ps
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Actions | ForEach-Object {
        [PSCustomObject]@{
            TaskName   = $task.TaskName
            Path       = $task.TaskPath
            ActionType = $_.ActionType
            Execute    = $_.Execute
            Arguments  = $_.Arguments
            WorkingDir = $_.WorkingDirectory
        }
    }
} > tasks.txt
```

### タスクスケジュール

下記フォルダでもタスクを確認できる。  
`C:\Windows\System32\Tasks`

```ps
"Running Services:"; Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -eq "Running" } | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId | ft -AutoSize | tee services-active.txt

"Non-Running Services:"; Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -ne "Running" } | Select-Object @{Name='Name'; Expression={if ($_.Name.Length -gt 22) { "$($_.Name.Substring(0,19))..." } else { $_.Name }}}, @{Name='DisplayName'; Expression={if ($_.DisplayName.Length -gt 45) { "$($_.DisplayName.Substring(0,42))..." } else { $_.DisplayName }}}, State, StartMode, PathName, ProcessId | Format-Table -AutoSize | Tee-Object services-idle.txt

$tasks = Get-CimInstance -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask; if ($tasks.Count -eq 0) { Write-Host "No scheduled tasks found."; exit } else { Write-Host "$($tasks.Count) scheduled tasks found." }; $results = @(); foreach ($task in $tasks) { foreach ($action in $task.Actions) { if ($action.PSObject.TypeNames[0] -eq 'Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_TaskExecAction') { $results += [PSCustomObject]@{ TaskPath = $task.TaskPath.Substring(0, [Math]::Min(50, $task.TaskPath.Length)); TaskName = $task.TaskName.Substring(0, [Math]::Min(50, $task.TaskName.Length)); State = $task.State; Author = $task.Principal.UserId; Execute = $action.Execute } } } }; if ($results.Count -eq 0) { Write-Host "No tasks with 'MSFT_TaskExecAction' actions found." } else { $results | Format-Table -AutoSize | tee scheduled-tasks.txt }

```

### プロセスとディレクトリ

```ps
Get-WmiObject -Class Win32_Process | ForEach-Object {$owner = $_.GetOwner(); [PSCustomObject]@{Name=$_.Name; PID=$_.ProcessId; P_PID=$_.ParentProcessId; User="$($owner.User)"; CommandLine=if ($_.CommandLine.Length -le 60) { $_.CommandLine } else { $_.CommandLine.Substring(0, 60) + "..." }; Path=$_.Path}} | ft -AutoSize | tee process-summary.txt

Get-ChildItem -Path "C:\Users" -Force | Where-Object { $_.PSIsContainer } | ForEach-Object { Get-ChildItem -Path "$($_.FullName)\AppData\Local\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object @{Name='User';Expression={$_.FullName.Split('\')[2]}}, FullName, Name, Extension } | ft -AutoSize | tee temp-folders.txt


Get-CimInstance -ClassName Win32_Volume | ft -AutoSize DriveLetter, Label, FileSystem, Capacity, FreeSpace | tee disc-volumes.txt

```
