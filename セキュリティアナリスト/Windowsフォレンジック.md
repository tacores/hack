# Windows フォレンジック

## 基本

```ps
# ユーザー一覧
net user

# ユーザー詳細（最終ログイン時刻等も）
net user <username>
```

## 自動起動

#### スタートアッププログラム

```shell
wmic startup get caption,command
```

#### スケジュールタスクをアクション込みで表示

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
