# Windows フォレンジック（アプリケーション）

https://tryhackme.com/room/windowsapplications

## Webブラウザ

Windows/ブラウザアーティファクト.md 参照

## Outlook

```
AppData\Local\Microsoft\Outlook\
```

添付ファイルの一時キャッシュ。（ただしクライアントを終了したら消える）
```
AppData\Local\Microsoft\Windows\INetCache\Content.Outlook
```

### .ost ファイル

メールのローカルコピー。[Xst Reader](https://github.com/Dijji/XstReader)で開ける。


## Teams

```
AppData\Roaming\Microsoft\Teams
```

[メタデータパーサー](https://github.com/lxndrblz/forensicsim/)

```ps
C:\Tools\ms_teams_parser.exe -f C:\Users\mike.myers\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\ -o output.json
```

```ps
$teams_metadata = cat .\output.json | ConvertFrom-Json
$users = @{}

# Initialise user hashtable for correlation
foreach ($data in $teams_metadata) {
   if ($data.record_type -eq "contact") {
     $users.add($data.mri, $data.userPrincipalName)
   }
}
$users | fl

$teams_metadata = cat .\output.json | ConvertFrom-Json
$messages = @{}
# Combine all conversations/messages with the same ID
foreach ($data in $teams_metadata) {
  if ($data.record_type -eq "message") {
    if ($messages.keys -notcontains $data.conversationId) {
      $messages[$data.conversationId] = [System.Collections.ArrayList]@()
    }
    $messages[$data.conversationId].add($data) > $null
  }
}
$messages | fl

$teams_metadata = cat .\output.json | ConvertFrom-Json
$users = @{}
$messages = @{}

# Initialise user hashtable for correlation
foreach ($data in $teams_metadata) {
   if ($data.record_type -eq "contact") {
     $users.add($data.mri, $data.userPrincipalName)
   }
}

# Combine all conversations/messages with the same ID
foreach ($data in $teams_metadata) {
  if ($data.record_type -eq "message") {
    if ($messages.keys -notcontains $data.conversationId) {
      $messages[$data.conversationId] = [System.Collections.ArrayList]@()
    }
    $messages[$data.conversationId].add($data) > $null
  }
}

# Print the parsed output focused on the significant values
foreach ($conversationID in $messages.keys) {
  Write-Host "Conversation ID: $conversationID`n"
  $conversation = $messages[$conversationID] | Sort createdTime
  foreach ($message in $conversation) {
    $createdTime = $message.createdTime
    $fromme = $message.isFromMe
    $content = $message.content
    $sender = $users[$message.creator]

    Write-Host "Created Time: $createdTime"
    Write-Host "Sent by: $sender"
    Write-Host "Direction: $direction"
    Write-Host "Message content: $content"
    Write-Host "`n"
  }

  Write-host "----------------`n"
}
```

## OneDrive

```
Appdata\Local\Microsoft\OneDrive\logs
```

- SyncEngine.odl：処理された各ファイルの情報を含む、実行されたすべての操作が含まれる
- SyncDiagnostics.log：OneDrive の同期プロセスに関する診断情報を含むログファイル

ODLファイルを解析するために、[OneDriveExplorer](https://github.com/Beercow/OneDriveExplorer) を使える。（管理者として実行）

## Webサーバー

```
C:\Apache24\logs
C:\inetpub\logs\LogFiles\<WEBSITE>
```
