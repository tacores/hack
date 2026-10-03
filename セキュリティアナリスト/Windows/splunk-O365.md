# splunk-O365

## Exchange

```
New-InboxRule
```

件名一覧

```
index=vantage sourcetype="o365:reporting:messagetrace" 
| table Subject
| dedup Subject
```

## SharePoint

ダウンロード

```
FileDownloaded
```

ファイル共有。その後、MessageTraceでリンクがメール送信されていないか？（ファイル名で検索）

```
sourcetype="o365:management:activity" action=shared
```

コンテンツや属性等の変更

```
sourcetype="o365:management:activity" action=modified app=SharePoint
```

## Teams

リンク付きメッセージの作成

```
app=MicrosoftTeams webb command=MessageCreatedHasLink
```
