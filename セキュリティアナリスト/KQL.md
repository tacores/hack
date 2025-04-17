# KQL (Kibana Query Language)

https://www.elastic.co/guide/en/kibana/7.17/kuery-query.html

https://tryhackme.com/room/advancedelkqueries

## 基本

### 予約文字

これらを使う場合はバックスラッシュエスケープが必要。  
`+, -, =, &&, ||, &, | and !`

### ワイルドカード

`*`は任意の数の文字、`?`は任意の 1 文字に一致する。

## フリーテキスト検索

"United States" という値の列があるとき、

### ヒットするパターン

```
United States
United*
"United States"
```

### ヒットしないパターン

```
United
"United*"
```

## AND, OR, NOT

```
"United States" AND NOT ("Florida")
```

## フィールドベースの検索

```
Source_ip:238.163.231.224 AND UserName:Suleman
```

### ネストクエリ

```json
{
  "comments": [
    {
      "author": "Alice",
      "text": "Mitigated DDoS attack"
    },
    {
      "author": "Bob",
      "text": "Checked logs, found suspicious IPs"
    }
  ]
}
```

このような JSON の場合、下記のようなネストクエリの記述が可能。

```shell
# comments.authorフィールドを含む全てのイベントにヒット
comments.author:*

# Aliceのみに絞る
comments.author:"Alice"
```

## 範囲クエリ

```
@timestamp<"yyyy-MM-ddTHH:mm:ssZ"

@timestamp>yyyy-MM-dd
```

## ファジー検索と近接検索

KQL ではなく、Lucene 構文。（ElasticSearch の場合、クエリ窓の右側で切り替える）

### ファジー検索

構文 `field_name:search_term~fuzziness_value`

- ファジー値は大きいほどヒットしやすくなる
- ファジー検索はネストされたデータには機能せず、1 単語にのみ機能する

```shell
# server01, serber01, sorvor01 などがヒットする
host_name:server01~2
```

### 近接検索

構文 `field_name:"search term"~slop_value`

- ファジー検索との構文的な違いは、ダブルクォートを使うこと
- 指定した２語の間に最大何単語含まれる場合にヒットするかということ
- 単語の順序は逆でもヒットする

```shell
# server と error の間に最大１単語しか含まれない全てのイベントを検索
# : や - などは単語としてカウントされない。
log_message:"server error"~1

# 複数条件指定も可能
log_message:"server error"~1 OR "login server"~1

# 複合語間が4単語以内という指定
incident_comments:"`data leak` `true negative`"~4
```

## 正規表現

- KQL ではなく Lucene 構文
- 正規表現を // で囲む

```shell
Description:/(s|m).*/

# 複数指定
Description:/(s|m).*/ AND /user.*/
```

## 頻出

永続化

```
*schtasks*
*ScheduledTask*
```

ツール

```
mimikatz
```

## 具体例

### 初期アクセス

#### SSH ブルートフォース検出

```
host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Failed
```

攻撃元 IP を確認した後、認証成功したか確認する

```
host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Accepted AND source.ip: (167.71.198.43 OR 218.92.0.115)
```

#### Chrome ブラウザによるファイル保存

```
host.name: WKSTN-* AND process.name: chrome.exe AND winlog.event_id: 11
```

#### Outlook を使用して開いたファイル

```
host.name: WKSTN-* AND process.name: OUTLOOK.EXE AND winlog.event_id: 11
```

### 実行

#### コマンドライン実行

```
host.name: WKSTN-* AND winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe)
```

スクリプトブロック生成

```
host.name: WKSTN-* AND winlog.event_id: 4104 and not powershell.file.script_block_text : "*Set-StrictMode*"
```

キーワード

```
invoke / invoke-expression / iex
-enc / -encoded
-noprofile / -nop
bypass
-c / -command
-executionpolicy / -ep
WebRequest
Download
```

#### LOLBAS 検出

```
host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (mshta.exe OR certutil.exe OR regsvr32.exe) OR process.parent.name: (mshta.exe OR certutil.exe OR regsvr32.exe))
```

- winlog.computer_name
- user.name
- process.parent.command_line
- process.name
- process.command_line
- destination.ip

#### スクリプト、プログラミングツール

```
host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND (process.name: (*python* OR *php* OR *nodejs*) OR process.parent.name: (*python* OR *php* OR *nodejs*))
```

- winlog.computer_name
- user.name
- process.parent.command_line
- process.name
- process.command_line
- destination.ip
- destination.port

### 防御回避

#### セキュリティソフト無効化

```
host.name: WKSTN-* AND (*DisableRealtimeMonitoring* OR *RemoveDefinitions*)
```

#### Windows イベントログ削除

```
host.name: WKSTN-* AND winlog.event_id: 1102
```

#### プロセスインジェクション

```
host.name: WKSTN-* AND winlog.event_id: 8
```

- winlog.computer_name
- process.executable
- winlog.event_data.SourceUser
- winlog.event_data.TargetImage

### 永続化

#### スケジュールタスクの作成

```
host.name: WKSTN-* AND (winlog.event_id: 4698 OR (*schtasks* OR *Register-ScheduledTask*))
```

- winlog.computer_name
- user.name
- process.command_line
- winlog.event_id
- winlog.event_data.TaskName

#### レジストリキー変更

```
host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational
```

レジストリキーを絞る

```
host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\Explorer\\User* OR *CurrentVersion\\Explorer\\Shell*)
```

```
host.name: WKSTN-* AND winlog.event_id: 13 AND winlog.channel: Microsoft-Windows-Sysmon/Operational AND process.name: (reg.exe OR powershell.exe)
```

- winlog.computer_name
- user.name
- process.name
- registry.path
- winlog.event_data.Details

### コマンド＆コントロール

#### DNS

```
# Visualize で件数が多いドメインに注目する
network.protocol: dns AND NOT dns.question.name: *arpa
```

- query

宛先 IP を特定した後

```
host.name: WKSTN-1* AND destination.ip: 167.71.198.43 AND destination.port: 53
```

- host.name
- user.name
- process.parent.command_line
- process.name
- process.command_line

#### クラウドアプリ

```
host.name: WKSTN-1* AND *discord.gg*
```

#### 暗号化された HTTP トラフィック

```

```
