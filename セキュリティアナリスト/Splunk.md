# Splunk

初期状態では何も表示されないので、まずは index 指定する。  
分からない場合は、ワイルドカードを指定可能。

```
index=*
```

## コマンド

### フィルタリングコマンド

#### fields コマンド

```
index=windowslogs | fields + host + User + SourceIp
```

#### search コマンド

```
index=windowslogs | search Powershell
```

#### 重複除去

```
index=windowslogs | table EventID User Image Hostname | dedup EventID
```

#### リネーム

```
index=windowslogs | fields + host + User + SourceIp | rename User as Employees
```

### 構造化コマンド

#### テーブル

```
index=windowslogs | table EventID Hostname SourceName
```

#### head

```
index=windowslogs |  table _time EventID Hostname SourceName | head 5
```

#### tail

```
index=windowslogs |  table _time EventID Hostname SourceName | tail 5
```

#### sort

```
index=windowslogs |  table _time EventID Hostname SourceName | sort Hostname
```

#### reverse

```
index=windowslogs | table _time EventID Hostname SourceName | reverse
```

### 変換コマンド

#### top

```
index=windowslogs | top limit=7 Image
```

#### rare

```
index=windowslogs | rare limit=7 Image
```

#### highlight

```
index=windowslogs | highlight User, host, EventID, Image
```

#### stats

| Command | Explanation                                                       | Syntax                              | Example                    |
| ------- | ----------------------------------------------------------------- | ----------------------------------- | -------------------------- |
| Average | This command is used to calculate the average of the given field. | `stats avg(field_name)`             | `stats avg(product_price)` |
| Max     | It will return the maximum value from the specific field.         | `stats max(field_name)`             | `stats max(user_age)`      |
| Min     | It will return the minimum value from the specific field.         | `stats min(field_name)`             | `stats min(product_price)` |
| Sum     | It will return the sum of the fields in a specific value.         | `stats sum(field_name)`             | `stats sum(product_cost)`  |
| Count   | The count command returns the number of data occurrences.         | `stats count(function) AS new_NAME` | `stats count(source_IP)`   |

#### chart

```
index=windowslogs | chart count by User
```

#### timechart

```
index=windowslogs | timechart count by Image
```

## Tips

### ワイルドカード

```
index=windowslogs DestinationIp=172.*
```

### 件数のカウント、ソートの例

```
index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests
```

### 表示する列を選択

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```

### 正規表現ライクなフィルター

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data
```

### 正規表現を使用した抽出

```
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds
```

form_data が `username=admin&passwd=batman&option=com_login&task=login` という内容であるとき、creds は `batman` になる。& が英数字アンダースコアに含まれないため。

### sysmon の EventID=1 （プロセス実行）

```
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```

## 設定ファイル

https://tryhackme.com/room/splunkdatamanipulation

### inputs.conf

データ入力と、さまざまなソースからデータを収集する方法を定義

```
[monitor:///path/to/logfile.log]
sourcetype = my_sourcetype

[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
index = main
source = vpn
sourcetype = vpn_logs
interval = 5
```

### props.conf

フィールド抽出を定義するために、さまざまなソースタイプの解析ルールを指定

```
[my_sourcetype]
EXTRACT-field1 = regular_expression1
EXTRACT-field2 = regular_expression2

例：DISCONNECT または CONNECT の後をイベント区切りとする
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)

例：[Authentication] の前をイベント区切りとする
[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]

例：クレジットカード番号の後の12桁をマスクする
[purchase_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \d{4}\.
SEDCMD-cc = s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g

# transforms.conf と紐づける場合は必要
TRANSFORM-customfields = network_custom_fields
```

### transforms.conf

インデックス付きイベントのフィールド変換とエンリッチメントを定義

```
[add_new_field]
REGEX = existing_field=(.*) FORMAT = new_field::$1

# User: ***** ****, の部分を切り出す設定
# この場合、props.conf に、下記のような指定が必要
# TRANSFORM-vpn = vpn_custom_fields

[vpn_custom_fields]
REGEX = User:\s([\w\s]+)
FORMAT = Username::$1
WRITE_META = true

[vpn_custom_fields_two]
REGEX = User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)
FORMAT = Username::$1 Server::$2 Action::$3
WRITE_META = true
```

- SHOULD_LINEMERGE = true の場合、正規表現内で改行は不要なことに注意

### fields.conf

インデックス時にフィールドとして処理する項目を指定

```
# transforms.conf の設定内容に対応している

[Username]
INDEXED = true

[Server]
INDEXED = true

[Action]
INDEXED = true
```

### indexes.conf

ストレージ、保持ポリシー、アクセス制御など、Splunk のインデックスの構成を管理

```
[my_index]
homePath = $SPLUNK_DB/my_index/db
coldPath = $SPLUNK_DB/my_index/colddb
thawedPath = $SPLUNK_DB/my_index/thaweddb
maxTotalDataSizeMB = 100000
```

### outputs.conf

インデックス付きデータをリモート Splunk インスタンスやサードパーティ システムなどのさまざまな出力に送信するための宛先と設定を指定

```
[tcpout] defaultGroup = my_indexers
[tcpout:my_indexers]
server = remote_indexer:9997
```

### authentication.conf

認証設定とユーザー認証方法を管理

```
[authentication]
authSettings = LDAP
[authenticationLDAP]
SSLEnabled = true
```
