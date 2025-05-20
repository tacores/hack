# KQL (Kusto)

https://tryhackme.com/room/kqlkustointroduction

https://tryhackme.com/room/kqlkustobasicqueries

https://tryhackme.com/room/kqlkustoadvancedqueries

https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference?view=azure-data-explorer&preserve-view=true

KQL（Kibana）とは全くの別物。

## KQL の例

### 1

```
Heartbeat
| summarize AggregatedHeartbeatCount = count() by Computer
| order by AggregatedHeartbeatCount desc
| take 10
```

- Heartbeat はクエリの名前ではなく、Heartbeat テーブルからデータを取得している。
- `|` はパイプ。

### 2

単に、下記を KQL とすることで、SecurityEvent テーブル全体が表示される。

```
SecurityEvent
```

### 3

```
SecurityEvent
| where TimeGenerated >= ago(3h) and TargetUserName == "JBOX00$"
| project TimeGenerated, Account, Activity, Computer
| sort by TimeGenerated desc
```

- project は 列を選択。select のような意味。

### 4

失敗したログイン試行

```
SecurityEvent
| where EventID == 4625
```

## 演算子・関数

### 一覧

| 演算子/関数名 | 説明                                                     | 例                                                                      |
| ------------- | -------------------------------------------------------- | ----------------------------------------------------------------------- |
| `search`      | 指定されたテーブルで一致する値またはパターンを検索します | `search "failed"`                                                       |
| `where`       | 条件に基づいてテーブルをフィルタリングします             | `SigninLogs \| where EventID == "4624"`                                 |
| `take`        | 結果セットで返される行数を制限します                     | `SigninLogs \| take 5`                                                  |
| `sort`        | 指定された列に基づいて並べ替えます                       | `SigninLogs \| sort by TimeGenerated, Identity desc \| take 5`          |
| `ago`         | 現在時刻からの時間オフセットを返します                   | `ago(1h)`                                                               |
| `print`       | スカラー式を含む 1 行を出力します                        | `print bin(4.5, 1)`                                                     |
| `project`     | 特定の列を選択します                                     | `Perf \| project ObjectName, CounterValue, CounterName`                 |
| `extend`      | 新しい計算列を追加します                                 | `Perf \| extend AlertThreshold = 80`                                    |
| `count`       | テーブル内のレコード数を計算します                       | `SecurityAlert \| count()`                                              |
| `join`        | 共通列に基づいて複数のテーブルを結合します               | `LeftTable \| join [JoinParameters] ( RightTable ) on Attributes`       |
| `union`       | 複数のテーブルを結合し全行を返します                     | `OfficeActivity \| union SecurityEvent`                                 |
| `range`       | クエリの時間範囲を指定します                             | `range LastWeek from ago(7d) to now() step 1d`                          |
| `summarize`   | 列と集計関数に基づいて集計します                         | `Perf \| summarize count() by CounterName`                              |
| `top`         | 上位 N 件のレコードを返します                            | `SigninLogs \| top 5 by TimeGenerated desc`                             |
| `parse`       | 正規表現で文字列を列に解析します                         | `parse kind=regex Col with * var1:string var2:long`                     |
| `render`      | グラフィック出力としてレンダリングします                 | `SecurityEvent \| render timechart`                                     |
| `distinct`    | 重複を除いた異なる組み合わせを返します                   | `SecurityEvent \| distinct Account, Activity`                           |
| `bin`         | 値を時間枠に丸めてグループ化します                       | `bin(StartTime, 1d)`                                                    |
| `let`         | 変数を定義します                                         | `let aWeekAgo = ago(7d); SigninLogs \| where TimeGenerated >= aWeekAgo` |

### SQL との比較

| Category                   | SQL                                                                      | KQL                                                                      |
| -------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| Select data from a table   | SELECT \* FROM table_name                                                | table_name                                                               |
| Select specific columns    | SELECT column1, column2 FROM table_name                                  | table_name \| project column1, column2                                   |
| Aggregation / Grouping     | SELECT DISTINCT column FROM table_name                                   | table_name \| summarize by column                                        |
| Aggregation / Grouping     | SELECT AVG(column1), SUM(column2) FROM table_name                        | table_name \| summarize AvgColumn1=avg(column1), SumColumn2=sum(column2) |
| Aggregation / Grouping     | SELECT COUNT(_) FROM dependencies GROUP BY name HAVING COUNT(_) > 3      | table_name \| summarize Count = count() by name \| where Count > 3       |
| Select top N rows          | SELECT TOP 10 \* FROM table_name                                         | table_name \| take 10                                                    |
| Filtering data             | SELECT \* FROM table_name WHERE condition                                | table_name \| where condition                                            |
| Top N by measure           | SELECT \* FROM table_name ORDER BY column                                | table_name \| order by column asc                                        |
| Top N by measure           | SELECT TOP 10 \* FROM table_name                                         | table_name \| top 10 by \*                                               |
| Join                       | SELECT \* FROM table1 INNER JOIN table2 ON table1.column = table2.column | table_name \| join kind=inner table2 on \$left.column == \$right.column  |
| Select specific columns    | SELECT name, resultCode FROM dependencies                                | table_name \| project name, resultCode                                   |
| Subquery                   | SELECT column1 FROM (SELECT \* FROM table_name) AS subquery              | let subquery = table_name; subquery \| project column1                   |
| Comparison operator (date) | SELECT \* FROM dependencies WHERE timestamp > getdate()-1                | table_name \| where timegenerated > ago(1d)                              |

### 検索演算子

複数のテーブルで

```
search in (SecurityEvent, SecurityDetection, SecurityAlert) "error"
```

全てのテーブルで

```
search "threat"
```

特定のテーブル

```
AzureNetworkAnalyticsIPDetails_CL
| search "13.89.179.10"
```

### let 文

```
let threshold = 1000;
Perf
| where CounterValue > threshold
| order by CounterValue asc
```

```
let timeOffset = 7d;
let discardEventID = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset * 2) and EventID != discardEventID
```

### 時間

| 関数名           | 説明                                                       | 例                                                                      |
| ---------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| `now()`          | クエリ実行時の現在の UTC 日時を返す                        | `now()`                                                                 |
| `ago()`          | 現在の時刻を基準とした時間枠を指定する                     | `ago(1d)`                                                               |
| `startofday()`   | 指定した日時の 1 日の開始時刻（00:00:00）を返す            | `startofday(ago(1d))` → 1 日前の 0 時 0 分 0 秒                         |
| `endofday()`     | 指定した日時の 1 日の終わり（23:59:59.999...）を返す       | `endofday(now())`                                                       |
| `datetime()`     | 指定した日時を表す                                         | `datetime(2020-12-31 23:59:59)`                                         |
| `startofmonth()` | 指定した日時の月の開始時刻（その月の 1 日 00:00:00）を返す | `startofmonth(datetime("2023-11-15T12:00:00"))` → `2023-11-01 00:00:00` |

開始時間

```
WindowsFirewall
| where TimeGenerated >= startofday(ago(1d)) and TimeGenerated < startofday(now())
```

過去 14 日間

```
Operation
| where TimeGenerated > ago(14d)
| where OperationStatus == "Warning"
| take 100
```

17 時から 22 時の時間帯以外でログイン失敗

```
SecurityEvent
| where EventID == "4625"
| where hourofday( TimeGenerated) !between (17 .. 22)
```

### 要約演算子

```
SecurityEvent
| summarize EventCount = count() by EventID
```

count\_ のような列名が自動でつけられる

```
SecurityEvent
| summarize count() by Activity
```

列の組み合わせごとにカウント

```
SecurityEvent
| where TimeGenerated > ago(3days)
| where EventID == 4648
| summarize count() by Process, Computer, AccountType
```

### レンダリング演算子

レンダリング演算子は、必ずクエリの最後。

- Bar chart
- Column chart
- Pie chart
- Area chart
- Scatter chart
- Time chart

```
SecurityEvent
| summarize count() by Computer
| render piechart
```

```
Perf
| where CounterName == "Disk Read Bytes/sec"
| summarize AvgValue = avg(CounterValue) by bin(TimeGenerated, 1h)
| render barchart
```

## 高度な演算子

### 結合演算子

```
LeftTable | join [JoinFlavor] (RightTable) on Attributes
```

結合フレーバー

| kind                          | 説明                                                           |
| ----------------------------- | -------------------------------------------------------------- |
| `inner`                       | 両テーブルの一致するすべての組み合わせを返す                   |
| `innerunique`                 | 両テーブルの一致する一意な組み合わせを返す（重複なし）         |
| `leftouter`                   | 左テーブルのすべての行と一致する右テーブルの行を返す           |
| `rightouter`                  | 右テーブルのすべての行と一致する左テーブルの行を返す           |
| `fullouter`                   | 両方のテーブルのすべての行を返し、一致しない部分は null を含む |
| `leftsemi`                    | 右テーブルと一致する左テーブルの行のみ返す                     |
| `rightsemi`                   | 左テーブルと一致する右テーブルの行のみ返す                     |
| `leftanti` / `leftantisemi`   | 右テーブルに一致しない左テーブルの行のみ返す                   |
| `rightanti` / `rightantisemi` | 左テーブルに一致しない右テーブルの行のみ返す                   |

#### 例

```
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Computer
| join kind=inner (
   Heartbeat
) on Computer
| project Computer, FailedLogins, ComputerEnvironment
```

SecurityEvent テーブルに一致するイベントがないコンピューターを Heartbeat テーブルから取得

```
SecurityEvent
| join kind=rightanti (
    Heartbeat
) on Computer
| project TimeGenerated, Computer, ComputerIP, ComputerEnvironment
```

### Union 演算子

```
SecurityEvent
| union ProtectionStatus
```

```
SecurityEvent
| summarize count() by Computer
| union (
SigninLogs
| summarize count() by Location
)
| order by count_ desc
```

### project 演算子

| オペレーター      | 説明                                         |
| ----------------- | -------------------------------------------- |
| `project`         | 列の選択、名前変更、新しい列の追加ができる   |
| `project-away`    | 指定した列を出力から除外する                 |
| `project-keep`    | 名前パターンで一致する列だけを出力に保持する |
| `project-rename`  | 列名を変更する                               |
| `project-reorder` | 出力列の順序を変更する                       |

### extend 演算子

新しい計算列を作成する。

```
SecurityEvent
| where Computer == "JBOX10"
| extend TimeSinceReboot = (now() - TimeGenerated)
| project Computer, TimeGenerated, TimeSinceReboot
```

case を使って、数値を文字列に変換

```
SecurityEvent
| extend EventCategory = case(EventID == 4624, "Logon", EventID == 4634, "Logoff", "Other")
| project TimeGenerated, AccountType, EventID, EventCategory, Computer
```

### parse 演算子

- parse 演算子は文字列式を評価し、その値を 1 つ以上の計算列に解析しる。解析に失敗した文字列は、計算列に null 値として格納される。
- parse-kv は、文字列式から構造化された情報を抽出し、キー/値形式で表現するために使用される。
- parse-where は文字列式を評価し、その値を 1 つ以上の計算列に解析するために使用される。この場合、出力は解析に失敗した文字列を除外し、解析に成功した文字列のみになる。

| kind    | 説明                                                                                           |
| ------- | ---------------------------------------------------------------------------------------------- |
| simple  | デフォルト。通常の文字列として厳密に一致させる。                                               |
| regex   | 正規表現で解析。全ての区切り文字が必要で、列の型も完全一致が必要。                             |
| flags   | regex モードで使うフラグ。例：U（非貪欲）、m（複数行）、s（改行対応）、i（大文字小文字無視）。 |
| relaxed | 区切り文字はすべて必要だが、列の型は部分一致でも許容される。                                   |

```
SecurityEvent
| where EventID == 4769
| where TimeGenerated >= ago(60d)
| parse EventData with * 'IpAddress">' IpAddress '</Data' *
| parse EventData with * 'IpPort">' IpPort '</Data' *
| parse EventData with * 'ServiceName">' ServiceName '</Data' *
| project TimeGenerated, Computer, IpAddress, IpPort, ServiceName, Activity
```
