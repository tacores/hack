# KQL (Kibana Query Language)

https://www.elastic.co/guide/en/kibana/7.17/kuery-query.html

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
