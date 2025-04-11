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
