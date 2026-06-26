# EQL

https://tryhackme.com/room/detectionrulesdevelopment

EQL（Event Query Language）は、Elasticが独自に開発した、時間的な制約を持つイベントシーケンスを表現するための言語。KQLが個々のドキュメントに一致するのに対し、EQLは複数のロジックにわたる順序付きパターンに一致する。

## 相関ベース検出

Elastic のルール作成で、Event Correlation を選択する。

「同じ送信元IPアドレスからの複数回のログオン失敗、それに続く認証成功」の検出例

```
sequence by source.ip with maxspan=5m
  [authentication where event.code == 4625 and 
      winlog.event_data.LogonType == 3] with runs = 10
  [authentication where event.code == 4624 and 
      winlog.event_data.LogonType == 10]
```
