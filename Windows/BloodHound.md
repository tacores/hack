# BloodHound

https://github.com/BloodHoundAD/BloodHound

1. bloodhound-python や SharpHound で列挙し、jsonファイルを固めたzipファイルを出力
2. neo4j を起動
3. bloodhound でグラフ表示

列挙は「騒がしい」プロセスで、大量のイベントログを生成するため、初回は All、次回以降はセッションのみといった運用が必要。セッションは頻繁に列挙しなおす必要がある。

１．列挙を実行

```sh
bloodhound-python -u asrepuser1 -p qwerty123! -d tryhackme.loc -ns 10.211.12.10 -c All --zip
```

２．neo4j を起動

```sh
sudo neo4j start
```

３．Bloodhound を起動  

```sh
bloodhound --no-sandbox
```

GUI に zip ファイルを D&D したらインポートされる。

## SharpHound（Windows）

```ps
# 全部列挙
# アウトプットとして zipファイルが作成される
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

# セッションだけ
SharpHound.exe --CollectionMethods Session --Domain za.tryhackme.com --ExcludeDCs
```

```shell
# kali に zip をコピー
scp <AD Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .
```

--ExcludeDCs は DC を除外し、検出リスクを下げる。

```sh
.\SharpHound.exe --CollectionMethods All --Domain tryhackme.loc --ExcludeDCs
```
