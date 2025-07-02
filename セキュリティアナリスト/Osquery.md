# Osquery

https://tryhackme.com/room/osqueryf8

https://osquery.io/

## 基本

```shell
# インタラクティブモード起動
osqueryi
```

```shell
# ヘルプ
.help

# クエリ可能なテーブル一覧
.table

# process テーブルを確認
.table process

# user という用語が含まれるすべてのテーブル一覧
.table user

# テーブルスキーマ
.schema <table_name>
```

```shell
# 表示モード変更
.mode <MODE>

# .help で使用可能なモードが一覧表示される。
    csv      Comma-separated values
    column   Left-aligned columns see .width
    line     One value per line
    list     Values delimited by .separator string
    pretty   Pretty printed SQL results (default)
```

## スキーマドキュメント

https://osquery.io/schema/

- 表示する Osquery バージョンを選択できる
- テーブル件数が表示される（フィルター後の数）
- テーブル名と簡単な説明
- 列、タイプ、説明
- OS の種類でフィルターできる

## SQL クエリ

- 完全な SQL 言語ではなく、SQLite のスーパーセット。
- 基本的に SELECT のみ。エンドポイントのデータを更新することはない。
- DELETE や UPDATE は、ビューのための使用に限られる。
- 一部のテーブルでは WHERE 句が必須になっている。

### 例

```sql
# LIMIT
SELECT * FROM programs LIMIT 1;

# count
SELECT count(*) from programs;

# WHERE
SELECT * FROM users WHERE username='James';
```

```sql
# JOIN
select p.pid, p.name, p.path, u.username from processes p JOIN users u on u.uid=p.uid LIMIT 10;

# 個人的には下記の方が馴染みがある
(select p.pid, p.name, p.path from processes p) JOIN (select u.username from users u) on u.uid=p.uid LIMIT 10;

select p.pid, p.name, p.path, u.username from processes p, users u where u.uid=p.uid LIMIT 10;
```

### プロセス

```sql
-- ファイルレスマルウェアの可能性
SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;

-- 親プロセスが欠落しているプロセス
SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);

-- ユーザーディレクトリから起動
SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';

-- tmpディレクトリから起動
SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';
```

### ネットワーク

```sql
-- ネットワーク接続
SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;

-- リモート接続
SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;

-- リスニングポート
SELECT * FROM listening_ports;
```

### ディスク上のTTPフットプリント

```sql
-- 開いているファイル
SELECT pid, fd, path FROM process_open_files;

SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';

-- 最近変更されたファイル
SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));
```
