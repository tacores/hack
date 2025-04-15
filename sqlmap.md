# sqlmap

https://tryhackme.com/room/sqlmap

## コマンドオプション

### 基本オプション

| オプション            | 説明                                                  |
| --------------------- | ----------------------------------------------------- |
| `-u URL`, `--url=URL` | 対象の URL（例: "http://www.site.com/vuln.php?id=1"） |
| `--data=DATA`         | POST で送信するデータ文字列（例: "id=1"）             |
| `--random-agent`      | ランダムに選ばれた HTTP User-Agent ヘッダーを使用     |
| `-p TESTPARAMETER`    | テスト対象のパラメータ                                |
| `--level=LEVEL`       | 実行するテストのレベル（1〜5、デフォルトは 1）        |
| `--risk=RISK`         | 実行するテストのリスクレベル（1〜3、デフォルトは 1）  |
| `-h`                  | ヘルプ                                                |
| `-hh`                 | Advanced ヘルプ                                       |

### 列挙オプション

| オプション        | 説明                                                   |
| ----------------- | ------------------------------------------------------ |
| `-a`, `--all`     | すべての情報を取得する                                 |
| `-b`, `--banner`  | DBMS のバナー情報を取得する                            |
| `--current-user`  | DBMS の現在のユーザーを取得する                        |
| `--current-db`    | DBMS の現在のデータベースを取得する                    |
| `--passwords`     | DBMS ユーザーのパスワードハッシュを列挙する            |
| `--dbs`           | DBMS のデータベースを列挙する                          |
| `--tables`        | DBMS のデータベーステーブルを列挙する                  |
| `--columns`       | DBMS のデータベーステーブルのカラムを列挙する          |
| `--schema`        | DBMS のスキーマを列挙する                              |
| `--dump`          | DBMS のデータベーステーブルのデータをダンプする        |
| `--dump-all`      | すべての DBMS データベーステーブルのデータをダンプする |
| `--is-dba`        | 現在の DBMS ユーザーが DBA（管理者）かどうかを検出する |
| `-D <DB NAME>`    | 列挙対象の DBMS データベースを指定する                 |
| `-T <TABLE NAME>` | 列挙対象の DBMS データベーステーブルを指定する         |
| `-C COL`          | 列挙対象の DBMS データベーステーブルのカラムを指定する |

### OS アクセスオプション

| オプション       | 説明                                                                          |
| ---------------- | ----------------------------------------------------------------------------- |
| `--os-shell`     | 対話型の OS シェルを起動するプロンプトを表示                                  |
| `--os-pwn`       | OOB シェル、Meterpreter、または VNC の起動プロンプトを表示                    |
| `--os-cmd=OSCMD` | 指定した OS コマンドを実行する                                                |
| `--priv-esc`     | データベースプロセスユーザーの権限昇格を試みる                                |
| `--os-smbrelay`  | ワンクリックで OOB シェル、Meterpreter、または VNC を起動するプロンプトを表示 |
| `--sql-shell`    | 対話型の SQL シェルを起動するプロンプトを表示                                 |

## 実行方法

Burp 等でファイル保存したリクエストを利用するのが簡単。

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
