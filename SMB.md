# SMB

## 列挙

```shell
# -U ユーザーリストを取得
# -M マシンリストを取得
# -N ネームリストダンプを取得 (-U および -M とは異なります)
# -S シェアリストを取得
# -P パスワードポリシー情報を取得
# -G グループとメンバーリストを取得
# -a 上記のすべて（完全な基本列挙）
enum4linux -S $TARGET

# -R RID
enum4linux -R 1000-1003 $TARGET
```

```sh
# 無名ログイン
smbclient -L \\$TARGET -U ""

# パスワードなしログイン
smbclient -L //$TARGET -N
```

## 接続

```shell
# バックスラッシュが正式だが、エスケープが面倒なので環境が許せばスラッシュの方が楽
smbclient //$TARGET/<share> -U <user>
```

### 再帰的にファイル取得

```shell
smbget -R smb://$TARGET/anonymous
```

smbclient のプロンプトでも可能。

```sh
recurse ON
prompt OFF
mget *
```

### 再帰的に表示

```sh
smbmap -u "user" -p "pass" -H $TARGET -r
```

### 接続可否の確認

```sh
crackmapexec smb windcorp.thm -u brittanycr -p 'thm1234#'
```
