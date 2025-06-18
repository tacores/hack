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

## 接続

```shell
# バックスラッシュが正式だが、エスケープが面倒なので環境が許せばスラッシュの方が楽
smbclient //$TARGET/<share> -U <user>
```

### 再帰的にファイル取得

```shell
smbget -R smb://$TARGET/anonymous
```
