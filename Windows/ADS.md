# ADS (Alternate Data Streams)

### 書き込み

```powershell
# example ファイルの showme ストリームに hello を書き込む
echo hello > example:showme

set-content -path example -stream showme
```

### 表示

```powershell
# showme ストリームの内容を表示する
get-content -path example -stream showme
hello

# PowerShell Core (7.x以降) ならワイルドカード使用可能
get-content -path example -stream *

# sysinternals の streams コマンドでは中身は表示されない
streams example

E:\tmp\example:
         :showme:$DATA 8
```

### 検索

```powershell
# Windows フォルダを含めたら膨大な出力になるので含めないよう注意
gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'
```

### 削除

ちなみにテキストエディタで上書きしたら ADS は全部消える

```powershell
remove-item –path example –stream showme
```
