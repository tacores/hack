# Atomic Red Team

https://tryhackme.com/room/atomicredteam

https://github.com/redcanaryco/atomic-red-team

セキュリティテストと脅威エミュレーションを実行するためのフレームワークを提供するオープンソースプロジェクト。

## 基本

### Executor

| Executor   | Operating System | Notes                                                                                                     |
| ---------- | ---------------- | --------------------------------------------------------------------------------------------------------- |
| sh / bash  | Linux, macOS     | この Executor で実行されるコマンドは、通常、攻撃者が悪用する Unix 系ツールです。                          |
| cmd.exe    | Windows          | この Executor で実行されるコマンドは、攻撃者が悪用する Windows 標準またはサードパーティ製のバイナリです。 |
| PowerShell | Windows          | この Executor で模倣されるコマンドは、攻撃者に悪用される既知の悪意ある PowerShell モジュールです。        |
| Manual     | N/A              | このタイプで記載される内容は、脅威を模倣するための手順であり、GUI など自動化できない操作を含みます。      |

### 構成

```shell
user@ATOMIC$ ls -lh T1003.001/
-rw-r--r--   1 user  user       300B Jan 4 22:57 T1003.001.md
-rw-r--r--   1 user  user       500B Jan 4 22:58 T1003.001.yaml
```

MITRE ATT&CK のテクニック ID を基準に構成されている。  
詳細が yaml で定義されている。外部コマンドのパス、クリーンアップコマンドなど。  
クリーンアップをきちんとしないとそれが悪用される可能性があるため、クリーンアップは重要。

### Invoke-AtomicRedTeam

https://github.com/redcanaryco/invoke-atomicredteam/wiki

Invoke-AtomicRedTeam は、Atomic Red Team プロジェクトの atomics フォルダに定義されたテストを実行する PowerShell モジュール。

## コマンド

### モジュールのロード

```ps
# モジュールの読み込み中に表示されるすべてのセキュリティ警告を無視する
powershell -ExecutionPolicy bypass

# モジュール読み込み
Import-Module "C:\Tools\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Atomics フォルダの場所を指定（デフォルトは、 C:\AtomicRedTeam\atomics）
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\Tools\AtomicRedTeam\atomics"}

# 読み込まれたか確認
help Invoke-AtomicTest
```

### テスト説明

```ps
# 簡潔な説明（テスト番号がリストされるだけ）
Invoke-AtomicTest T1127 -ShowDetailsBrief

# 詳細な説明
Invoke-AtomicTest T1127 -ShowDetails
```

### 依存関係

```ps
# 依存関係の事前チェック
Invoke-AtomicTest T1127 -CheckPrereqs

# 依存関係をインターネットから自動的に取得
Invoke-AtomicTest T1127 -GetPrereqs
```

### テスト実行

```ps
# テスト番号指定
Invoke-AtomicTest T1127 -TestNumbers 1,2

# テスト名指定
Invoke-AtomicTest T1127 -TestNames "Lolbin Jsc.exe compile javascript to dll"

# テストGUID指定
Invoke-AtomicTest T1127 -TestGuids 3fc9fea2-871d-414d-8ef6-02e85e322b80

# 全てのテスト
Invoke-AtomicTest T1127

# テスト番号指定のもうひとつの方法
Invoke-AtomicTest T1127-2
```

```ps
# クリーンアップ実行
Invoke-AtomicTest T1053.005 -TestNumbers 1,2 -Cleanup
```

```ps
# Mitre ID に対応する Atomic が存在するか確認する
ls C:\Tools\AtomicRedTeam\atomics | Where-Object Name -Match "T1566.001|T1203|T1059.003|T1083|T1082|T1016|T1049|T1007|T1087.001"

# テスト一覧
'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -ShowDetailsBrief }

# 前提条件の確認
'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -CheckPrereqs }
```

## カスタムテスト

必要なテストがリポジトリに含まれていない場合 h、Atomic テストを GUI で生成できるツールもある。

https://github.com/redcanaryco/invoke-atomicredteam/wiki/The-atomic-GUI
