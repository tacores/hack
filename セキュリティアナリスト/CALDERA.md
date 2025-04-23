# CALDERA

https://github.com/mitre/caldera

https://tryhackme.com/room/caldera

自律的な敵対者エミュレーション演習を効率的に実行するために設計されたオープンソースフレームワーク。ユーザーは、現実世界の攻撃シナリオをエミュレートし、セキュリティ防御の有効性を評価することができる。

## Red の基本的なフロー

### サーバーの実行

```shell
# CALDERA サーバーを実行
ubuntu@tryhackme:~$ cd Rooms/caldera/caldera

ubuntu@tryhackme:~/Rooms/caldera/caldera$ source ../caldera_venv/bin/activate

(caldera_venv) ubuntu@tryhackme:~/Rooms/caldera/caldera$ python server.py --insecure
```

### エージェントの導入

1. CALDERA サーバーの Web 画面にログイン
1. サイドバーの Agent ボタンをクリック、Deploy a agent。
1. プラットフォームに応じたエージェントを選択（Windows なら Manx エージェント）
1. IP アドレス等を適切に設定する
1. エージェントマシンで実行するべきコマンドが表示されているので、コピー
1. エージェントマシンでコマンド実行

成功したら、エージェントタブにエージェントが表示される。

### 敵対者プロファイル

1. サイドバーの Adversaries ボタンをクリック
1. 検索窓でプロファイルを選択する（Enumerator など）
1. 実行するアビリティのリストが下に表示される
1. アビリティをクリックすると、詳細が表示される

### オペレーションの実行

1. サイドバーの Operations ボタンをクリック
1. オペレーションの作成をクリック
1. プロファイルを選択
1. Advanced で、適切なグループを選択。（グループに対応するエージェントのみでアビリティが実行される）
1. 難読化するかどうかを選べる
1. Start をクリックしてオペレーションを開始

### 結果の確認

1. View Command, View Output をクリックして結果を確認する。

## Blue

### Response プラグイン

レスポンスプラグインは、CALDERA の脅威エミュレーションプラグインに対応するプラグイン。主に検知と対応アクションに重点を置いた機能を備えている。

### 防御者プロファイル

1. サイドバーの Defenders ボタンをクリック
1. プロファイルを選択（Incident Responder など）

### ファクトとソース

- Fact とは識別可能なデータ。エージェントがアビリティ実行中に取得したり、事前設定された設定から読み込んだりすることができる。
- Source とは、Fact のグループ

```ps
# remote.port.unauthorized に含まれるFactの数だけコマンドを実行する
Get-NetTCPConnection -RemotePort "#{remote.port.unauthorized}" -EA silentlycontinue | where-object { write-host $_.OwningProcess }
```

### エージェントの展開

1. Sandcat 等のエージェントを選択して作成
1. 適切な設定値を入れる
1. Deploy as a blue-team agent instead of red のコマンドをコピペして実行
