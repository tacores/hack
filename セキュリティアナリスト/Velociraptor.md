# Velociraptor

https://tryhackme.com/room/velociraptorhp

https://docs.velociraptor.app/

ユニークで高度なオープンソースのエンドポイント監視、デジタルフォレンジック、サイバー対応プラットフォーム。

## 展開

Velociraptor は、実行ファイルがサーバーまたはクライアントとして機能し、 Windows、Linux、MacOS で実行できるという点でユニーク。また、Velociraptor は、 Amazon EFS や Google Filestore などのクラウド ファイル システムとも互換性がある。

https://docs.velociraptor.app/docs/deployment/

```shell
# Start the Velociraptor Server (Ubuntu Terminal):
cd velociraptor
./velociraptor-v0.5.8-linux-amd64 --config server.config.yaml frontend -v

# Add Windows as a client (CMD)
velociraptor-v0.5.8-windows-amd64.exe --config velociraptor.config.yaml client -v
```

### Instant Velociraptor

ローカル マシンにのみ展開される、完全に機能する Velociraptor システム

https://docs.velociraptor.app/docs/deployment/#instant-velociraptor

```
Velociraptor.exe gui
```

## クライアントとのやり取り

`Show All` ボタンを押すとクライアントが表示され、操作できるようになる。

- クライアントから 24 時間通信が無い場合は、状態が赤い点になる
- シェルを実行する機能、履歴を表示する機能などがある

### 収集

https://docs.velociraptor.app/docs/artifacts/

- アーティファクト選択で `Windows.KapeFiles.Targets` などを選択
- Configure で収集したい項目を選択
- Launch を押すと実行される

### VFS（仮想ファイルシステム）

https://docs.velociraptor.app/docs/clients/vfs/

クライアントのファイルシステムと対話するためのインターフェイス

- file
- ntfs
- registry
- artifact

## VQL（ヴェロキラプトルクエリ言語）

https://docs.velociraptor.app/docs/vql/

- notebook タブからノートを作成できる。jupyter と似ている。
- タイプを MarkDown ではなく、VQL を指定することに注意。
- ノートブックの補完機能を使うには、`?` を入力。
- コマンドラインから実行することも可能。

```cmd
velociraptor.exe -v query "SELECT * FROM info()"
```

### 構文

```
SELECT <Column Selectors> FROM <VQL plugin> WHERE <filter expression>
```

VQL リファレンス  
https://docs.velociraptor.app/vql_reference/

フォレンジックのためには、適したプラグインを探すことが肝要  
https://docs.velociraptor.app/docs/forensic/

## アーティファクト交換

https://docs.velociraptor.app/exchange/

コミュニティによるアーティファクトを見ることができ、参考になる。  
公式のレビューや承認は一切受けていないので、使用する場合は展開する前に内容を完全に理解することが必須。
