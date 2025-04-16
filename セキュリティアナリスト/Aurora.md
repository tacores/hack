# Aurora

https://tryhackme.com/room/auroraedr

https://www.nextron-systems.com/aurora/

Sigma ルールと IOC を用いて ETW 経由でローカルイベントストリーム上の脅威パターンを検出する Windows エンドポイントエージェント。真陽性ルールに一致すると、Aurora は「応答アクション」をトリガーし、Windows イベントログビューアーに表示される。

エンタープライズ版と無料コミュニティ版の Aurora Lite がある。

```shell
# 最小限の設定で起動
aurora-agent.exe -c agent-config-minimal.yml

# サービスとして起動
aurora-agent.exe --install -c agent-config-minimal.yml

# 現在実行中のサービスからステータス取得
aurora-agent.exe --status

# サブスクライブしたチャンネルからAuroraが監視するすべてのイベントをクエリ
aurora-agent.exe --trace > aurora-trace.log

# 情報をJSON形式で出力
-json
```

出力形式

```shell
# ログファイル出力
aurora-agent.exe --logfile aurora-minimal.log

# UDP/TCP ターゲット
--udp-target
--tcp-target
host: port
```

## Aurora レスポンス

### 定義済みレスポンス

- Suspend
- Kill
- Dump

### カスタムレスポンス

| Flag               | Definition                                                                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Simulate           | ルールやレスポンスを実際には発動せずにテストするために使用されます。どのタイプのレスポンスが発動されるかを示すログが作成されます。                                             |
| Recursive          | レスポンスが子プロセスにも影響を与えることを指定するために使用されます。通常はデフォルトで有効になっています。                                                                 |
| Low privilege only | `lowprivonly` フラグで示されます。このフラグは、対象プロセスが LOCAL SYSTEM または昇格されたロールで実行されていない場合にレスポンスを発動させます。                           |
| Ancestor           | `ancestors` フラグは、レスポンスが自身ではなくプロセスの先祖に影響を与えることを示します。整数のキーと値のペアで先祖のレベル（例：1 は親プロセス、2 は祖父など）を指定します。 |
| Process ID field   | `processidfield` フラグは、レスポンスの影響を受けるプロセス ID を含むフィールドを指定します。                                                                                  |

### 例

#### １：親プロセスを Kill

```yaml
response:
  type: predefined
  action: kill
  processidfield: ParentProcessId
```

#### ２：Suspend

```yaml
response:
  type: predefined
  action: suspend
```

#### ３：イメージをコピーするカスタムレスポンス

```yaml
response:
  type: custom
  action: cmd /c copy %Image% "%%ProgramData%%\Aurora\Image-%ProcessId%.bin"
```

### Aurora EventID

| Event ID | Description（日本語訳）                                     |
| -------- | ----------------------------------------------------------- |
| 1        | プロセス作成の Sigma ルールに一致しました。                 |
| 2        | ファイル作成時間の設定に関する Sigma ルールに一致しました。 |
| 3        | ネットワーク接続に関する Sigma ルールに一致しました。       |
| 4        | Sysmon ステータスに関する Sigma ルールに一致しました。      |
| 5        | プロセス終了の Sigma ルールに一致しました。                 |
| 6        | ドライバの読み込みに関する Sigma ルールに一致しました。     |
| 7        | イメージ読み込みに関する Sigma ルールに一致しました。       |
| 8        | リモートスレッド作成に関する Sigma ルールに一致しました。   |
| 9        | ローディスクアクセスに関する Sigma ルールに一致しました。   |
| 10       | プロセスアクセスに関する Sigma ルールに一致しました。       |
| 11       | ファイル作成に関する Sigma ルールに一致しました。           |
| 12       | レジストリイベントに関する Sigma ルールに一致しました。     |
| 15       | ストリームハッシュ作成に関する Sigma ルールに一致しました。 |
| 17       | パイプイベントに関する Sigma ルールに一致しました。         |
| 19       | WMI イベントに関する Sigma ルールに一致しました。           |
| 21       | レジストリイベントに関する Sigma ルールに一致しました。     |
| 22       | DNS クエリに関する Sigma ルールに一致しました。             |
| 23       | ファイル削除に関する Sigma ルールに一致しました。           |
| 96       | Sigma ルールが再読み込みされました。                        |
| 97       | Sigma ルールファイルが見つかりませんでした。                |
| 98       | Sigma モジュールからの未分類のログメッセージです。          |
| 99       | 他のカテゴリに該当しない Sigma ルールに一致しました。       |
| 100      | ライセンスファイルが見つかりました。                        |
| 101      | ステータスメッセージ（--report-stats から）                 |
| 102      | Aurora エージェントが開始されました。                       |
| 103      | Aurora エージェントが終了しています。                       |
| 104      | 現在のライセンスが期限切れです。                            |
| 105      | 有効なライセンスファイルが見つかりませんでした。            |
| 107      | プロセスが大量のイベントを生成しました。                    |
| 108      | 内部パニックが発生しました。                                |
| 200      | BeaconHunter（ビーコン検出ツール）                          |
| 300      | Lsass ダンプ検出ツール                                      |
| 400      | ETW カナリア（ETW モニタリング）                            |
| 500      | プロセス改ざん検出ツール                                    |
| 600      | 一時ドライバ読み込み検出ツール                              |
| 700      | コマンドライン不一致検出ツール                              |
| 800      | イベント配信モジュール                                      |
| 900      | ETW プロバイダ                                              |
| 1000     | イベントログプロバイダ                                      |
| 1100     | ハンドルポーリングプロバイダ                                |
| 1200     | リソース制御                                                |
| 6000     | Sigma ルール一致によるレスポンスが実行されました。          |
| 6001     | Sigma ルール一致によるレスポンスがシミュレートされました。  |
