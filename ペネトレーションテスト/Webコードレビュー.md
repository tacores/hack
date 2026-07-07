# Webコードレビュー

https://tryhackme.com/room/webframeworkscodereview

## 基礎

### 読む順番

| ステップ | 何を読むべきか | それが私たちに教えてくれること |
|---------|----------------|--------------------------------|
| 1 | READMEとドキュメント | アプリの機能、実行方法、使用されているフレームワーク |
| 2 | 依存関係マニフェスト | ライブラリとバージョン、サードパーティの攻撃対象領域 |
| 3 | 設定ファイル | デバッグフラグ、シークレット、データベース文字列 |
| 4 | 経路／入口 | 侵入経路の全リスト、攻撃対象領域マップ |
| 5 | 認証ミドルウェアとデコレーター | どのルートが保護されているか、どのルートが保護されていないか |
| 6 | データベース/モデル層 | データの保存場所とクエリの構築方法 |
| 7 | 個別のルートハンドラー | 各エントリーポイントの背後にあるロジック |

### source と sink

- source はユーザーが制御するデータがアプリケーションに入力される場所。
- sink は攻撃者からの入力が与えられた際に危険となるあらゆる操作。
- sink単体ではバグではない。sourceからsinkへ到達する経路に安全なステップが存在しないsinkはバグである。

## 検索

### grep

```sh
grep -rn --include="*.py" -E "os\.system|subprocess|eval\(|exec\(|pickle\.loads|render_template_string|cursor\.execute|send_file|open\(" .

grep -rnE "(SECRET|KEY|TOKEN|PASSWORD|API_KEY)\s*=\s*['\"]" --include="*.py" .

grep -rnE "DEBUG\s*=\s*True|TESTING\s*=\s*True|verify\s*=\s*False" .

grep -rE "AKIA[0-9A-Z]{16}" .

```

### [semgrep](https://github.com/semgrep/semgrep)

構文解析を活用してバグやセキュリティの脆弱性を検出する高速でオープンソースの静的解析ツール

```sh
pip install semgrep

# インターネット接続が必要
semgrep --config p/owasp-top-ten .

# ローカルのルールファイルを指定
semgrep --config /opt/review/semgrep-rules .
```

#### カスタムルール

```yaml
rules:
  - id: render-template-string-usage
    pattern: render_template_string(...)
    message: render_template_string on possible user input, check for SSTI
    severity: WARNING
    languages: [python]
```
