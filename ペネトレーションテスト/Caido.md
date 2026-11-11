# Caido

https://tryhackme.com/room/caidobasics

https://tryhackme.com/room/caidocoretools

## インストール

### debパッケージをインストール

https://www.caido.io/download/

```sh
# install
sudo apt install ~/Downloads/caido-desktop-v0.59.0-linux-x86_64.deb

# 起動
caido
```

### ブラウザ拡張機能

ChromeかFireFoxで、Caido を検索してインストール。  
ローカルでcaidoが起動していたら、Auto Detect で自動検出できる。

### CA証明書

1. Caido右上のユーザーアイコンからCA証明書を選択
2. プラットフォームを選択してダウンロードを実行
3. ブラウザの設定からロードする

## HTTPQL

### 基本構造

#### 名前空間 - クエリ対象

- req- リクエストデータ（メソッド、URL、ヘッダー、ボディ）
- resp- レスポンスデータ（ステータスコード、ヘッダー、本文）
- row- テーブルメタデータ（行ID、タイムスタンプ）

#### フィールド - どのプロパティを調査するか

host, method, path, query, code, raw, etc.

#### 演算子 - マッチング方法

eq (equals), cont (contains), regex, gt (greater than), etc.

#### 値 - 何にマッチするか

- String: "POST", "api", ".js"
- Number: 200, 404, 500
- Date: "2025-07-22 16:00:00"

| **演算子** | **意味** | **使用例** | **用途** |
| :--- | :--- | :--- | :--- |
| eq | 等しい（完全一致） | `req.method.eq:"POST"` | 特定のHTTPメソッドを検索する |
| ne | 等しくない | `resp.code.ne:200` | 成功レスポンスを除外する |
| cont | 含む（大文字・小文字を区別しない） | `req.path.cont:"api"` | APIエンドポイントを検索する |
| ncont | 含まない | `req.host.ncont:"staging"` | ステージング環境への通信を除外する |
| regex | 正規表現 | `req.path.regex:"/v[1-3]/"` | 特定のパターンに一致する通信を検索する |
| gt | より大きい | `resp.code.gt:399` | エラーレスポンス（4xx/5xx）を検索する |
| lt | より小さい | `resp.code.lt:400` | 成功レスポンスを検索する |
| like | SQLのLIKE演算子 | `req.ext.like:"%.js"` | ワイルドカードを使用して一致する通信を検索する |

### HTTPQLの例

#### 特定のリクエストタイプの検索

| **説明** | **HTTPQLクエリ** |
| :--- | :--- |
| POSTリクエストのみを表示 | `req.method.eq:"POST"` |
| すべてのAPIエンドポイントを表示 | `req.path.cont:"api"` |
| JavaScriptファイルを検索 | `req.ext.eq:".js"` |

#### 回答の分析

| **説明** | **HTTPQLクエリ** |
| :--- | :--- |
| 認証失敗箇所を特定 | `resp.code.eq:401` |
| すべてのエラー（4xxおよび5xx）を表示 | `resp.code.gt:399` |
| Cookie設定に関する応答を検索 | `resp.raw.cont:"Set-Cookie:"` |

#### 高度なセキュリティテスト

| **説明** | **HTTPQLクエリ** |
| :--- | :--- |
| CSRF脆弱性の可能性があるリクエスト（CSRFトークンのないAPIへのGET以外のリクエスト）を検出 | `req.host.cont:"api" AND req.query.ncont:"xsrf_param" AND req.method.ncont:"GET"` |
| 特定のCookieを含むリクエストを特定 | `req.raw.cont:"cookieVal" AND resp.raw.cont:"Set-Cookie: j=cookieVal"` |
| 5分前のリクエストを検索 | `req.path.cont:"thatOneReq" AND req.created_at.gt:"2025-07-22 16:00:00"` |
| レガシーAPIバージョン（v1、v2、v3）のみを表示 | `req.path.regex:"/v[1-3]/"` |
| バージョン管理されたエンドポイントをすべて検索 | `req.path.regex:"/api/v[1-9]/"` |

#### クエリの組み合わせ

論理演算子を使用して複数の条件を組み合わせることができる。

| **説明** | **HTTPQLクエリ** |
| :--- | :--- |
| AND：両方の条件を満たす通信を検索 | `req.path.cont:"api" AND resp.code.eq:200` |
| OR：いずれかの条件を満たす通信を検索 | `resp.code.eq:401 OR resp.code.eq:403` |
| 括弧を使用して条件をグループ化 | `(req.method.eq:"POST" OR req.method.eq:"PUT") AND resp.code.gt:399` |

## スコープとフィルター

### スコープ

スコープは、テスト対象のドメインまたはサブドメインを定義する。  
スコープタブの New Preset から作成し、HTTP History タブなどで選択して有効化する。

### フィルター

フィルターを使用すると、HTTPQLクエリを再利用可能なプリセットとして保存できる。  
フィルタータブの New Preset から作成し、HTTP History のHTTPQLから選択。

スコープとフィルターは、インターセプトの条件としても利用できる。
