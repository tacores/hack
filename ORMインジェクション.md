# ORM インジェクション

## フレームワークの識別

ORMインジェクションはORMによって方法が異なるため、フレームワークを識別することが第一歩になる。下記の部分にフレームワーク固有の情報が出ていないか着目する。

- Cookie
- HTMLソースコード
- HTTPヘッダー
- URL構造
- ログインページ、エラーページ

## 実装

### 脆弱な実装
```php
$users = User::whereRaw("email = '1' OR '1'='1'")->get();
```

### 安全な実装

パラメータ化されたクエリを使う

```php
$users = User::where('email', $email)->get();
```
