# ElasticSearch

## 基本

### インストール

```shell
sudo su

# 生成パスワード、その他コマンドが表示されるのでメモを忘れずに
# パスワードは elastic ユーザーのもの。
dpkg -i elasticsearch.deb

systemctl enable elasticsearch.service
systemctl start elasticsearch.service
```

### 構成ファイル

`/etc/elasticsearch`

- `elasticsearch.yml` メイン設定
- `jvm.options` JVM 設定
- `log4j2.properties` ロギング関連設定
- `users` ユーザー認証と認可の設定
- `roles.yml`、`roles_mapping.yml` ロールとユーザーおよび権限のマッピングを定義
