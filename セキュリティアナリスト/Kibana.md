# Kibana

## 基本

### インストール

```shell
dpkg -i kibana.deb

systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
```

### 構成ファイル

`/etc/kibana`

- `kibana .yml` メイン設定
- `kibana .keystore` パスワードや API キーなどの機密性の高い設定情報を安全に保存する。

確認コード

```
/usr/share/kibana/bin/kibana-verification-code
```
