# Nessus

https://tryhackme.com/room/rpnessusredux

## インストール

1. Essentials のアクティベーションコードを取得

https://www.tenable.com/products/nessus/nessus-essentials

2. メールで URL が送られるので、ダウンロードしてインストール

```sh
sudo dpkg -i package_file.deb

sudo /bin/systemctl start nessusd.service
```

3. アクティベーションコードを入れ、ログイン用ユーザー名とパスワードを決める。

https://localhost:8834/

アカウント作成の画面が出てきたらスキップすればアクティベーションコードを入れる画面が出てくる。
