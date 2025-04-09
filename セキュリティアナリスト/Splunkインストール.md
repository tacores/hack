# Splunk インストール

https://tryhackme.com/room/splunklab

前提としてユーザーアカウントが必要。  
https://www.splunk.com/

## Linux

### Enterprise の解凍と配置

```shell
sudo su
tar xvzf splunk_installer.tgz
mv splunk /opt/
```

```shell
cd /opt/splunk/bin

# 初回起動時、Splunk管理者のユーザー名とパスワードを決める
./splunk start --accept-license
```

### ユニバーサールフォワーダー

```shell
sudo su
tar xvzf splunkforwarder.tgz
mv splunkforwarder /opt/
```

```shell
cd /opt/splunkforwarder

# 初回起動時、Splunk管理者のユーザー名とパスワードを決める（Enterpriseとは別扱い）
./bin/splunk start --accept-license
```

### よく使うコマンド

/opt/splunk がカレントディレクトリであるとする。

```shell
# サーバー起動、停止、再起動
./bin/splunk start
./bin/splunk stop
./bin/splunk restart

# ステータス確認
./bin/splunk status

# インデックスに単一のイベントを追加する
./bin/splunk add oneshot

# 検索
./bin/splunk search <keyword>

# ヘルプ
./bin/splunk help
```

### データ取り込み

- ヘビーフォワーダーとユニバーサルフォワーダーの 2 種類がある。
- ヘビーフォワーダーは送信前にフィルター、分析、変更等の処理を行う。
- ユニバーサルフォワーダーは軽量エージェントで、そのまま送信する。

ユニバーサールフォワーダーは別途ダウンロードが必要。  
https://www.splunk.com/en_us/download/universal-forwarder.html?locale=en_us

#### 受信ポートの設定

1. 8000 ポートの管理画面から「設定」「転送と受信」を表示
1. 「受信の構成」から「新しい受信ポート」を選択
1. データ受信のポートを設定。デフォルトは 9997。

#### インデックスの作成

※インデックスを作成しないと、デフォルト（main）インデックスに保存される。

1. 8000 ポートの管理画面から「設定」「インデックス」を表示。
1. 適切な名前を付けて保存。

#### フォワーダーの設定

```shell
cd /opt/splunkforwarder/bin

# フォワーダーサーバーを追加
./splunk add forward-server <ip>:9997

# syslogファイルを取り込む
./splunk add monitor /var/log/syslog -index Linux_host
# authlog
./splunk add monitor /var/log/auth.log -index Linux_host

# 設定内容の確認
cat /opt/splunkforwarder/etc/apps/search/local/inputs.conf

# テストログの作成
logger "coffely-has-the-best-coffee-in-town"
```

## Windows

Enterprise インストーラーをダウンロードして実行する。  
途中で管理アカウントを作成する。

`C:\Program Files\Splunk`

### データの取り込み

#### 受信ポートの設定

Linux と同じ

#### ユニバーサルフォワーダー

- インストーラーを実行
- Splunk フォワーダーを複数のホストにインストールする場合のため、デプロイメントサーバーのセットアップ可能。オプションのためスキップ可能。
- リスナーの設定（リスナー 9997 ポート指定）

#### データ追加

- 「設定」、「データ追加」、「フォワード」。
- フォワーダーを選択して Next。
- Local Event Logs からログの種類を選択できる。（Application、Security、System など）。ディレクトリ選択なども可能。選択したら Next。
- インデックスを作成
