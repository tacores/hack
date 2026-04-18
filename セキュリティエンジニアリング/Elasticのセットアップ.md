# Elastic のセットアップ

https://tryhackme.com/room/elasticlab

## Elastic Search と Kibana のデプロイ

```sh
sudo su
ls
elasticagent  elasticsearch.deb  kibana.deb
```

elastic ユーザーのパスワードが表示されるのでメモしておくこと。

```sh
dpkg -i elasticsearch.deb
```

メモリ使用量の制限

```sh
nano /etc/elasticsearch/jvm.options.d/heap.options

# 設定例。起動時に確保するサイズと最大サイズ
-Xms1g
-Xmx1g
```

```sh
systemctl start elasticsearch
systemctl enable elasticsearch
systemctl status elasticsearch
```

```sh
dpkg -i kibana.deb
```

```sh
nano /etc/kibana/kibana.yml

# 末尾に追加。
xpack.encryptedSavedObjects.encryptionKey: "soc-lab-training-key-32chars-long!"
xpack.fleet.registryUrl: "http://localhost:8081"
```

```sh
systemctl start kibana
systemctl enable kibana
systemctl status kibana
```

Kibana にアクセスすると、Enrolement token を要求される。  
http://localhost:5601/

```sh
# 登録トークンを作成する
/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# 確認コードを作成する
/usr/share/kibana/bin/kibana-verification-code
```

表示されたトークンとコードを順番に入力すると構成処理が始まる。  
インストール時に表示された、elastic ユーザーのパスワードを入力してログイン。

## Fleet Server と Elastic Agent のデプロイ

### Fleet

Kibana の左上のメニューから、Management -> Fleet。`Add Fleet Server` を押下。

Name, URL を入力。例：fleet-server, https://10.144.186.21:8220  
`Generate Fleet Server policy` をクリック。

下記のようなコマンドが表示されるのでコピーしてエージェントで実行する。  
本番ではない環境で動かすため、手作業で末尾に `--insecure` を追加した。

```sh
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.2.4-linux-arm64.tar.gz
tar xzvf elastic-agent-9.2.4-linux-arm64.tar.gz
cd elastic-agent-9.2.4-linux-arm64
sudo ./elastic-agent install \
  --fleet-server-es=https://10.144.186.21:9200 \
  --fleet-server-service-token=AAEAAWVsYXN0aWMvZmxlZXQtc2VydmVyL3Rva2VuLTE3NzYzMDMyNTgxOTk6b2ctNkswV3hRbWFZeDNMM28tR1ZMUQ \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca-trusted-fingerprint=8f8fd596ca2ca5dfb61c9bb030b121cf745ed386cbb95ab1502b49c75e605f32 \
  --fleet-server-port=8220 \
  --install-servers
  --insecure
```

### Agent

```sh
cd elasticagent

# elastic-agent が入っているディレクトリで上記のコマンドを実行
```

## Webログの統合

1. Kibanaメニューで、Management -> Integrations
2. `Apache HTTP Server` を検索
3. `Add Apache HTTP Server` をクリック
4. `Existing hosts` を選択
5. `Save and Continue` を選択
6. `Save and deploy changes` を選択

## カスタムログ

Tryhackmeのタスク6参照

## ダッシュボード

Tryhackmeのタスク7参照
