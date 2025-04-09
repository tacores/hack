# Logstash

https://tryhackme.com/room/logstash

様々なソースからデータを収集、拡充、変換できるオープンソースのデータ処理エンジン。Elasticsearch や Kibana といった Elastic Stack の他のツールと併用することで、包括的なデータ処理・可視化パイプラインを構築できる。

## 基本

### インストール

```shell
dpkg -i logstash.deb

systemctl daemon-reload
systemctl enable logstash.service
systemctl start logstash.service
```

### 構成ファイル

`/etc/logstash`

- `logstash.yml` メイン設定
- `jvm.options` JVM 設定
- `log4j2.properties` ロギング設定
- `pipelines.yml` Logstash で複数のパイプラインを実行している場合、このファイルを使用してパイプラインを定義および構成する。
- `conf.d/` このディレクトリは、個々のパイプライン設定ファイルを保存するのによく使用される。
- `patterns/` このディレクトリには、 Logstash の grok フィルターで使用できるカスタムパターンが保存される。
- `startup.options` : 一部のシステムでは、起動時に Logstash に渡すことができる追加のオプションと引数を含むこのファイルが見つかる場合がある。
- ``

logstash.yml

```
# 3 秒ごとに構成ファイルを調べて、取り込まれているログ ソースに変更があるかどうかを確認するようになる。
config.reload.automatic: true
config.reload.interval: 3秒
```

### 実行方法

```shell
logstash -f <conffile>.conf

logstash -e "<filter>"
```

### プラグイン

大きく分けて、入力、フィルター、出力の 3 構成になる。

#### TCP 入力

https://www.elastic.co/guide/en/logstash/current/plugins-inputs-tcp.html

ドキュメントを参照すると、port のみ必須パラメータであると分かる。

```
input
{
    tcp {
        port => 5456
    }
}
```

#### JSON フィルター

https://www.elastic.co/guide/en/logstash/current/plugins-filters-json.html

source が必須。

```
filter
{
    json {
        source => "message"
    }
}
```

#### ElasticSearch 出力

https://www.elastic.co/guide/en/logstash/current/plugins-outputs-elasticsearch.html

```
output
{
  elasticsearch
   {
            hosts => ["localhost:9200"]
            index => "your_index_name"
    }
}
```

合わせて `/etc/logstash/conf.d/<name>.conf` ファイルに保存

## 入力プラグイン

### File

```
input
{
     file
          {
                     path => "/path/to/your/file.log"
                     start_position => "beginning"
                     sincedb_path => "/dev/null"
           }
 }
```

### Beats

```
input
{
    beats
          {
                     port => 5055
           }
 }
```

### TCP

```
input
{
    tcp
          {
                     port => 5055
                     codec => json
           }
 }
```

### UDP

```
input
{
    udp
          {
                     port => 514
                     codec => "plain"
           }
 }
```

### HTTP

```
input
{
    http
          {
                     port => 5055
           }
 }
```

## フィルタープラグイン

### Mutate フィールド追加

```
filter
{
    mutate
    {
                add_field => { "new_field" => "new_value" }
    }
 }
```

### 小文字変換

```
filter
{
    mutate
    {
                lowercase => ["field_name"]   }
    }
 }
```

### Grok データ抽出

パターンに従い、field_name という新しいフィールドに保存される

```
filter
{
    grok
    {
                match => { "message" => "%{PATTERN:field_name}" }
    }
 }
```

### Prune 空のフィールド削除

パラメータで指定されたフィールドを除く空のフィールドをイベントから削除

```
filter
{
    prune
    {
                whitelist_names => ["field1", "field2"]   }
    }
 }
```

### Translate

country フィールドが"US" の場合、 "United States"に置き換えられ、"CA" の場合、 "Canada"に置き換えられる。

```
filter
{
    translate
    {
                field => "country"
                destination => "country_name"
                dictionary => {       "US" => "United States"   "CA" => "Canada"   }
    }
 }
```

### if-else によるドロップ

```
filter
{
   if [status] == "error"
   {     drop { }
     }
   else {
      # Perform additional transformations or filters   }
 }
```

### 正規表現を使った if-else

```
filter {
  if [message] =~ /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/
  {
    # Extract the timestamp from the log entry
    date {
      match => [ "message", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
      target => "@timestamp"
    }
  }
}
```

### キーと値のペアを解析

field_split パラメータ はキーと値のペア間の区切り文字（&）を指定し、value_split パラメータ はキーと値間の区切り文字（=）を指定する。

```
filter
{
    kv
    {
        field_split => "&"     value_split => "="
    }
 }
```

### フィールド名変更

```
filter
{  mutate {
    rename
    {
                "old_field" => "new_field"
                add_field => { "another_field" => "value" }
    }
 }}
```

## 出力プラグイン

### ElasticSearch

```
output
{
    elasticsearch
    {
                hosts => ["localhost:9200"]
                index => "my_index"
    }
 }
```

### ファイル出力

```
output
{
    file
    {
                path => "/path/to/output.txt"
    }
 }
```

### メッセージキュー

```
output
{
   rabbitmq
   {
               host => "localhost"
               exchange => "my_exchange"
               routing_key => "my_routing_key"
    }
 }
```

### 別の Logstash インスタンスに送信

```
output
{
    logstash
       {
                host => "destination_host"
                port => 5000   }
 }
```

### jdbc （データベースに送信）

```
output
{
    dbc
    {
        connection_string => "jdbc:mysql://localhost:3306/mydb"
        statement => "INSERT INTO mytable (field1, field2) VALUES (?, ?)"
        parameters => ["%{field1}", "%{field2}"]
    }
 }
```

### TCP サーバーに送信

```
output
{
    tcp
    {
        host => "destination_host"
        port => 5000
    }
 }
```

### Kafka メッセージブローカー

```
output
{
    kafka
      {
              bootstrap_servers => "kafka_host:9092"
              topic_id => "my_topic"
      }
 }
```

### Websocket エンドポイント

```
output
{
   websocket
        {
                url => "ws://localhost:8080/my_endpoint"
        }
 }
```

### Syslog サーバー

```
output
{
     syslog
             {
                 host => "syslog_server"
                 port => 514
                 protocol => "udp"
             }
 }
```

### stdout コンソール出力（デバッグ用）

```
output
{
    stdout {
    }
 }
```
