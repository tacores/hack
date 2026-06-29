# Snort

https://tryhackme.com/room/snort

https://tryhackme.com/room/detectionengineeringwithsnort

3 モードがある

- スニファーモード
- パケットロガーモード
- NIDS、NIPS モード

```shell
# -q オプションを付けるとクワイエットモード（デフォルトのバナーとセットアップに関する初期情報を表示しない）

# バージョン
snort -V
```

## スニファーモード

```shell
# 詳細モード
sudo snort -v -i eth0

# パケットデータダンプモード
sudo snort -d

# リンク層ヘッダーも取得
sudo snort -de

# フルパケットダンプ
sudo snort -X
```

## パケットロガーモード

```shell
# デフォルトでは、/var/log/snort に tcpdump形式でダンプ

# カレントディレクトリにログ記録
sudo snort -dev -l .

# ASCII によるログ記録
sudo snort -dev -K ASCII -l .

# ログを読む（ASCIIファイルは読めない）
sudo snort -r snort.log.1638459842
# tcpdump で読む
sudo tcpdump -r snort.log.1638459842 -ntc 10

# フィルターを指定して読む
sudo snort -r logname.log -X
sudo snort -r logname.log icmp
sudo snort -r logname.log tcp
sudo snort -r logname.log 'udp and port 53'

# 10パケットのみ読む
sudo snort -dvr logname.log -n 10
```

## IPS/IDS モード

```shell
# 構成ファイルが有効であることをテスト
sudo snort -c /etc/snort/snort.conf -T

# ログ記録無効
sudo snort -c /etc/snort/snort.conf -N

# バックグラウンドモード（デーモン）
sudo snort -c /etc/snort/snort.conf -D

# 高速スタイルのアラート表示
snort -c /etc/snort/snort.conf -A console

# 16 進数とテキスト形式のペイロードを含む基本的なヘッダー詳細
sudo snort -c /etc/snort/snort.conf -A cmg

# コンソール出力しない
sudo snort -c /etc/snort/snort.conf -A fast

# 全ての情報が提供される（コンソール出力はされないことに注意）
sudo snort -c /etc/snort/snort.conf -A full

# アラートファイルは作成されない（ログファイルは作成される）
sudo snort -c /etc/snort/snort.conf -A none

# 設定ファイルなしでルールを使用（ルールのテスト目的）
sudo snort -c /etc/snort/rules/local.rules -A console

# IPSモード（パケットをドロップ）
# confファイルによる設定でもIPS化が可能
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console
```

設定ファイル、ルールファイル、pcapファイルを指定する形

```sh
sudo snort -c /etc/snort/snort.lua -R task-06-ruleset.rules -r task-06-dirty.pcap -A alert_fast -q
```

## pcap

```shell
# -X オプションはデータを完全に表示する

# 単一
sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -X -n 10

# 複数
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -X

# 複数（pcapとアラートの対応を区別できる形）
sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -X --pcap-show
```

tcpdump を使う方法

```shell
sudo tcpdump -nn -X -r ./ftp-png-gif.pcap port 21
```

## ルール例

### HTTP

```text
alert tcp any any -> any 80 (msg: "TCP 80 In Found"; sid: 1000001; rev:1;)
alert tcp any 80 -> any any (msg: "TCP 80 Out Found"; sid: 1000002; rev:1;)
```

GETのみ対象にする

```text
pkt_data; content:"GET ", depth 4; \
```

### FTP

```text
alert tcp any any -> any 21 (msg: "FTP In Found"; sid: 1000001; rev:1;)
alert tcp any 21 -> any any (msg: "FTP Out Found"; sid: 1000002; rev:1;)

# ログインエラー
alert tcp any 21 -> any any (msg: "FTP Fail Found"; content:"530 User"; sid: 1000003; rev:1;)

# contet は複数並べることも可能
alert tcp any 21 -> any any (msg: "FTP Fail Found"; content:"331 Password"; content:"admin"; sid: 1000005; rev:1;)
```

### ASCII モードと HEX モード

```text
(ASCII mode)
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)

(HEX mode)
alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)
```

### サイズ

```text
dsize:min<>max;
dsize:>100
dsize:<100
```

### アクション

```text
alert: Generate an alert and log the packet.
log: Log the packet.
drop: Block and log the packet.
reject: Block the packet, log it and terminate the packet session.
```

### メタデータ

```text
metadata:mitre_attack T1071.001, author "saqib", ticket "NFG-2145";
```

### 繰り返し

同じ送信元IPから、10分間（600秒）の間に、このルールに引っかかる通信が5回発生したら、それ以降のアラートをトリガーする

```text
detection_filter:track by_src, count 5, seconds 600;
```

### 抑制

ベースのルールが下記であるとする。

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 ( \
  msg:"L2-SNORT POSSIBLE C2 BEACON - Finance egress regularity"; \
  flow:to_server,established; \
  dsize:<100; \
  detection_filter:track by_src, count 5, seconds 360; \
  metadata:mitre_attack T1071.001, author "saqib", ticket "NFG-2145"; \
  sid:1000002; \
  rev:1; \
)
```

task-04-suppress.lua として上記内容を保存したとする。  
gidはテキストルールセット、sidは対象ルールID。抑制するIPアドレスの判定基準を送信元に設定、抑制対象とするIPアドレス。

```text
suppress =
{
    { gid = 1, sid = 1000002, track = 'by_src', ip = '10.14.22.199' }
}
```

--tweaks オプションを使ってルールファイルを書き換えることなく抑制できる。

```sh
sudo snort -c /etc/snort/snort.lua -R task-04-answer.rules -r task-04-noisy-traffic.pcap -A alert_fast -q --tweaks task-04-suppress | wc -l
```

## ブロックリスト

```text
reputation =
{
    blocklist = '/home/ubuntu/lab/task-05/task-05-blocklist.txt',
    memcap = 500,
    priority = 'blocklist',
    nested_ip = 'inner',
}
```
