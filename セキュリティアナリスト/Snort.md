# Snort

https://tryhackme.com/room/snort

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
