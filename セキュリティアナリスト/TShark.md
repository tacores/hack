# TShark

## 基本

https://tryhackme.com/room/tsharkthebasics

https://tryhackme.com/room/tshark

```shell
# ヘルプ
tshark -h

# バージョン
tshark -v

# 利用可能なスニッフィング インターフェイスを一覧表示
tshark -D

# ライブトラフィックをキャプチャするインターフェイスを選択
tshark -i 1
tshark -i ens55

# tcpdump のようにスニッフィング
tshark

# Wireshark のような色分けされた出力。
tshark --color
```

```shell
# 読み取り/入力機能
# キャプチャファイルを読み取る。
tshark -r demo.pcapng

# パケット数
# 指定された数のパケットをキャプチャしたら停止する。
tshark -c 10

# 書き込み/出力機能
# スニッフィングしたトラフィックをファイルに書き込む。
tshark -w sample-capture.pcap

# 各パケットの詳細情報
# Wireshark の「パケット詳細ペイン」と同様の詳細情報を提供する。
tshark -V

# サイレントモード
# 端末上のパケット出力を抑制する。
tshark -q

# パケットバイトを表示
# 各パケットの詳細を 16 進数と ASCII ダンプで表示する。
tshark -x
```

-V や -x で詳細を表示するのは、フィルタリングした後にする。

```shell
# pcapngを1パケットだけ読み取り、ファイルに保存する例
tshark -r demo.pcapng -c 1 -w write-demo.pcap
```

### キャプチャ条件

キャプチャ、スニッフィングモードでのみ機能する。  
-a と -b を組み合わせることも可能。

#### 自動停止条件

```shell
# 期間: トラフィックをスニッフィングし、X 秒後に停止。
tshark -w test.pcap -a duration:1

# ファイル サイズ: 最大キャプチャ ファイル サイズを定義。
# X ファイル サイズ (KB) に達すると停止。
tshark -w test.pcap -a filesize:10

# 出力ファイルの最大数を定義。X ファイルの後に停止。
tshark -w test.pcap -a filesize:10 -a files:3
```

#### リングバッファ制御オプション

```shell
# 期間: トラフィックを X 秒間スニッフィングし、新しいファイルを作成してそこに出力を書き込む。
tshark -w test.pcap -b duration:1

# ファイル サイズ: 最大キャプチャ ファイル サイズを定義。
# ファイル サイズ X (KB) に達すると、新しいファイルを作成し、そのファイルに出力を書き込む。
tshark -w test.pcap -b filesize:10

# ファイル: 出力ファイルの最大数を定義。X ファイルを作成した後、最初の/最も古いファイルを書き換える。
tshark -w test.pcap -b filesize:10 -b files:3
```

```shell
# 例
tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5
```

### キャプチャフィルターと表示フィルター

```shell
# キャプチャフィルター。BPF 構文および Wireshark のキャプチャ フィルターと同じ。
-f

# 表示フィルター。Wiresharkの表示フィルターと同じ。
-Y
```

#### キャプチャフィルタの例

```shell
tshark -f "host 10.10.10.10"
tshark -f "net 10.10.10.0/24"
tshark -f "port 80"
tshark -f "portrange 80-100"

tshark -f "src host 10.10.10.10"
tshark -f "dst host 10.10.10.10"

tshark -f "tcp"
tshark -f "ether host F8:DB:C5:A2:5D:81"
tshark -f "ip proto 1"
```

#### 表示フィルタの例

```shell
tshark -Y 'ip.addr == 10.10.10.10'
tshark -Y 'ip.addr == 10.10.10.0/24'
tshark -Y 'ip.src == 10.10.10.10'
tshark -Y 'ip.dst == 10.10.10.10'

tshark -Y 'tcp.port == 80'
tshark -Y 'tcp.srcport == 80'

tshark -Y 'http'
tshark -Y "http.response.code == 200"

tshark -Y 'dns'
tshark -Y 'dns.qry.type == 1'
```

```shell
# nl でパイプすると、フィルタ後の件数とパケット番号の対応が分かる
tshark -r demo.pcapng -Y 'http' | nl
```

## 統計

https://tryhackme.com/room/tsharkcliwiresharkfeatures

```shell
# Wireshark のような色分けされた出力。
tshark --color

# 統計で使用可能なフィルター
tshark -z help

# 使用例
tshark -r demo.pcapng -z io,phs -q
```

統計をフィルタリングするたびに、最初にパケットが表示され、次に統計が表示される。-q パラメータを使用してパケットを抑制し、統計に重点を置くことができる。

```shell
# プロトコル階層
tshark -r demo.pcapng -z io,phs -q

# UDPに絞る
tshark -r demo.pcapng -z io,phs,udp -q

# パケット長ツリー
tshark -r demo.pcapng -z plen,tree -q

# IP4エンドポイント
tshark -r demo.pcapng -z endpoints,ip -q

# 会話
tshark -r demo.pcapng -z conv,ip -q

# エキスパート情報
tshark -r demo.pcapng -z expert -q
```

IP6 の場合は、ip を ipv6 に変えるだけ。

```shell
# IP4プロトコルの種類
tshark -r demo.pcapng -z ptype,tree -q

# 利用可能なホスト
tshark -r demo.pcapng -z ip_hosts,tree -q

# 送信元と送信先IPアドレス
tshark -r demo.pcapng -z ip_srcdst,tree -q

# 送信先とポート
tshark -r demo.pcapng -z dests,tree -q

# DNS統計
tshark -r demo.pcapng -z dns,tree -q

# HTTP統計
tshark -r demo.pcapng -z http,tree -q
```

## ストリーム、オブジェクト、資格情報

```shell
# ストリーム番号１をフォロー
tshark -r demo.pcapng -z follow,tcp,ascii,1 -q

# オブジェクトをエクスポート
tshark -r demo.pcapng --export-objects http,/home/ubuntu/Desktop/extracted-by-tshark -q

# 資格情報
tshark -r credentials.pcap -z credentials -q
```

## Contains, Matches, Extract

```shell
# フィールドの抽出
tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5

# contains
tshark -r demo.pcapng -Y 'http.server contains "Apache"'

tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y

# matches
tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'
```

### 抽出例

```shell
# ホスト名
tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname

# DNSクエリ
tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r

# ユーザーエージェントの抽出
tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r
```

```sh
# Base64後にTCPで送信されたデータを抽出
tshark -r traffic.pcapng -Y "tcp.stream eq 1 && tcp.len > 0" -T fields -e tcp.payload \
  | grep -v '^$' | tr -d '\n' | xxd -r -p > dmp-base64.txt
```

```sh
# FTPのユーザー名とパスワードを抽出
tshark -r /home/ubuntu/captures/investigation.pcap -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' -T fields -e ftp.request.command -e ftp.request.arg
```

```sh
# 302リダイレクトチェーンの抽出
tshark -r /home/ubuntu/captures/investigation.pcap -Y "http.response.code == 302" -T fields -e frame.time -e ip.src -e http.location
```

```sh
# TLS証明書のサブジェクトを抽出
tshark -r investigation.pcap -Y "ip.src == 194.165.16.56 and tls.handshake.certificate" -T fields -e tls.handshake.certificate | sed -n '1p' | tr -d ':' | xxd -r -p | openssl x509 -inform DER -noout -subject

# JA4フィンガープリントの抽出
tshark -r investigation.pcap -Y "ip.dst == 194.165.16.56 and tls.handshake.type == 1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja4 | sort -u
```

```sh
# DNS TXTレコードクエリを抽出
tshark -r investigation.pcap -Y "dns.qry.type == 16" -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.txt

# ICMP トンネリングを抽出
tshark -r investigation.pcap -Y "icmp.type == 8 and frame.len > 100" -T fields -e frame.time -e ip.src -e ip.dst -e frame.len -e data.data | head -3
```

```sh
# 22, 2222 以外で実行されているSSH接続。SSH-2.0 という文字列で検索。
tshark -r investigation.pcap -Y "frame contains 53:53:48:2d:32:2e:30 and tcp.port != 22 and tcp.port != 2222" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
```

[スクリプト](https://tryhackme.com/room/advancedpacketanalysis)

```sh
#!/bin/bash
PCAP="${1:-/home/ubuntu/captures/investigation.pcap}"
OUT="${2:-/home/ubuntu/evidence/iocs}"
mkdir -p "$OUT/http_objects"

# External destination IPs
tshark -r "$PCAP" -q -T fields -e ip.dst \
  -Y "not ip.dst in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}" \
  | sort -u > "$OUT/external_ips.txt"

# HTTP hostnames
tshark -r "$PCAP" -q -T fields -e http.host \
  -Y "http.request" | sort -u | grep -v '^$' > "$OUT/http_hosts.txt"

# TLS SNI values
tshark -r "$PCAP" -q -T fields -e tls.handshake.extensions_server_name \
  -Y "tls.handshake.type == 1" | sort -u | grep -v '^$' > "$OUT/tls_sni.txt"

# DNS queries
tshark -r "$PCAP" -q -T fields -e dns.qry.name \
  -Y "dns.flags.response == 0" | sort -u | grep -v '^$' > "$OUT/dns_queries.txt"

# JA4 fingerprints
tshark -r "$PCAP" -q -T fields -e tls.handshake.ja4 \
  -Y "tls.handshake.type == 1" | sort -u | grep -v '^$' > "$OUT/ja4_fingerprints.txt"

# All HTTP-transferred objects, then hash them
tshark -r "$PCAP" --export-objects http,"$OUT/http_objects/" >/dev/null 2>/dev/null
( cd "$OUT/http_objects" && sha256sum * 2>/dev/null > "$OUT/extracted_hashes.txt" )

echo "IOC extraction complete. Output in: $OUT"
```
