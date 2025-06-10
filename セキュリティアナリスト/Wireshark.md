# Wireshark

## パケットナビゲーション

https://tryhackme.com/room/wiresharkthebasics

### パケットを検索

Edit -> Find Packet

- 入力タイプ (表示フィルター、16 進数、文字列、正規表現)
- 検索フィールド（パケット リスト、パケットの詳細、パケット バイト）

### パケットをマークする

閉じるとマークは失われる

### パケットコメント

閉じても保存されたままになる

### エクスポート

マークされたパケットのみエクスポートするといったことが可能

### オブジェクトエクスポート

ネットワーク経由で転送されたファイルをエクスポートできる

### 時間表示形式

View メニューから表示形式を選択。ローカルタイムゾーンか UTC か注意。

### 認証情報

ツール → クレデンシャルからプレインテキストの認証情報を参照可能

### FW ACL ルール生成

パケットを選択して、ツール →FW ACL ルールからルールコピーできる。（ドロップダウンで種類選択可能）

## パケットフィルタリング

### 黄金律

```text
クリックできるものは、フィルターしてコピーできる
```

フィールドを右クリックして「フィルターに適用する」が便利。

### 会話フィルター

関連するパケットのみを表示するのに便利

### 会話を色付け

フィルターせずに、関連するパケットの色を変える

### フィルターとして準備

すぐにフィルター適用せず、クエリをペインに追加する

### 列として適用

パケット詳細の行を右クリックして実行することで、その部分を表示する列を追加可能

### TCP ストリームを追跡

Follow -> TCP Stream で、TCP ストリームとして表示可能

## パケットオペレーション

https://tryhackme.com/room/wiresharkpacketoperations

### 統計

- 解決されたアドレス
- プロトコル階層。プロトコルごとの回数やパーセンテージなど
- 会話。2 エンドポイント間のトラフィックを表す
- エンドポイント。1 つのエンドポイントの情報  
  IP アドレスの名前解決をしたい場合は、編集ー設定ー名前解決で機能を ON にする。  
  また、MaxMind データベース ディレクトリを設定することでジオロケーション解決も可能。
- IPx 統計。IP4 だけ、または IP6 だけを対象とすることができる。
- DNS。DNS パケットのみを対象とした統計。
- HTTP,HTTP2

## フィルタ

### キャプチャフィルタ構文

- Scope: host, net, port and portrange.
- Direction: src, dst, src or dst, src and dst,
- Protocol: ether, wlan, ip, ip6, arp, rarp, tcp and udp.
- ポート 80 トラフィックをキャプチャするサンプル フィルター: tcp port 80

https://www.wireshark.org/docs/man-pages/pcap-filter.html

キャプチャ、キャプチャフィルターメニューにクイックリファレンスがある。

### 表示フィルタ構文

- パケットフィルターは小文字で定義される
- ip.addr はパケットの方向を考慮しない。ip.src/ip.dst はパケットの方向がある。
- tcp.port と tcp.srcport, tcp.dstport も同じ。
- 文字列はダブルクォート。http.request.method == "GET"
- ポート 80 トラフィックをキャプチャするサンプル フィルター: tcp.port == 80

https://www.wireshark.org/docs/dfref/

分析、表示フィルターメニューにクイックリファレンスがある。

### 高度なフィルタリング

```shell
# contains
http.server contains "Apache"

# match（正規表現。大文字小文字を区別しない）
http.host matches "\.(php|html)"

# in
tcp.port in {80 443 8080}
# 範囲指定も可能
tcp.port in {20..80}

# upper（文字列を大文字に変換）
upper(http.server) contains "APACHE"

# lower
lower(http.server) contains "apache"

# string（文字列以外の値を文字列に変換）
string(frame.number) matches "[13579]$"
```

## 解析例

https://tryhackme.com/room/wiresharktrafficanalysis

### nmap

```shell
# TCP SYN スキャン
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

# UDP close port メッセージ
icmp.type==3 and icmp.code==3
```

### ARP

```shell
arp.opcode == 1
arp.opcode == 2
arp.dst.hw_mac==00:00:00:00:00:00
arp.duplicate-address-detected or arp.duplicate-address-frame
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)
```

### DHCP

```shell
Request：dhcp.option.dhcp == 3
ACK:dhcp.option.dhcp == 5
NAK：dhcp.option.dhcp == 6

dhcp.option.hostname contains "keyword"
dhcp.option.domain_name contains "keyword"
```

### NetBIOS

```shell
nbns.name contains "keyword"
```

### Kerberos

```shell
kerberos.CNameString contains "keyword"
kerberos.CNameString and !(kerberos.CNameString contains "$" )

kerberos.pvno == 5
kerberos.realm contains ".org"
kerberos.SNameString == "krbtg"
```

### ICMP, DNS

```shell
data.len > 64 and icmp

dns contains "dnscat"
dns.qry.name.len > 15 and !mdns
```

### FTP

```shell
# 211:システムステータス
# 212:ディレクトリのステータス
# 213:ファイルステータス
ftp.response.code == 211

# 220:サービス準備完了。
# 227:パッシブモードに入ります。
# 228:ロングパッシブモード。
# 229:拡張パッシブモード。
ftp.response.code == 227

# 230:ユーザーログイン。
# 231:ユーザーがログアウトしました。
# 331:有効なユーザー名です。
# 430:ユーザー名またはパスワードが無効です
# 530:ログインできません。パスワードが無効です。
ftp.response.code == 230

ftp.request.command == "USER"
ftp.request.command == "PASS"
ftp.request.arg == "password"

ftp.response.code == 530
(ftp.response.code == 530) and (ftp.response.arg contains "username")
(ftp.request.command == "PASS" ) and (ftp.request.arg == "password")
```

### HTTP

```shell
http.request.method == "GET"
http.request.method == "POST"
http.request

http.response.code == 405
http.response.code == 503

http.user_agent contains "nmap"
http.request.uri contains "admin"
http.request.full_uri contains "admin"

http.server contains "apache"
http.host contains "keyword"
http.host == "keyword"
http.connection == "Keep-Alive"
data-text-lines contains "keyword"

http.user_agent
(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")

# log4j
http.request.method == "POST"
(ip contains "jndi") or ( ip contains "Exploit")
(frame contains "jndi") or ( frame contains "Exploit")
(http.user_agent contains "$") or (http.user_agent contains "==")
```

### HTTPS

```shell
http.request
tls
tls.handshake.type == 1
tls.handshake.type == 2
ssdp

(http.request or tls.handshake.type == 1) and !(ssdp)
(http.request or tls.handshake.type == 2) and !(ssdp)
```

#### キーログファイルを追加・削除

「編集 --> 設定 --> プロトコル --> TLS」 メニューまたは右クリック

キーログファイルの生成はブラウザで行われる。SSLKEYLOGFILE 環境変数でファイルパスを指定すれば、そのファイルに TLS セッションを確立する際に生成されるプレマスターシークレットが保存されていく。

#### サーバーの秘密鍵候補

```
/etc/apache2/certs
```
