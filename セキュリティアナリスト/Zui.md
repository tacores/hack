# Zui (旧 Brim)

https://tryhackme.com/room/brim

https://tryhackme.com/room/threathuntingwithzui

pcap をロードすると、Zui はファイルを処理し、Zeek ログを作成して相関させる。

## デフォルトクエリ

- 概要。各イベントの件数
- Windows 固有のイベント
- 一意の接続と接続データの相関関係
- 各接続が送受信したデータサイズ
- DNS クエリ、HTTP リクエスト
- ファイルアクティビティ。ファイル名、ハッシュ値を表示
- IP サブネット統計
- Suricata ルールの結果に基づいた情報

## カスタムクエリ

- デフォルトクエリを参考に
- パフォーマンスを良くするため常にフィールドフィルターを使う

```shell
# ログソースPathごとの件数
count() by _path | sort -r count

# 頻繁に接続しているホスト
_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r

# アクティブなポート
_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count

# 特定のポート
_path == "conn" | id.resp_p == 443

# IP でフィルター
_path=="conn" | 104.168.44.45 | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c

# 特定のサブネットを除外
_path == "conn" | not (id.resp_h in [10.0.0.0/8]) | count() by id.resp_h | sort -r count | head 10


# 長い接続
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration

# 転送されたデータ
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes

# C2通信の疑い
_path=="dns" | count () by query | sort -r
_path=="http" | count () by uri | sort -r

# 疑わしいホスト名
_path=="dhcp" | cut host_name, domain

# 疑わしいIPアドレス
_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r

# ファイル検出
filename!=null

# SMB
_path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"

# 既知のパターン
event_type=="alert" or _path=="notice" or _path=="signatures"
```

```sh
# in
_path == "conn" | not (id.resp_h in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16])

# 集約
_path == "conn" | conns := count(), bytes_out := sum(orig_bytes), bytes_in := sum(resp_bytes) by id.orig_h | sort -r bytes_out

# 文字列マッチング
_path == "dns" | query == "backup.corpfiles-sync.com"

# 部分検索
_path == "dns" | grep("corpfiles-sync", query)

# 文字列長
_path == "dns" | len(query) > 60

# cut で特定のフィールドを選択
_path == "conn" | id.orig_h == 10.14.22.88 | cut ts, id.resp_h, id.resp_p, duration, orig_bytes, resp_bytes

# セッションのUIDを取得してからのクロスピボット
_path == "conn" | id.resp_h == 185.213.154.201
uid == "CvYpdNPp57QfgKpF8"

# クライアントが20回以上の外部HTTPS接続を開いた送信元IPアドレスと宛先IPアドレスのペアをリストし、接続頻度でソートして候補を特定
_path == "conn" | id.resp_p == 443 | not (id.resp_h in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]) | sessions := count(), bytes_out := sum(orig_bytes) by id.orig_h, id.resp_h | sessions >= 20 | sort -r sessions
```

## 例

### ビーコンパターン

#### 頻繁な外部接続

```sh
_path == "conn" |
not (id.resp_h in [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]) |
count() by id.orig_h, id.resp_h, id.resp_p |
sort -r count |
count > 20
```

#### 間隔パターンの調査

```sh
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 | sort ts | cut ts
```

#### 各ビーコンのバイト数と接続状態

```sh
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 |
cut ts, duration, orig_bytes, resp_bytes, conn_state
```

#### TLSログとの関連付け

```sh
_path == "ssl" | id.orig_h == 10.14.22.88 | id.resp_h == 194.165.16.56 |
cut ts, server_name, ja4, validation_status, subject
```

### データ流出

#### 受信データより送信データのほうが大きい接続

```sh
_path == "conn" |
not (cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
orig_bytes > 1000000 |
orig_bytes / (resp_bytes + 1) > 10 |
sort -r orig_bytes
```

#### 業務時間外のデータ送信

```sh
_path == "conn" |
orig_bytes > 1000000 |
(ts < 2025-11-14T07:00:00Z or ts > 2025-11-14T20:00:00Z)
```

#### HTTPデータをピボット

```sh
_path == "http" |
id.resp_h == 185.213.154.201 |
sort -r request_body_len |
cut ts, id.orig_h, id.resp_h, method, host, uri, request_body_len, orig_mime_types, user_agent
```

#### DNS

```sh
_path == "dns" |
query == "backup.corpfiles-sync.com" |
cut ts, id.orig_h, query, answers, rcode_name
```

#### File

```sh
_path == "files" |
10.14.22.88 in tx_hosts |
185.213.154.201 in rx_hosts |
cut ts, tx_hosts, rx_hosts, conn_uids, source, analyzers, mime_type, filename, total_bytes, md5, sha1
```

#### 10MBを超える内部SMBセッション

```sh
_path == "conn" |
(cidr_match(10.0.0.0/8, id.orig_h) or cidr_match(172.16.0.0/12, id.orig_h) or cidr_match(192.168.0.0/16, id.orig_h)) |
(cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
id.resp_p == 445 |
resp_bytes > 10000000 |
sort -r resp_bytes
```

### 横方向移動

#### 予期せぬ内部管理接続

```sh
_path == "conn" |
(cidr_match(10.0.0.0/8, id.orig_h) or cidr_match(172.16.0.0/12, id.orig_h) or cidr_match(192.168.0.0/16, id.orig_h)) |
(cidr_match(10.0.0.0/8, id.resp_h) or cidr_match(172.16.0.0/12, id.resp_h) or cidr_match(192.168.0.0/16, id.resp_h)) |
id.resp_p in [445, 3389, 5985, 22, 135, 389] |
not id.orig_h == id.resp_h |
count() by id.orig_h, id.resp_p |
sort -r count
```

#### スキャン検出

```sh
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_p == 445 | conn_state == "S0" | count()
```

#### RDP接続

```sh
_path == "conn" | id.orig_h == 10.14.22.88 | id.resp_p == 3389 | sort ts |
cut ts, id.resp_h, duration, orig_bytes, resp_bytes
```

#### DCへのホップ

```sh
_path == "conn" |
id.orig_h == 10.14.10.15 |
id.resp_p in [389, 445] |
count() by id.resp_h, id.resp_p |
sort id.resp_h
```

## zedファイル保存

ファイル名のパターン：`[Behaviour]-[LogSource]-[KeyField]`

例

- Beaconing-conn-highcount
- Exfil-conn-asymmetric
- LateralMov-SMB-internal
