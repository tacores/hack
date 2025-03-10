# Brim

https://tryhackme.com/room/brim

pcap をロードすると、Brim はファイルを処理し、Zeek ログを作成して相関させる。

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

### 例

```shell
# 頻繁に接続しているホスト
_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r

# アクティブなポート
_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count

# IP でフィルター
_path=="conn" | 104.168.44.45 | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq -c

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
