# tor

https://tryhackme.com/room/torforbeginners

## Tor

```shell
# インストール
sudo apt-get install tor

# サービス開始、停止
sudo service tor start

sudo service tor status

sudo service tor stop
```

## ProxyChains

https://github.com/haad/proxychains

特定のアプリケーションによって作成されたすべてのTCP接続を、TOR やその他の SOCKS4、SOCKS5、HTTP (S)プロキシなどのプロキシ経由で実行するように強制するツール

```shell
# インストール
sudo apt install proxychains

# 設定ファイル
sudo nano /etc/proxychains.conf
```

```shell
proxychains firefox
```

## tor browser

```shell
# インストール
sudo apt install -y tor torbrowser-launcher

torbrowser-launcher
```


