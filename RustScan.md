# RustScan

https://tryhackme.com/room/rustscan

https://github.com/bee-san/RustScan

## インストール

https://github.com/bee-san/RustScan/

/home/kali/.cargo/bin に PATH を通す。

```shell
cargo install rustscan
```

## スクリプト

https://github.com/bee-san/RustScan/tree/master/fixtures/.rustscan_scripts

`$HOME/.rustscan_scripts.toml/rustscan_scripts.toml`

## 実行方法

### ホスト指定

```shell
# 複数IP
rustscan -a 127.0.0.1,0.0.0.0

# ホストスキャン
rustscan -a www.google.com, 127.0.0.1
Open 216.58.210.36:1
Open 216.58.210.36:80
Open 216.58.210.36:443
Open 127.0.0.1:53
Open 127.0.0.1:631

# CIDR
rustscan -a 192.168.0.0/30

# ホストファイルを使う
cat hosts.txt
192.168.0.1
192.168.0.2
google.com
192.168.0.0/30
127.0.0.1

rustscan -a hosts.txt
```

### ポート指定

```shell
# 個別ポート
rustscan -a 127.0.0.1 -p 53

# マルチポート
rustscan -a 127.0.0.1 -p 53,80,121,65535

# 範囲
rustscan -a 127.0.0.1 --range 1-1000
```

### その他

```shell
# nmap引数
rustscan -a 127.0.0.1 -- -A -sC

これが実行される
nmap -Pn -vvv -p $PORTS -A -sC 127.0.0.1

# ポート順をランダムにする
rustscan -a 127.0.0.1 --range 1-1000 --scan-order "Random"
```

```shell
# バージョン
rustscan -a <ip> -- -sV

# アグレッシブスキャン
rustscan -a <ip> -- -A
```
