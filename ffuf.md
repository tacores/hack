# ffuf

https://tryhackme.com/room/ffuf

```shell
# seclists のインストール
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
```

```shell
# 基本的な使い方
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt

# FUZZ以外のキーワードを割り当てる使い方
ffuf -u http://10.10.152.87/NORAJ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt:NORAJ
```

## パス、ディレクトリ検索

```shell
# 拡張子付きファイル名リスト
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt

# index + 拡張子
ffuf -u http://10.10.152.87/indexFUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt

# 特定拡張子に絞った検索
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.txt

# ディレクトリ検索
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

## フィルター

```shell
# 403応答を非表示
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 403

# 200応答のみ表示
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -mc 200

# 特定サイズの応答を非表示
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fc 0

# 正規表現を使用
ffuf -u http://10.10.152.87/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files-lowercase.txt -fr '/\..*'
```

他にもあるので、不便に感じたらヘルプを参照。

## パラメータファジング

```shell
# パラメータを探す
ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fw 39

ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fw 39
```

```shell
# 0から255までの整数値を渡す5つの方法
ruby -e '(0..255).each{|i| puts i}' | ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

ruby -e 'puts (0..255).to_a' | ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

for i in {0..255}; do echo $i; done | ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

seq 0 255 | ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

cook '[0-255]' | ffuf -u 'http://10.10.1.196/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33
```

```shell
# パスワードファジング
ffuf -u http://10.10.1.196/sqli-labs/Less-11/ -c -w /usr/share/wordlists/SecLists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
```

## サブドメイン列挙

```shell
# vhost列挙。こちらの方が良い
ffuf -u http://mydomain.com -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.mydomain.com' -fs 0

# DNSサーバー依存。プライベートNW内でしか解決されない可能性がある。
ffuf -u http://FUZZ.mydomain.com -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 内部サブドメイン

SSRFの例。@をつけていることと、#でコメントアウトしている点に注意。


```sh
ffuf -u 'http://nahamstore.thm/stockcheck' -c -w /usr/share/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt -X POST -d 'product_id=2&server=stock.nahamstore.thm@FUZZ.nahamstore.thm#'
```

## プロキシ

```shell
# Burpプロキシなどのプロキシを経由する
ffuf -u http://10.10.1.196/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -x http://127.0.0.1:8080

# マッチした場合だけプロキシ経由で再送する
ffuf -u http://10.10.1.196/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -replay-proxy http://127.0.0.1:8080
```

## オープンリダイレクトパラメータ

URLを踏ませることでリダイレクトさせるXSS

```sh
ffuf -u 'http://nahamstore.thm/?FUZZ=http://attacker/foo' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fs 4254
```

## その他

```shell
# ワードファイル内のコメント行を無視する
-ic

# Markdown形式でファイル出力
-of md -o ffuf.md

# HTTPリクエストファイルをインプットにする
-request

# ワードリストをSTDINから取る
-w -

# フルURLとリダイレクトを出力する
-v

# リダイレクトをフォロー
-r

# 出力に色を付ける
-c
```
