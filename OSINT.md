# OSINT (Opne Source Intelligence)

## Google hacking

```text
site:host.com
inurl:admin
filetype:pdf
intitle:admin
```

## Wappalyzer

whatweb のオンライン版のようなもの  
https://www.wappalyzer.com/

## Wayback Machine

Web サイトの歴史アーカイブ  
https://archive.org/

## サブドメイン検出

### SSL/TLS 証明書

CA のログからサブドメインを探せる可能性がある  
https://crt.sh  
https://ui.ctsearch.entrust.com/ui/ctsearchui

### Google

www を除くサブドメインを検索する

```text
site:*.domain.com -site:www.domain.com
```

### dnsrecon

```shell
$ dnsrecon -t brt -d acmeitsupport.thm
[*] No file was specified with domains to check.
[*] Using file provided with tool: /usr/share/dnsrecon/namelist.txt
[*]     A api.acmeitsupport.thm 10.10.10.10
[*]     A www.acmeitsupport.thm 10.10.10.10
[+] 2 Record Found
```

### sublist3r

```shell
$ ./sublist3r.py -d acmeitsupport.thm

          ____        _     _ _     _   _____
         / ___| _   _| |__ | (_)___| |_|___ / _ __
         \___ \| | | | '_ \| | / __| __| |_ \| '__|
          ___) | |_| | |_) | | \__ \ |_ ___) | |
         |____/ \__,_|_.__/|_|_|___/\__|____/|_|

         # Coded By Ahmed Aboul-Ela - @aboul3la

[-] Enumerating subdomains now for acmeitsupport.thm
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
[-] Searching now in Virustotal..
[-] Total Unique Subdomains Found: 2
web55.acmeitsupport.thm
www.acmeitsupport.thm
```

FUZZ の部分にワードがあてはめられる

```shell
$ ffuf -w /usr/share/dnsrecon/dnsrecon/data/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.176.170

# 「普通のサイズ」=ハズレを除外する
$ ffuf -w /usr/share/dnsrecon/dnsrecon/data/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://10.10.176.170 -fs 2395
```

## GPS座標

Exiftoolの出力が下記だとする。この表示では南緯か北緯か、西経か東経かは分からない。

```
GPS Latitude                    : 26 deg 12' 14.76"
GPS Longitude                   : 28 deg 2' 50.28"
GPS Position                    : 26 deg 12' 14.76", 28 deg 2' 50.28"
```

Googlemap で次のように検索する。偶然で都市に当たる確率は低いので4種類調べれば高確率で絞り込める。

```sh
# 北緯、東経（エジプト）
26°12'14.76N 28°2'50.28E
# 北緯、西経（北大西洋）
26°12'14.76N 28°2'50.28W
# 南緯、東経（ヨハネスブルグ）
26°12'14.76S 28°2'50.28E
# 南緯、西経（南大西洋）
26°12'14.76S 28°2'50.28W
```

## 画像逆検索

Googleの文字列入力窓の右側に画像で検索ボタンがある。

## ツール

### pgpdump

```shell
# PGP公開鍵に含まれるメールアドレス等をダンプする
pgpdump <pgp-pubkey-file>
```
