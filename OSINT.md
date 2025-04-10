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
https://web.archive.org/

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

## ツール

### pgpdump

```shell
# PGP公開鍵に含まれるメールアドレス等をダンプする
pgpdump <pgp-pubkey-file>
```
