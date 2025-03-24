# Takeover CTF

https://tryhackme.com/room/takeover

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.207.211
root@ip-10-10-10-185:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-24 06:32 GMT
Nmap scan report for futurevera.thm (10.10.207.211)
Host is up (0.00070s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
MAC Address: 02:6D:D4:F0:44:1F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.53 seconds
root@ip-10-10-10-185:~# sudo nmap -sV -p22,80,443 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-24 06:33 GMT
Nmap scan report for futurevera.thm (10.10.207.211)
Host is up (0.00037s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:6D:D4:F0:44:1F (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
gobuster dir -x=txt,php -u https://futurevera.thm -w ./dirlist.txt -t 30 -k

===============================================================
/.php                 (Status: 403) [Size: 280]
/assets               (Status: 301) [Size: 319] [--> https://futurevera.thm/assets/]
/css                  (Status: 301) [Size: 316] [--> https://futurevera.thm/css/]
/.htaccess            (Status: 403) [Size: 280]
/.htaccess.txt        (Status: 403) [Size: 280]
/.htaccess.php        (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.htpasswd.php        (Status: 403) [Size: 280]
/.htpasswd.txt        (Status: 403) [Size: 280]
/js                   (Status: 301) [Size: 315] [--> https://futurevera.thm/js/]
/server-status        (Status: 403) [Size: 280]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

特になし。

サブディレクトリかと思って散々探したが、ルームの説明に「サブドメインの列挙」と書かれていた。

サブドメイン検索。-u には IP 指定、-H でサブドメインを含むドメイン指定すればよい。

```shell
root@ip-10-10-10-185:~# ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -X GET -H "Host: FUZZ.futurevera.thm" -u https://10.10.207.211 -fs 4605

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.207.211
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 4605
________________________________________________

support                 [Status: 200, Size: 1522, Words: 367, Lines: 34]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81]
:: Progress: [4997/4997] :: Job [1/1] :: 1657 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

support, blog というサブドメインを見つけた。

- support.futurevera.thm を hosts に追加
- ブラウザでhttps://support.futurevera.thmにアクセス（Burpプロキシを切って直接接続すること）
- Firefox で URL 左側の鍵マークをクリックし、証明書を表示すると、DNS Name に「secrethelpdesk934752.support.futurevera.thm」と表示されている（Burp プロキシを経由しているとこれが表示されない）
- secrethelpdesk934752.support.futurevera.thm を hosts に追加し、http で curl すると flag が出てくる

```shell
$ curl -v http://secrethelpdesk934752.support.futurevera.thm
* Host secrethelpdesk934752.support.futurevera.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.207.211
*   Trying 10.10.207.211:80...
* Connected to secrethelpdesk934752.support.futurevera.thm (10.10.207.211) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: secrethelpdesk934752.support.futurevera.thm
> User-Agent: curl/8.11.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Mon, 24 Mar 2025 07:57:53 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://flag{ひみつ}.s3-website-us-west-3.amazonaws.com/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
<
* Connection #0 to host secrethelpdesk934752.support.futurevera.thm left intact
```

## 振り返り

- ffuf でドメインを検索する方法は勉強になった
- 証明書に何か隠されている場合、Burp プロキシを ON にしていると見逃してしまう
