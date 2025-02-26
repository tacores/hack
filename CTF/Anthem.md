# Anthem CTF

https://tryhackme.com/room/anthem

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.219.196
root@ip-10-10-40-82:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 06:08 GMT
Nmap scan report for 10.10.219.196
Host is up (0.00037s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
MAC Address: 02:FE:A4:8F:12:F3 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 153.99 seconds
root@ip-10-10-40-82:~# sudo nmap -sV -p80,3389,5985 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-02-26 06:12 GMT
Nmap scan report for 10.10.219.196
Host is up (0.00023s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
MAC Address: 02:FE:A4:8F:12:F3 (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

robots.txt

```shell
UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/
```

/umbraco でログイン画面表示

```shell
$ searchsploit umbraco
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                               | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                        | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                        | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Directory Traversal                                           | aspx/webapps/50241.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting                        | php/webapps/44988.txt
Umbraco v8.14.1 - 'baseUrl' SSRF                                                  | aspx/webapps/50462.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Metasploit は実行したが成功しなかった。  
他は認証が必要。

管理者名が分からない。ここでウォークスルーを見た。

```text
A cheers to our IT department
Tuesday, December 31, 2019

During our hard times our beloved admin managed to save our business by redesigning the entire website.

As we all around here knows how much I love writing poems I decided to write one about him:

Born on a Monday,
Christened on Tuesday,
Married on Wednesday,
Took ill on Thursday,
Grew worse on Friday,
Died on Saturday,
Buried on Sunday.
That was the end…
```

この詩を検索すると Solomon Grundy という童謡。それが管理者名らしい。  
あ～、なるほど。・・・とはならない。釈然としない。

メールアドレスは、SG@Anthem.com

SG@Anthem.com / UmbracoIsTheBest! -> 管理画面ログイン  
SG / UmbracoIsTheBest! -> RDP ログイン

その後、

- Web ページのそこかしこに隠された意味のないフラグを集める
- C ドライブ直下に隠しフォルダがある
- その中のファイルに読み取り権限を自分でつける
- そのパスワードを使って Administrator で接続

## 振り返り

- 徒労感が大きく楽しくはないが、ポイントが大きいので許せる感じ。ランキング上げるには良いが、楽しみたい人にはお勧めしない
- パスワード使いまわしは CTF では殆ど見ないが、実際大事な観点ではある
