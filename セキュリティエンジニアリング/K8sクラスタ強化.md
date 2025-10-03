# K8sクラスタ強化

https://tryhackme.com/room/clusterhardening

https://tryhackme.com/room/k8sbestsecuritypractices

## CISセキュリティベンチマーク  

https://www.cisecurity.org/benchmark/kubernetes

CISベンチマークとK8Sのバージョンは1対1ではない。  
[CISベンチマークがどのバージョンに対応しているかの一覧表](https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md#cis-kubernetes-benchmark-support)


## Kube-bench  

https://github.com/aquasecurity/kube-bench

## kubelet

Kubelet はクラスター内のすべてのノードで実行されるエージェントであり、コンテナがポッド内で確実に実行されていることを確認する役割を担っている。

kubeletコンポーネントは、kube-apiserverから発信されたトラフィックにのみ応答する必要がある。

- kubelet設定ファイル
- Kubeletによる認証

詳細はTHM参照

## APIトラフィックのセキュリティ保護

各コンポーネント間の通信をTLSで暗号化する。THM参照

## アドミッションコントローラ

リクエストが安全で本物だとしても、リクエストが無駄なリソースを消費したり、安全でない処理を実行したりしていないかを確認するために、リクエストの動作をチェックする。

Webhookには、チェックのロジックが含まれる。

## サービスアカウント

```sh
kubectl create serviceaccount example-name --namespace example-namespace
```

Pod、デプロイメント定義で関連付ける。

ロール作成

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-checker-role
  namespace: test-chambers
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

ロールバインディング作成

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-checker-role-binding
  namespace: test-chambers
subjects:
- kind: ServiceAccount
  name: pod-checker
  namespace: test-chambers
roleRef:
  kind: Role
  name: pod-checker-role
  apiGroup: rbac.authorization.k8s.io
```

```sh
kubectl apply -f role.yaml
kubectl apply -f rolebind.yaml
```

## ランタイムセキュリティ

https://tryhackme.com/room/k8sruntimesecurity

### 監査ポリシー

- 機密リソースの場合は、メタデータレベルでのみログに記録する
- 読み取り専用URLは通常、ログに記録するべきではない
- すべてのリソース（読み取り専用URL以外）を少なくともメタデータレベルでログに記録し、リソースが重要な場合は、機密情報が含まれていない限り、RequestResponseレベルでログに記録する

## セキュリティランタイム強制ツール

AppArmour などの利用。

## Falco

Falcoはランタイム脅威検出エンジン。  
システム（Kubernetes環境）の動作を分析し、観察された動作を事前定義された脅威条件のリストと比較し、一致するものが見つかった場合にアラートをトリガーする。
