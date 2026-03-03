# AWSサービスの監視

https://tryhackme.com/room/monitoringawsservices

## S3

### ハント

バケットはデフォルトでプライベートなため、パブリックになった瞬間のイベントを監視する。

```
index=* eventName=PutBucketPublicAccessBlock

index=* eventName=PutBucketPolicy
```

それに続く ListObjects, GetObject に注目。

## EC2

RDPやSSHがインターネットから接続可能になっていないか。

- セキュリティグループがパブリックRDPアクセスを許可するように変更された場合
- EC2インスタンスが安全でないセキュリティグループを使用するように起動された場合

など

### ハント

#### 新しいセキュリティグループが作成された

```sh
# 作成されたセキュリティグループIDをメモ
index=* eventName=CreateSecurityGroup

# 指定された受信 (イングレス) ルールをセキュリティ グループに追加
index=* eventName=AuthorizeSecurityGroupIngress sg-xxxxxx

# 新しい VM または古い VM がこのセキュリティグループを使用しているか
index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx
```

#### セキュリティグループルールの1つが変更された

```sh
index=* eventName IN(*SecurityGroupIngress, ModifySecurityGroupRules)

index=* earliest=-1y eventName=CreateSecurityGroup sg-xxxxxx

index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx
```

### 注意点

上記のイベントが検出されたからといって必ずしも外部から接続可能になっているとは限らない。セキュリティグループ、ネットワーク ACL、VM ファイアウォールのセキュリティ制御があり、他の制御によってプライベート状態が保たれている可能性もある。

## データベース

サービスによって異なるが、概ねデータベースの公開非公開は、次の2つのいずれかまたは両方によって決まる

- アクセスポリシー: S3と同様に、サービスアクセスを定義するリソースベースのポリシー
- ネットワーク制御: VPC、サブネット、アクセス制御リスト、セキュリティグループ、 EC2と同じ

### Amazon RDS

### ハント

```
index=* eventName=CreateDBInstance

index=* eventName=ModifyDBInstance

index=* eventName=AuthorizeSecurityGroupIngress
```


