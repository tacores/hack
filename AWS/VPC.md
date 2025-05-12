# VPC

https://tryhackme.com/room/attackingdefendingvpcs

## 基本

- AWS VPC はリージョン単位で構築される。VPC ベースのワークロードをデプロイするリージョンごとに VPC を作成する必要がある。
- AWS アカウントを作成すると、すべての標準リージョンにデフォルト VPC がデプロイされる。これらの VPC はそれぞれ、172.31.0.0/16 という同じ CIDR 範囲を使用する。
- ARP スプーフィングなどの一般的な攻撃手法は VPC 環境では機能しない。

## AZ、サブネット、ルートテーブル

- VPC はサブネットで構成され、各サブネットは 1 つのアベイラビリティーゾーン (AZ) にのみ存在する。
- サブネットは VPC CIDR 範囲のサブセットである CIDR 範囲を使用する必要があり、サブネット CIDR 範囲は重複できない。
- すべての VPC には VPC ルーターがある。
- VPC には、インターネットゲートウェイ（IGW）と仮想プライベートゲートウェイ（VGW）という 2 つの特別なルート宛先がある。IGW は VPC とインターネットの境界として機能するエンドポイント。VGW は VPC とオンプレミスネットワーク の境界として機能するエンドポイント。
- AWS はマネージド NAT ゲートウェイと呼ばれるサービスを提供している。これは AWS が運用する EC2 インスタンスで、NAT 機能を提供することでプライベートサブネットからインターネットへのアクセスを可能にする。通常、プライベートサブネットでは 0.0.0.0/0 の宛先を NAT ゲートウェイにルーティングするように設定し、パブリックサブネットでは 0.0.0.0/0 の宛先を IGW に直接ルーティングするようにルートテーブルを設定する。

## NACL とセキュリティグループ

### NACL

- ネットワークアクセスコントロールリスト（NACL）は、AWS が提供する VPC ファイアウォール構造のひとつで、サブネットに適用される。
- NACL はステートレスであり、最初の（インバウンド）接続と戻りの（アウトバウンド）トラフィックの両方が承認される必要がある。
- NACL は許可または拒否のいずれかのアクションをサポートし、アクションは特定の順序で評価される。
- IAM とは異なり、明示的な拒否は明示的な許可を上書きしない。代わりに、ルールは一致するまで順番に処理される。
- デフォルトでは、NACL には「すべて拒否」ルールがある。

### セキュリティグループ

- セキュリティグループは、 EC2 インスタンスや RDS データベースなどの特定のリソースにアタッチされる。
- セキュリティグループは許可のみをサポートする。
- セキュリティグループはステートフルであり、Ingress（インバウンド）と Egress（アウトバウンド）で異なるルールセットを持つ。
- セキュリティグループは、ソースとして CIDR 範囲を参照するか、別のセキュリティグループ ID を参照できる。セキュリティグループが参照されている場合、そのセキュリティグループが関連付けられているすべての ENI がトラフィックの有効なソースとなる。

### VPC 内外

- EC2, RDB, RedShift 等は VPC 内。S3, Lambda, DynamoDB 等は VPN 外。
- VPC 内のリソースは NACL とセキュリティグループによって保護され、誰も直接アクセスできないようにすることができる。VPC 外のリソースは IAM によってのみ保護される。
- VPC 内のすべてのリソースには、 Elastic Network Interface (ENI)がある。ENI は、 VPC の一部である仮想ネットワークカード。ENI はインスタンスにアタッチしたり、デタッチしたり、別のインスタンスに移動したりできる（多くの場合、これは高可用性フェイルオーバーを容易にするために行われる）。
- ENI は特定のサブネットに関連付けられており、同じアベイラビリティゾーン内の 2 つのサブネットにまたがる EC2 インスタンスをブリッジできる。

```shell
# アカウント内の全てのENIを一覧表示
aws ec2 describe-network-interfaces
```

## VPC ワームホール

VPC 内のリソースが VPC 外の特定のリソースと通信できるように、VPC エンドポイントと AWS PrivateLink という 2 つの関連サービスがある。これらのサービスにより、ネットワークチームやセキュリティチームは VPC 内のインターネットからの送信を制限したり、完全に無効化したりできる。

### VPC エンドポイント

- VPC エンドポイントは S3 と DynamoDB で動作する。プライベートサブネット内のマシンは S3 にアクセスするために NatGateway を利用する必要がなくなる。
- VPC エンドポイントには、 VPC ルートテーブルにルートが必要。ルートの宛先は、特定の CIDR 範囲ではなく、マネージドプレフィックスリストと呼ばれるサービスの抽象的な表現。
- AWS はプレフィックスリストを使用して、 AWS CIDR 範囲を VPC にマッピングする。これらのプレフィックスリストにより、AWS は顧客に VPC ルートテーブルやセキュリティグループを変更させることなく、パブリック IP アドレスを管理できる。

```shell
# プレフィックスリスト表示（VPCコンソールでも確認可能）
aws ec2 describe-prefix-lists
```

### AWS PrivateLink

- VPC PrivateLink は、 AWS サービスまたは他の AWS カスタマーに紐付けられた VPC 内の ENI 。
- AWS またはそのパートナーは、インターネットへのトラフィックの送信をカスタマーに要求することなく、AWS カスタマーにサービスを提供できる。
- AWS コンソールでは、利用可能なすべての PrivateLink サービスを確認できる。

## VPC 内の DNS

- Amazon が提供する DNS サーバーの IP アドレスは、常に「 VPC IPv4 ネットワーク範囲のベースに 2 を加えた値」になる。Amazon DNS サーバーは、すべてのパブリック DNS エントリを解決する。
- プライベート Route53 ホストゾーンを作成し、VPC にアタッチすることもできる。Route53 は Amazon のホスト型 DNS サービス。重要なのは、VPC 内のインスタンスに対して Amazon DNS プロバイダーが名前解決するプライベート DNS エントリを設定できること。
- VPC の DNS サーバーは、他のネットワーク（オンプレミスネットワークを含む）からのリクエストに応答し、オンプレミスの DNS サーバーにリクエストを転送するように設定することもできる。DNS は、クラウドの侵害が企業のオンプレミスネットワークの侵害につながる可能性がある、もう一つのラテラルムーブメントパス。
- DNS ファイアウォールを使用すると、 VPC 内のインスタンス（および Route53 リゾルバーを利用するオンプレミスのマシン）がクエリを実行できる DNS ドメインと、クエリを実行できない DNS ドメインを設定できる。DNS ファイアウォールは、DNS 情報漏洩攻撃に対する緩和メカニズムとして機能する。
- DNS クエリログを使用すると、Route53 リゾルバーの DNS アクティビティをセキュリティ情報イベント管理 ( SIEM ) にフィードして、脅威分析をさらに強化できる。
- VPC は、DNS ログをロググループ「VPCResolverLogs」に送信するように設定されている。CloudWatch Logs コンソールから DNS エントリを確認できる。

## VPC モニタリング

- VPC Flow Logs は、パケットヘッダーを記録しますが、パケットの内容は記録しないという点で、 NetFlow に似ている。FlowLogs サービスは、生成されたログを CloudWatch Logs または S3 バケットに送信できる。
- VPC トラフィックミラーリングは ENI ベースのネットワークタップとして機能し、ディープパケットインスペクションに役立つ。

https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html

https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html

## VPC 相互接続

- [DirectConnect](https://aws.amazon.com/directconnect/)
- [Site to Site VPN](https://aws.amazon.com/vpn/site-to-site-vpn/)
- [VPC Peering](https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html)
- [Transit Gateway](https://aws.amazon.com/transit-gateway/)
- [Client VPN](https://aws.amazon.com/vpn/client-vpn/)

## ケーススタディ

ターゲットのネットワーク向けエンジニアの AWS 認証情報を入手したというケース。

### EC2 インスタンスに PublicIP アドレスを割り当てる

```shell
# Public IPアドレスの割り当て（取得）
~ $ aws ec2 allocate-address
{
    "AllocationId": "eipalloc-0cd5faf4a0035e813",
    "PublicIpv4Pool": "amazon",
    "NetworkBorderGroup": "us-east-1",
    "Domain": "vpc",
    "PublicIp": "52.73.71.55"
}
```

```shell
# ENI（ネットワークインターフェース）を見つける
~ $ aws ec2 describe-instances > instances.json
~ $ grep eni instances.json
                                "AttachmentId": "eni-attach-06a1be2b508125608",
                            "NetworkInterfaceId": "eni-065a26428f62c9a4d",
```

```shell
# IP と ENI を関連付ける
~ $ aws ec2 associate-address --network-interface-id eni-065a26428f62c9a4d --allocation-id eipalloc-0cd5faf4a0035e813
{
    "AssociationId": "eipassoc-03a9e57669ce31b7e"
}
```

### プライベートサブネットが直接インターネットアクセスできるようルートテーブルを変更

```shell
# インターネットGW ID を取得
~ $ aws ec2 describe-internet-gateways
```

```shell
# ルートテーブルIDを取得
$ aws ec2 describe-route-tables
```

```shell
# ルートテーブルにルートを追加
aws ec2 create-route --route-table-id rtb-0196ffe0d336924d2 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-05daed223ba7228eb
```

```shell
# 追加されたことを確認
aws ec2 describe-route-tables
```

### セキュリティグループを変更

```shell
# セキュリティグループを確認
aws ec2 describe-security-groups > security-groups.json
```

```shell
# セキュリティグループルールを追加（sgはステートフルのため1個で良い）
$ aws ec2 authorize-security-group-ingress  --protocol all --port 0-65535 --cidr 0.0.0.0/0 --group-id sg-0ceca94cffb5fbfa7
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-04ea450e3d5ddf111",
            "GroupId": "sg-0ceca94cffb5fbfa7",
            "GroupOwnerId": "830352411100",
            "IsEgress": false,
            "IpProtocol": "-1",
            "FromPort": -1,
            "ToPort": -1,
            "CidrIpv4": "0.0.0.0/0",
            "SecurityGroupRuleArn": "arn:aws:ec2:us-east-1:830352411100:security-group-rule/sgr-04ea450e3d5ddf111"
        }
    ]
}
```

### NACL を変更

```shell
# NACL ID を取得
$ aws ec2 describe-network-acls > nacls.json
```

```shell
# 評価リストの先頭に新しいルールを作成（受信を許可）
$ aws ec2 create-network-acl-entry --cidr-block 0.0.0.0/0 --ingress  --protocol -1 --rule-action allow --rule-number 1 --network-acl-id acl-0da2b26bc8e3ed5ce
```

```shell
# NACL はステートレスのため、送信も許可が必要
aws ec2 create-network-acl-entry --cidr-block 0.0.0.0/0 --egress  --protocol -1 --rule-action allow --rule-number 1 --network-acl-id acl-0da2b26bc8e3ed5ce
```

```shell
# 変更後内容確認
aws ec2 describe-network-acls --filters Name=network-acl-id,Values=acl-0da2b26bc8e3ed5ce
```
