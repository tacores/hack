# EC2

https://tryhackme.com/room/amazonec2attackdefense

## EC2 接続方法

| Method               | Requires Direct Network Access | Requires Agent                         | Requires EC2 IAM Permissions |
| -------------------- | ------------------------------ | -------------------------------------- | ---------------------------- |
| Direct SSH/RDP       | YES                            | NO                                     | NO                           |
| EC2 Instance Connect | YES                            | YES (Installed on Amazon Linux 2)      | NO                           |
| SSM Run Command      | NO                             | YES                                    | YES                          |
| SSM Session Manager  | NO                             | YES                                    | YES                          |
| EC2 Serial Console   | NO                             | NO, but users must have a password set | NO                           |

## インスタンス権限

### AWS 認証情報を取得

インスタンス内から AWS 認証情報を取得するには、インスタンスメタデータサービス（IMDS）を利用する。

169.254.169.254 は、IMDS がリッスンしている、AWS ハイパーバイザーの一部である特別な IP アドレス。

```shell
# ロール名を取得
role_name=$( curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ )

echo $role_name
Ec2RoomInstanceProfile

# ロール名を使い、セッション認証情報を取得
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/${role_name}
```

### IMDSv2 を有効にする

v2 の方がセキュリティが強固。

```shell
# インスタンスID取得
instance_id=$( curl -s http://169.254.169.254/latest/meta-data/instance-id )
echo "My Instance ID is $instance_id"

# IMDSv2 を有効化
aws ec2 modify-instance-metadata-options --instance-id $instance_id --http-tokens required --region us-east-1
```

IMDSv2 を使って認証情報を取得

```shell
# トークンを取得
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

# ロール名を取得
role_name=$( curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ )
echo "Role Name is $role_name"

# 認証情報を取得
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/${role_name}
```

## EC2 ネットワークとストレージ

### ネットワーク

- EC2 ネットワークは Elastic Network Interface (ENI) を中心に構築される。
- すべての EC2 インスタンスには少なくとも 1 つの ENI が存在する。
- デフォルトで EC2 インスタンスはインスタンスからのトラフィックとインスタンス宛てのトラフィックのみを送受信できる。
- すべての ENI には、少なくとも 1 つのセキュリティグループが関連付けられている。
- セキュリティグループは、ENI との通信に許可される IP 送信元アドレス、ポート、プロトコルを定義する。
- EC2 インスタンスを NAT、ファイアウォール、またはルーターとして機能させるには、このデフォルトの送信元/宛先チェックを無効にする必要がある。

```shell
# ENIの1つを確認
aws ec2 describe-network-interfaces | jq '.NetworkInterfaces[0]'
```

### ストレージ

- EC2 は、EC2 インスタンスのハードディスクストレージとして Amazon Elastic Block Store (EBS) を使用する。
- EBS ボリュームは、バックアップや共有のためにスナップショットを作成できる。S3 に保存されるためコストが低い。
- エフェメラルストレージは、EC2 インスタンスを実行している物理マシン内に存在する SSD。耐久性のためにコンピューティングワークロードとは分離されている EBS ボリュームとは異なり、エフェメラルストレージはインスタンスの停止と再起動時に消去される。エフェメラルストレージはスナップショットをサポートしない。
- EBS ボリュームとスナップショットは、様々なタイプの KMS 暗号化を使用して暗号化できる。
- EBS スナップショットは AWS アカウント間で共有できるため、組織で承認されたゴールデンイメージを共有することで、データ、ソースコード、またはシークレットを誤って世界中に公開してしまう可能性が高まる。

```shell
# スナップショットの情報を見る
$ aws ec2 describe-snapshots --snapshot-ids snap-051a9c27b12a797a4
{
    "Snapshots": [
        {
            "Description": "",
            "Encrypted": false,
            "OwnerId": "019181489476",
            "Progress": "100%",
            "SnapshotId": "snap-051a9c27b12a797a4",
            "StartTime": "2022-04-17T16:19:28.473000+00:00",
            "State": "completed",
            "VolumeId": "vol-ffffffff",
            "VolumeSize": 1,
            "StorageTier": "standard"
        }
    ]
}
```

スナップショットはリージョンに存在するが、ボリュームはマウント元のマシンと同じ AZ に存在する必要がある。

```shell
# AZの取得
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone
```

```shell
# スナップショットからボリュームを作成
aws ec2 create-volume --snapshot-id snap-051a9c27b12a797a4 --volume-type gp3 --region us-east-1 --availability-zone <az>
```

```shell
# インスタンスにボリュームをアタッチ
instance_id=$( curl  -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/instance-id )

aws ec2 attach-volume --region us-east-1 --device /dev/sdh --instance-id $instance_id --volume-id vol-REPLACE-ME-WITH-YOUR-VolumeId

sudo fdisk -l
```

```shell
# ボリュームをマウント
sudo mkdir /snapshot-recovery
sudo mount /dev/nvme1n1 /snapshot-recovery
ls /snapshot-recovery
```

## EC2 設定

### カスタム AMI

```shell
# アカウント内のAMIを確認
aws ec2 describe-images --owners 019181489476 --region us-east-1
```

### UserData

```shell
# UserDataの取得
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data
```

```shell
# 方法２
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
instance_id=$( curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/instance-id )
aws ec2 describe-instance-attribute --attribute userData --instance-id $instance_id --region us-east-1 --query UserData --output text  | base64 -d
```

```shell
# rootとして読む
/var/lib/cloud/instance/scripts/part-001
```

## オートスケーリング

### セキュリティ観点の注意事項

- ASG がスケールダウンする際、フリート内の最も古いインスタンスがスケールダウンされる。つまり、信頼できないトラフィックに最もさらされているマシンが最初に終了される。
- パブリックに公開する必要があるのはロードバランサーのみ。ELB は外部トラフィックを受け取り、プライベート VPC アドレスを使用して EC2 フリートに渡す。したがって、EC2 フリートにパブリックアドレスは必要ない。
- ロードバランサーの種類によっては、無料の AWS 証明書管理（ACM）システムを使用して暗号化された TLS 接続を終端できる。第 2 世代の ELB（アプリケーションロードバランサー、または ALB）には、AWS ウェブアプリケーションファイアウォール（WAF）を接続できる。この WAF は、 OWASP で定義されているような一般的なレイヤー 7（アプリケーション層）攻撃を検出またはブロックできる。
