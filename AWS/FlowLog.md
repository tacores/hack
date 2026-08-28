# FlowLog

https://tryhackme.com/room/theinvisiblenetwork

## 基礎知識

VPC FlowLogs は、VPC 内のネットワーク インターフェイスとの間で送受信される IP トラフィックに関するメタデータをキャプチャする。

フローログは、次の3つのレベルで有効化できる。

- VPCレベル- VPC内のすべてのネットワークインターフェースのすべてのトラフィックをキャプチャ。
- サブネットレベル- 特定のサブネット内のすべてのインターフェースのトラフィックをキャプチャ。
- ENI（Elastic Network Interface）レベル- 単一のインターフェースのトラフィックをキャプチャ。

フローログは、以下の3つの宛先に配信できる。

- CloudWatch Logs
- Amazon S3
- Amazon Kinesis Data Firehose

FlowLogsは、パケットの内容ではなく、接続に関するメタデータを記録する。また、以下の項目は除外される。

- Amazonが提供するDNSサーバーへのDNSクエリ
- インスタンスメタデータサービスへのトラフィック（169.254.169.254）
- DHCPトラフィック
- VPCルーターへのトラフィックと、各サブネット内の予約済みアドレス

## 検出

VPCに存在するフローログ

```sh
aws ec2 describe-flow-logs \
      --filter "Name=resource-id,Values=$VPC_ID" \
      --output table
```

アカウント内に存在するフローログ

```sh
aws ec2 describe-flow-logs \
      --query "FlowLogs[*].{ID:FlowLogId,Resource:ResourceId,Status:FlowLogStatus,Destination:LogDestinationType}" \
      --output table
```

## 設定例

```sh
aws logs create-log-group --log-group-name /vpc/net-lab-flow-logs

aws logs put-retention-policy \
      --log-group-name /vpc/net-lab-flow-logs \
      --retention-in-days 90
```

```sh
cat << 'EOF' > /tmp/flow-logs-trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
      --role-name net-lab-flow-logs-role \
      --assume-role-policy-document file:///tmp/flow-logs-trust-policy.json \
      --description "Allows VPC Flow Logs to publish to CloudWatch Logs" \
      --permissions-boundary arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/Room34-LearnerBoundary
```

```sh
cat << 'EOF' > /tmp/flow-logs-permissions-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
      --role-name net-lab-flow-logs-role \
      --policy-name FlowLogsToCloudWatch \
      --policy-document file:///tmp/flow-logs-permissions-policy.json
```

```sh
ROLE_ARN=$(aws iam get-role --role-name net-lab-flow-logs-role --query "Role.Arn" --output text)

aws ec2 create-flow-logs \
      --resource-type VPC \
      --resource-ids $VPC_ID \
      --traffic-type ALL \
      --log-destination-type cloud-watch-logs \
      --log-group-name /vpc/net-lab-flow-logs \
      --deliver-logs-permission-arn $ROLE_ARN
```



