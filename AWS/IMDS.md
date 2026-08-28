# IMDS

https://tryhackme.com/room/theleakymetadata

## 検出

```sh
aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[0].Instances[0].MetadataOptions" \
  --output json

{
    "State": "applied",
    "HttpTokens": "optional",
    "HttpPutResponseHopLimit": 2,
    "HttpEndpoint": "enabled",
    "HttpProtocolIpv6": "disabled",
    "InstanceMetadataTags": "disabled"
}
```

HttpTokens が optional の場合、IMDSv1 を許可する。

SSRFにより認証情報が暴露する可能性がある。

```sy
sh-5.2$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole
```

## 修正

```sh
aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens required \
    --http-endpoint enabled
```

トークンが必要になる。

```sh
sh-5.2$ curl -I http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole
HTTP/1.1 401 Unauthorized

sh-5.2$ TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

sh-5.2$ curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/Room43ManagedInstanceRole
{
  "Code" : "Success",
```

インスタンス起動時に HttpTokens を設定する方法。

```sh
$ aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type t3.micro \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SECURE_SG" \
    --iam-instance-profile Name=Room43ManagedInstanceProfile \
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
    --no-associate-public-ip-address \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=imdsv2-secure-instance},{Key=Purpose,Value=room-43-secure-build}]'
```
