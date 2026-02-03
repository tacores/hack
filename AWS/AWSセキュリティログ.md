# AWSセキュリティログ

https://tryhackme.com/room/awssecuritylogging

## 検知ルール

CloudTrailログを使用した、コントロールプレーンの検知のためのSigmaルール

https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws/cloudtrail

Elasticルール(AWSに限らない)

https://www.elastic.co/guide/en/security/current/prebuilt-rules.html

## ログ調査

書き込みイベントから始める

```
readOnly=false
```

```
ModifySecurityGroupRules
```

## ログを出す場所

### コントロールプレーン

設定や権限の変更に注目。

#### CloudTrail

全てのAPI履歴を保存（デフォルトでは30日分）

### マネージドサービス

#### CloudFront ログ

IISアクセスログに似ている。

#### Amazon VPC Flow ログ

ネットワークトラフィックを監視できる。ただし膨大な量のイベントが生成される点に注意。

#### S3 データイベント

CloudTrail でS3を含む一部サービスのデータイベントを記録するように拡張できる。

#### CloudWatch

集中的なログ記録と監視に広く利用されているAWSサービス

### ワークロード

パブリッククラウド、ハイブリッド、オンプレミス環境で動作する仮想マシン（VM）、コンテナ、サーバーレス関数などなどが出すログ
