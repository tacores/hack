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

## ログイン監視

https://tryhackme.com/room/monitoringawslogins

### コンソールログインの監視

#### 重要な監視

- rootユーザーのログイン
- サービスユーザーのログイン
- VPN,Tor、クラウドホスティング、その他疑わしいIPからのログイン成功
- ブルートフォース

```txt
eventName=ConsoleLogin
```

### アクセスキーの監視

#### コンソールからの実行かアクセスキー経由での実行か

- 認証情報は各API呼び出しに含まれるため、ConsoleLoginイベントは記録されない。CloudTrailには実行したAPIイベントのみ記録される。
- アクセスキーの場合、`sessionContext` セクションがない
- userAgent がブラウザかプログラム的な値か（偽装されていない場合）

```txt
// アクセスキーログインのみをフィルタリングするSplunkクエリ
userIdentity.accessKeyId=AKIA*

// コンソールアクションをフィルタリングするための代替クエリ
NOT userIdentity.sessionContext.attributes.creationDate=*
```

### IAMロールの不正使用の検出

#### EC2 か IAM ユーザーか

`i-123456789` の部分がロールセッション名。デフォルトでEC2の場合はインスタンス名、IAMユーザーの場合はユーザー名が設定される。カスタムセッション名が設定されている場合は判別できないので調査が必要。

```json
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::398985017225:assumed-role/UserAvatarsProcessor/i-123456789",
  },
```

#### AssumeRole イベント

AssumeRole後のすべてのアクションはロール自体からのものとしてログに記録され、元のユーザー名は参照されない。そのため、実際にロールを引き受けたユーザーを確認するには、必ず直前のAssumeRoleイベントまで遡る必要がある。

```txt
eventName=AssumeRole
```

### IAMの変更の検出

| Event Names | 説明 | 確認・対応のポイント |
|------------|------|----------------------|
| PutUserPolicy, PutRolePolicy, PutGroupPolicy | 既存の AWS ポリシーが変更された | 「ReadOnlyAccess」という名前なのに EC2 の起動・停止が可能になっている、など**ポリシー名と実際の権限内容の不一致**がないか確認する |
| AttachUserPolicy, AttachGroupPolicy, AttachRolePolicy, AddUserToGroup | IAM アイデンティティがグループに追加された、または新しいポリシーが割り当てられた | 新人インターンに「AdministratorAccess」が付与されている、など**権限付与が過剰・不自然でないか**確認する |
| DeleteVirtualMFADevice, DeactivateMFADevice | ユーザー自身、または他者の MFA が無効化された | 正当なのは、**直後に新しい MFA 登録が行われる場合のみ**（例：スマホ紛失による MFA 再設定） |
| CreateAccessKey, UpdateAccessKey | IAM アクセスキーが作成または有効化された | 特に**権限の強いユーザー**については IT 部門に必ず確認する。**漏洩したアクセスキーは AWS における最も一般的な初期侵入ベクタ** |
