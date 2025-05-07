# IAM

## 基本

### 用語

- AWS アカウント：AWS の独立した顧客。各アカウントは独立した信頼境界を持つ。AWS アカウント内には、複数の IAM ユーザー、グループ、およびロールが存在する場合がある。複数の AWS アカウントを AWS Organization のメンバーにすることができる。
- IAM ユーザー：AWS アカウント内で作成されるユーザー。IAM ユーザーは、認証、アイデンティティ、認可を 1 つのユニットに統合する。
- ルートユーザー：AWS が顧客とみなすユーザー。請求の変更やアカウントの解約など、カスタマーサービスとの主要なやり取りを行う。ルートユーザーは全権を握っており、アカウント内のすべてのリソースを完全に制御できる。ルートユーザーのユーザー名は、アカウント作成時に使用したメールアドレスと同じ。
- IAM ロール：個人、サービス、またはリソースが引き受けることを意図した AWS プリンシパル。ユーザーと比較して、一時的な権限付与。
- IAM グループ：IAM ユーザーの集合。多くの分野では、権限付与は IAM グループ経由でのみ行うことがベストプラクティスとされている。
- IAM ポリシー：プリンシパル（ユーザー、グループ、またはロール）がリソースに対して実行できるアクションを定義する。
- Amazon リソースネーム（ARN）は、AWS リソースを一意に識別する。
- IAM アイデンティティ：IAM プリンシパルとも呼ばれる。AWS アカウントとそのリソースへのアクセスを提供します。これらのプリンシパルは通常、認証を行うか、認証が実行されたことを検証する。プリンシパルは、リソース（ S3 バケットなど）にアタッチされ、リソースに対する操作権限を定義するリソースポリシーの中核となる概念。

### IAM プリンシパル

- IAM ユーザー
- IAM ロール
- IAM グループ
- AWS サービス
- `*` (Everyone)
- フェデレーションアイデンティティ

## IAM 権限

### アクション

アクションは大文字と小文字の区別はされない仕様。

```
サービス:API

ec2:StopInstance
s3:GetObject
sts:AssumeRole
iam:ListUsers
```

IAM アクションの完全なリスト  
https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html

### リソース

リソースのデフォルト値は`*`になっている。これは、AWS が顧客のリソースを識別できないためなので、最小権限の原則に従って適切に設定する必要がある。

### エフェクト

エフェクトのデフォルトは Deny であり、Allow と Deny が競合する場合は Deny が勝つ。

### プリンシパル

プリンシパル要素は、リソースポリシーにのみ必須で、アイデンティティベースのポリシーには必須ではない。

指定できるのは下記のどれか。

- AWS account and root user
- IAM roles
- Role sessions
- IAM users
- Federated user sessions
- AWS services
- All principals

### コンディション

指定できるコンディションは、アクションとリソースの種類により異なる。  
指定可能なコンディションは、上述の「IAM アクションの完全なリスト」で参照可能。

その他に、リソースタグも設定可能。

```json
"Condition": {
    "StringEquals": {
        "aws:ResourceTag/hogwarts-house": "Hufflepuff"
    }
```

## 最小権限の原則適用

### ステップ

1. 特定のサービスに制限する
1. 読み込みか、変更か
1. 特定リソースの列挙

### （例）目標とするポリシー

```
・すべてのEC2設定 を監査する
・シンガポール地域でのマシンの起動
・特定の企業S3バケットにアクセスする
```

#### 1. 特定のサービスに制限する

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PermitEC2",
      "Effect": "Allow",
      "Action": ["ec2:*", "s3:*"],
      "Resource": "*"
    }
  ]
}
```

#### 2. 読み込みか、変更か

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PermitEC2",
      "Effect": "Allow",
      "Action": ["ec2:Describe*", "ec2:Get*"],
      "Resource": "*"
    },
    {
      "Sid": "Permit S3",
      "Effect": "Allow",
      "Action": ["s3:Get*", "s3:List*"],
      "Resource": "*"
    }
  ]
}
```

#### 3. 特定リソースの列挙

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PermitEC2",
      "Effect": "Allow",
      "Action": ["ec2:Describe*", "ec2:Get*"],
      "Resource": "*"
    },
    {
      "Sid": "Singapore",
      "Effect": "Allow",
      "Action": ["ec2:*"],
      "Resource": "arn:aws:ec2:ap-southeast-1:*:instance/*"
    },
    {
      "Sid": "Permit S3",
      "Effect": "Allow",
      "Action": "s3:Get*",
      "Resource": [
        "arn:aws:s3:::my_corporate_bucket/*",
        "arn:aws:s3:::my_corporate_bucket"
      ]
    }
  ]
}
```

## IAM 認証

### ログインプロファイル

コンソールパスワードを意味する

### API アクセスキー

#### 長期セッションキー

- AKIA で始まる。
- 有効期限なし。ただし定期的にローテーションするのがベストプラクティス。
- アクセスキー ID とシークレットアクセスキーで構成される。
- 一度に 2 つのアクセスキーしか持つことができない。
- アクセスキー ID またはシークレットは設定できない。常に AWS によって生成される。

無効化、有効化、削除

```shell
aws iam update-access-key --access-key-id AKIA... --status Inactive
aws iam update-access-key --access-key-id AKIA... --status Active
aws iam delete-access-key --access-key-id AKIA...
```

生成

```shell
aws iam create-access-key --user-name student
```

#### セッションキー

- ASIA で始まる。
- 有効期限あり。
- 一時的なものであるため、削除したり無効化したりはできない。
- AWS セキュリティトークンサービス（略称「sts」）によって生成される。

生成

```shell
aws sts get-session-token
```

```shell
# AKIA文字列からAWSアカウントを識別
aws sts get-access-key-info --access-key-id AKIA4CVG4JHOCT6DNCHN
{
    "Account": "830352411100"
}
```

### サービスがロールの認証情報を取得する方法

- AWS STS AssumeRole API 呼び出し
  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- aws sts assume-role AWS CLI コマンド
  https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sts/assume-role.html
- EC2 インスタンスの場合、ハイパーバイザー内に特別なネットワークアドレスがあり、これを使用して EC2 インスタンスプロファイルの一時的な認証情報をリクエストできる。
- コードが AWS Lambda で実行されている場合、アクセスキー ID、シークレットアクセスキー、セッショントークンは環境変数として使用できる。
- ECS コンテナの場合、コンテナの認証情報を curl で取得できる別の IP アドレスがある。

```shell
# タスクのIAMロールが設定されている場合は、$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI 環境変数が入力される。
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

curl $AWS_CONTAINER_CREDENTIALS_FULL_URI -H "X-aws-ec2-metadata-token: $AWS_CONTAINER_AUTHORIZATION_TOKEN"
```

## 豆

- IAM ユーザーとしてアカウントの root メールアドレスを特定することはできないが、AWS アカウントが AWS Organization のメンバーである場合、コマンドで組織マスターのメールアドレスを取得可能。

```shell
aws organizations describe-organization
```

### コマンド

```shell
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam create-login-profile --user TryHackMe-IAM-User --password 'SolarWinds321!'

aws iam update-login-profile --user TryHackMe-IAM-User --password 'SolarWinds123!'
```
