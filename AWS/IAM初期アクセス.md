# IAM 初期アクセス

https://tryhackme.com/room/awsiaminitialaccess

AWS における主要なアクセスメカニズムは、AWS IAM サービスに関連付けられた認証情報。これらの認証情報、あるいはそれらを含むシステムを侵害することが、AWS のサービスやリソースにアクセスする唯一の方法。

## ソースコードに含まれる認証情報

- github
- PyPi

等のリポジトリにアクセスキーが残っていないか？

## スタックセットのフィッシング

- Infrastructure as Code (IaC) を介して AWS アカウントが侵害されるフィッシングシナリオ
- AWS CloudFormation には、数回のクリックでインフラストラクチャをデプロイできる Launch Stack URL 機能がある

形式

```
https://console.aws.amazon.com/cloudformation/home?region=region#/stacks/new?stackName=stack_name&templateURL=template_location
```

例

```
https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=tryhackme&templateURL=https://s3.amazonaws.com/bucket-name/template-name.template
```

この URL にアクセスすると、AWS CloudFormation コンソールのスタック作成ウィザードに誘導される。認証がまだ完了していない場合には、AWS マネジメントコンソールのサインインページに移動し、その後 AWS CloudFormation のスタック作成ウィザードにリダイレクトされる。

つまり、サインインページを偽装し、認証情報を攻撃者に送信させるフィッシングが成立する可能性がある。

## SSRF から IMDF

IMDS は Instance Metadata Service（インスタンスメタデータサービス）の略で、 EC2 インスタンス上（厳密にはホストハイパーバイザー側）で実行されるサービスであり、インスタンスの標準設定情報を照会できる。

```sh
# IMDSが設定されたEC2インスタンス内のディレクトリ情報リストを取得
curl http://169.254.169.254/latest/meta-data/

# インスタンスプロファイルのロール名
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# そのロールに関連付けられた実際の認証情報を取得
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME​​​
```

上記のようなリクエストを、SSRF で実行させることにより、EC2 の内部的な情報を取ることができる。
