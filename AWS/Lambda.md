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
