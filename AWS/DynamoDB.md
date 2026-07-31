# DynamoDB

```sh
pip install boto3
```

IDENTITY_POOL_ID を使って特定のテーブルを出力する。

```python
import boto3

# 1. 各種設定値の定義
IDENTITY_POOL_ID = 'us-east-1:836c0949-****************************'
REGION_NAME = 'us-east-1'
TABLE_NAME = 'Table-Name' # 読み取りたいテーブル名

# 2. Cognito Identity から一時的な認証情報を取得
cognito_client = boto3.client('cognito-identity', region_name=REGION_NAME)

# IDプールから一意のアイデンティティIDを取得
id_response = cognito_client.get_id(
    IdentityPoolId=IDENTITY_POOL_ID
)
identity_id = id_response['IdentityId']

# アイデンティティIDを使って一時的なAWS認証情報を取得
credentials_response = cognito_client.get_credentials_for_identity(
    IdentityId=identity_id
)
credentials = credentials_response['Credentials']

# 3. 取得した認証情報を使って DynamoDB クライアントを初期化
db_client = boto3.client(
    'dynamodb',
    region_name=REGION_NAME,
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretKey'],
    aws_session_token=credentials['SessionToken']
)

# 4. データの読み取りと出力 (テーブル全件スキャン)
try:
    response = db_client.scan(TableName=TABLE_NAME)
    items = response.get('Items', [])
    
    print(f"--- Table: {TABLE_NAME} のデータ一覧 ---")
    for item in items:
        print(item)
        
except Exception as e:
    print(f"エラーが発生しました: {e}")
```
