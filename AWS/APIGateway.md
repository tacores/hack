# API Gateway

https://tryhackme.com/room/awsapigateway

## FireProx

https://github.com/ustayready/fireprox

FireProx は AWS API Gateway を活用し、リクエストごとに送信元 IP アドレスをローテーションさせるパススループロキシを作成する。FireProx を使えば、宛先サーバーを指すプロキシ URL を作成し、そのプロキシ URL に Web リクエストを送信することで、宛先サーバーからのレスポンスを受け取ることができる。

```sh
git clone https://github.com/ustayready/fireprox
cd fireprox
pip3 install -r requirements.txt
```

```sh
# help
python fire.py

usage: fire.py [-h] [--profile_name PROFILE_NAME] [--access_key ACCESS_KEY] [--secret_access_key SECRET_ACCESS_KEY] [--session_token SESSION_TOKEN] [--region REGION] [--command COMMAND] [--api_id API_ID] [--url URL]

FireProx API Gateway Manager

optional arguments:
  -h, --help            show this help message and exit
  --profile_name PROFILE_NAME
                        AWS Profile Name to store/retrieve credentials
  --access_key ACCESS_KEY
                        AWS Access Key
  --secret_access_key SECRET_ACCESS_KEY
                        AWS Secret Access Key
  --session_token SESSION_TOKEN
                        AWS Session Token
  --region REGION       AWS Region
  --command COMMAND     Commands: list, create, delete, update
  --api_id API_ID       API ID
  --url URL             URL end-point
```

```sh
# 作成
python fire.py --command create --url https://api.bestcloudcompany.org

Creating => https://api.bestcloudcompany.org...
[2025-05-13 05:49:33+00:00] (mkfb5u9h0j) fireprox_bestcloudcompany => https://mkfb5u9h0j.execute-api.us-east-1.amazonaws.com/fireprox/ (https://api.bestcloudcompany.org)
```

```sh
# リスト
python fire.py --command list

# 削除
python fire.py --command delete --api_id mkfb5u9h0j
```

## Lambda authorizers

https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html

API Gateway の Lambda オーソライザーは、 API リクエストの認可を行う関数。API Gateway がフロントエンドとする特定のリソースへのアクセスを制御し、認可されたユーザーのみがこれらのリソースにアクセスできるようにする。

Lambda オーソライザーは、インフラストラクチャの管理やカスタム認可コードの記述をすることなく、複雑な認可ロジックを実行できるため便利。これにより、API のアクセス制御の管理が容易になり、リソースを大量に消費する認可タスクを Lambda にオフロードできるようになる。

### 注意点

#### 貪欲な拡大

URL パスのマッチングでワイルドカードを使用する場合、注意して使用しないと予期しない一致につながる可能性がある。例えば、貪欲な \* を含む正規表現パターンは、意図したよりも多くの文字に一致し、複数の URL パスの一部に一致する可能性がある。

例：次のようなオーソライザー実装があったとする。

```python
root@ip-10-10-89-159:~#
    if event['authorizationToken'] == 'testing123':
        auth = 'Allow'
        authResponse = {"principalId": "testing123", "policyDocument": {"Version": "2012-10-17", "Statement": [
            {"Action": "execute-api:Invoke",
             "Resource": "arn:aws:execute-api:us-east-1:{ACCOUNT_ID}:*/*/test/*",
             "Effect": auth}]}}
        return authResponse
    elif event['authorizationToken'] == ‘{PROD_AUTH_TOKEN}’:
        auth = 'Allow'
        authResponse = {"principalId": "testing123", "policyDocument": {"Version": "2012-10-17", "Statement": [
            {"Action": "execute-api:Invoke",
             "Resource": "arn:aws:execute-api:us-east-1:{ACCOUNT_ID}:*/*/prod/*",
             "Effect": auth}]}}
        return authResponse
```

```
https://api.bestcloudcompany.org/test/test/
https://api.bestcloudcompany.org/test/admin/
```

で許可されるのは意図したとおりだが、

```
https://api.bestcloudcompany.org/prod/test/
```

も許可されてしまう。
