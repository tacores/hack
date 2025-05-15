# IAM 列挙

https://tryhackme.com/room/awsiamenumeration

## 基本

### Boto3 が認証情報を検索する順序

https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html

1. boto3.client()メソッド内でパラメータとして資格情報を渡す
1. Session オブジェクトを作成するときに資格情報をパラメータとして渡す
1. 環境変数
1. ロールプロバイダーを引き受ける
1. Web ID プロバイダーの役割を引き受ける
1. AWS IAM アイデンティティセンター認証情報プロバイダー
1. 共有資格情報ファイル ( ~/.aws/credentials)
1. AWS 設定ファイル ( ~/.aws/config)
1. Boto2 設定ファイル (/etc/boto.cfg および~/.boto)
1. コンテナ資格情報プロバイダー
1. IAM ロールが設定されている Amazon EC2 インスタンス上のインスタンス メタデータ サービス。

#### 注目すべき箇所

- 環境変数 -ユーザーは、環境変数として AWS_ACCESS_KEY_ID と AWS_SECRET_ACCESS_KEY を使用して認証情報を設定できます。
- 共有認証情報ファイル(~/. aws /credentials) -これは、ロールを引き受けるための IAM ユーザー アクセス キーまたは SSO 構成を保存する場合に最も一般的な場所です。
- AWS Config ファイル (~/. aws /config) -ヘルパー スクリプトやその他の外部認証情報プロバイダーを参照する認証情報ソースは、通常ここで参照されます。
- ロールプロバイダーを引き受ける- ここでの秘訣は、誰かが AWS SSO または別のメカニズムを使用して AWS CLI 経由でロールを引き受けると、AWS CLI ツールが各ロールセッションの認証情報を ~/. aws / cli /cache/{role_session_id} にキャッシュすることを知ることです。
- Boto2 構成ファイル- Boto2 は Boto3 の前身バージョンであり、従来のクライアントで使用される可能性があります。
- インスタンスメタデータサービス (IMDS) - IAM ロールが設定されている Amazon EC2 インスタンス上。

## アクセスキー情報

```sh
# アクセスキーが属するAWSアカウントを取得する（認証なしで実行可）
aws sts get-access-key-info --access-key-id {access_key_id}
```

## リソースポリシーを介した IAM プリンシパル列挙

AWS リソースベースポリシーとは、特定の種類の AWS リソースに直接適用される IAM ポリシー。

1. リソースベースポリシーをサポートするリソースを作成し、そのリソースを更新して、存在するかどうかをテストするプリンシパルのアクセスを許可する。
1. プリンシパルが存在しない場合、更新コマンドはエラーメッセージを返す。
1. プリンシパルが存在する場合は、エラーメッセージは表示されず、更新されたリソースポリシーが実装される。
1. ほとんどの種類のリソースベースポリシーでは、アカウント ID、IAM ロール、IAM ユーザーで構成される。他の種類のプリンシパルは、この方法では列挙できない。

## IAM ユーザーとロールの列挙

### QuietRiot

https://github.com/righteousgambit/quiet-riot

- Quiet Riot は、 AWS / Azure Active Directory / Google Workspace のユーザー/プリンシパルを「認証なし」で列挙できる。
- スキャン対象に対して認証を受ける必要はないが、Quiet Riot が動作するには、スキャンで使用するリソースを展開する権限を持つアカウントに対して認証を受ける必要がある。

```sh
pip3 install quiet-riot
# apt-get install python3-jmespath

quiet-riot --help
```

名前リストを作成するスクリプトの例

```python
#!/usr/bin/env python
malenames = ['adam', 'john']
with open('familynames-usa-top1000.txt', 'r') as f:
    lastnames = f.read().splitlines()
with open('test.txt', 'w') as f:
    for i in malenames:
        for j in lastnames:
            first = i.lower()
            last = j.lower()
            f.write(f"{first}.{last}\n")
            f.write(f"{first[0]}{last}\n")
            f.write(f"{first}\n")
            f.write(f"{first}_{last}\n")
            f.write(f"{first}{last}\n")
            f.write(f"{first}{j[0].lower()}\n")
```

```
1. AWS Account IDs
2. Microsoft 365 Domains
3. AWS Services Footprinting
4. AWS Root User E-mail Address
5. AWS IAM Principals
    4.1. IAM Roles
    4.2. IAM Users
6. Microsoft 365 Users (e-mails)
7. Google Workspace Users (e-mails)
```

```sh
# 5はAWS。後はインタラクティブに入力
# アカウントIDとブルートフォースリストを与える
quiet_riot --scan 5
```

## ルートユーザーメールアドレス

- 基本的には、リソースベースのポリシーでは IAM ユーザー、IAM ロール、AWS アカウント ID しか返せない。
- しかし１つ例外があり、レガシー AWS S3 ACL（アクセスコントロールリスト）（現在はデフォルトで非推奨）を使用する場合、ACL ポリシーを使用して、潜在的なルートユーザーのメールアドレスに対応するメールアドレスを返せる可能性がある。

```sh
quiet_riot --s 4

E-mail Format (First and Last Names):
a. [first]@[domain]
b. [first][last]@[domain]
c. [first].[last]@[domain]
d. [last]@[domain]
e. [first]_[last]@[domain]
f. [first_initial][last]@[domain]
g. custom username list
h. input single e-mail address
```

## 有効化サービスのフットプリント

```sh
# アカウントIDを入力する
quiet_riot --s 3
```
