# Azure

### Azure cloud shell

```shell
# 現在のユーザー情報
az ad signed-in-user show

# ユーザー表示
az ad user list
az ad user list --filter "startsWith('wvusr-', displayName)"

# グループ表示
az ad group list
az ad group member list --group "Secret Recovery Group"

# ユーザー変更
az account clear
az login -u EMAIL -p PASSWORD

# グループに付けられたロールを表示
az role assignment list --assignee <groupid> --all

# Key Vault
az keyvault list
az keyvault secret list --vault-name warevillesecrets

# シークレット
az keyvault secret show --vault-name warevillesecrets --name <secret-name>
```
