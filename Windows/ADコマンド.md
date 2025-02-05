# AD コマンド

```ps
# ユーザーをグループに追加
Add-ADGroupMember "IT Support" -Members "Your.AD.Account.Username"

# 結果確認
Get-ADGroupMember -Identity "IT Support"

# パスワード変更
$Password = ConvertTo-SecureString "New.Password.For.User" -AsPlainText -Force
Set-ADAccountPassword -Identity "AD.Account.Username.Of.Target" -Reset -NewPassword $Password

# 強制的にアップデート（権限変更の反映が速くなるかもしれない）
gpupdate /force

# 利用可能な委任を列挙
Import-Module C:\Tools\PowerView.ps1
Get-NetUser -TrustedToAuth
```
