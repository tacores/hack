# Active Directory 強化

https://tryhackme.com/room/activedirectoryhardening

## 認証

### LM ハッシュを保存しない設定

Group Policy Management Editor > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > double click Network security - Do not store LM hash value on next password change policy > select "Define policy setting"

### SMB 署名を有効にする設定

Group Policy Management Editor > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > double click Microsoft network server: Digitally sign communication (always) > select Enable Digitally Sign Communications

### 署名された LDAP 要求のみを受け入れる設定

Group Policy Management Editor > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements > select Require signing from the dropdown

### パスワードローテーション

- 自動更新スクリプトを運用
- 多要素認証の使用
- グループ管理サービス アカウント (gMSA) を通じたローテーション

### パスワードポリシー

Group Policy Management Editor > Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy

## 最小権限モデル

### 階層型アクセスモデル (TAM)

- Tier 0: 最上位レベルで、すべての管理者アカウント、ドメイン コントローラー、およびグループ。
- Tier 1: ドメイン メンバー アプリケーションとサーバー。
- Tier 2: HR や営業スタッフ (IT 以外の担当者) などのエンドユーザー デバイス。

### アカウント監査

- 使用状況監査により、各アカウントの特定のタスクを監視し、アクセス権を検証。
- 権限監査により、システム内のすべてのアカウントに最小限の権限が付与されているかどうかを確認。
- 変更監査により、アカウント権限、パスワード、設定への不適切な変更を探す。これらに不適切な変更を加えると、データ漏洩につながる可能性がある。

## Microsoft Security Compliance Toolkit (MSCT)

https://www.microsoft.com/en-us/download/details.aspx?id=55319

### セキュリティベースラインのインストール

- Open Microsoft Security Compliance Website > click Download > click Windows Servers Security Baseline.zip > Download
- Open extracted folder > Scripts > & select desired baseline & execute with PowerShell

### ポリシーアナライザー

上記の Microsoft のページから PolicyAnalyzer.exe をダウンロード。
ローカルまたはドメイン レベルのポリシーを追加および管理できる。

## 既知の攻撃からの保護

### ケルベロースティング

- MFA
- Kerberos キー配布センター (KDC) サービスアカウントのパスワードを頻繁かつ定期的にリセット

### 推測しやすいパスワード

AD のパスワード監査をするツールでレポートを出力する

### リモートデスクトップブルートフォース

- 追加のセキュリティ制御なしで RDP をパブリック インターネットに公開しない
- スキャン攻撃やブルートフォース攻撃の試みを継続的に監査する

### パブリックアクセス可能共有

不要な共有を削除する

```ps
Get-SmbOpenFile
```
