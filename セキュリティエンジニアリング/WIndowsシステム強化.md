# Windows システム強化

https://tryhackme.com/room/microsoftwindowshardening

ここに書いてあるのは、「必ず実施すべきこと」ではなく「考慮すべきこと」

## アイデンティティ管理

- ユーザー アカウント制御設定で通知レベルを「常に通知する」にする。
- パスワードポリシー、ロックアウトポリシーの設定

## ネットワーク管理

- ファイアウォール設定
- 使用されていないネットワークデバイス無効化
- SMB プロトコル無効化
- ローカル DNS 保護（hosts ファイルを攻撃者が変更できないよう）
- ARP 攻撃対策
- リモートデスクトップ制限

```ps
# SMB 無効化
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

## アプリケーション管理

- 信頼できるアプリケーションストア
- アプリと機能設定から、アプリインストールを MS ストアのみに制限可能
- AppLocker によるルール設定（ローカルグループポリシーエディターから）
- Microsoft Smart Screen によるブラウザの保護（Settings > Windows Security > App and Browser Control > Reputation-based Protection）
- MS Officd 攻撃サーフェスの縮小

https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

## ストレージ管理

- BitLocker による暗号化（Control Panel > System and Security > BitLocker Drive Encryption）
- Windows サンドボックス（Search for 'Windows Features' and turn it on > Select Sandbox > Click OK to restart）
- セキュアブート（デフォルトで ON になっている）
- バックアップ有効化（ファイル履歴という組み込み機能がある）

## Windows Update

- 自動更新有効化
