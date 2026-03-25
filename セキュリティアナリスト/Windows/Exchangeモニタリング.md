# Exchange モニタリング

https://tryhackme.com/room/exchangeonlinemonitoring

## サインイン

### サインインログ

```sh
index=* sourcetype="azure:aad:signin" appDisplayName="One Outlook Web"
| table _time userPrincipalName appDisplayName ipAddress location.city status.errorCode
| sort - _time
```

### 監査ログ

```sh
index=* sourcetype="o365:management:activity" Workload=Exchange
| table _time UserId Operation Workload
```

#### 重要な Operation

| 操作 (Operation)         | 説明                                   | なぜ重要か                                                                 |
|--------------------------|----------------------------------------|----------------------------------------------------------------------------|
| MailItemsAccessed        | メールボックス内のメールが閲覧された     | 攻撃者が侵入後に機密メールを閲覧したかどうかの特定に役立つ                 |
| Send                     | メールボックスからメールが送信された     | 侵害された内部アカウントからのフィッシングメール送信の検知に役立つ         |
| New-InboxRule            | 新しい受信トレイルールが作成された       | 攻撃者が返信の削除や外部転送ルールを作成し、活動を隠蔽するために使用する   |
| Set-InboxRule            | 既存の受信トレイルールが変更された       | 新規作成ではなく既存ルールを改変して検知を回避するケースの検出に有効       |
| Set-Mailbox              | メールボックス設定（転送など）が変更された | 攻撃者が外部アドレスへのサイレント転送を設定するために使用する             |
| Add-MailboxPermission    | 他ユーザーへのアクセス権が付与された     | 攻撃者が永続的アクセスを確保するために自分へ権限付与する典型的手法         |

### メッセージトレースログ

トレースログには、受信者が含まれる。

```sh
index=* sourcetype="o365:reporting:messagetrace"
| table Received SenderAddress RecipientAddress Subject Status FromIP
```

## ルールの悪用

攻撃者がよく使うルールは２つ。

1. 削除ルール。侵害されたアカウントから送信されたフィッシングメールへの返信を自動的に削除する。これにより被害者に気付かれないようにする。
2. 転送ルール。特定の条件に一致する受信メールを、自身が管理する外部アドレスに自動的に転送する。対象を絞ることで大量のメール送信による疑念を持たれないようにする。

### ルール作成の調査

```sh
index=* Workload=Exchange Operation=New-InboxRule 
| table _time UserId Name DeleteMessage ForwardTo SubjectContainsWords
```

`DeleteMessage = True` が正当に使われることは稀なので常に調査が必要。

### メールボックスレベルの転送

ルールレベルではなく、メールボックスレベルの設定。

```sh
index=* Workload=Exchange Operation=Set-Mailbox 
| table _time UserId ForwardingSmtpAddress DeliverToMailboxAndForward
```

`DeliverToMailboxAndForward = False` は、被害者がメールを見ることなく転送される設定なので特に疑わしい。

## フィッシング送信の検出

### アクセスされたメール

```sh
index=* Workload=Exchange Operation=MailItemsAccessed 
| table _time UserId ClientIPAddress OperationCount
```

不自然なIPアドレスや、多すぎる回数に注意。

### 送信されたメール

```sh
index=* Workload=Exchange Operation=Send 
| table _time UserId Item.Subject ClientIP SaveToSentItems
```

注意すべき点

- 短時間の大量送信
- `SaveToSentItems=False`
- 不自然なIPアドレス

### メッセージトレース

受信者が含まれる。

```sh
index=* sourcetype="o365:reporting:messagetrace" 
| table Received SenderAddress RecipientAddress Subject Status FromIP
```
