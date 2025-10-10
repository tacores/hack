# iOS 分析

https://tryhackme.com/room/iosanalysis

https://tryhackme.com/room/iosforensics

## iOSペアリング

### 信頼証明書 (Trust Certificates)

デバイスが信頼されていない場合、iPhoneはLightningケーブルを介した電力供給のみを許可し、データの読み書きは許可しない。  
信頼証明書は、iPhoneのハードウェアに保存されている秘密鍵を使用して、リモートデバイスとiPhoneの両方で証明書を生成する暗号交換の結果。

`C:\ProgramData\Apple\Lockdown` (Windows側)

`/private/var/db/lockdown` または `/private/var/Lockdown` (iOS側)

- 有効期限は30日間（ただし、 生成された証明書は、ユーザーが最後にiPhoneのロックを解除してから48時間のみ使用できる）
- デバイスの一意の識別子を含む
- iPhoneとiPhoneが同期されているデバイスの両方に保存される

### アクセスレベル

#### ロック状態とロック解除状態

| 保護項目             | 説明 |
|----------------------|------|
| ファイル暗号化       | iPhone上のすべてのファイルは保存時に暗号化されます。ファイル内のデータを読み取るには認証が必要です。 |
| ファイルのアクセシビリティ | `NSFileProtectionComplete` データ保護クラス以降のファイルにはアクセスできません。`NSFileProtectionNone` の状態では、マークの付いたファイルのみアクセスできます。 |
| ハードウェアアクセス   | デフォルトでは、マイク、カメラなどの「機密」ハードウェアコンポーネントへのアクセス、および新しいBluetoothペアリングは拒否されます。 |
| アプリケーションアクセス | バックグラウンドで実行されるアプリケーション機能（音楽、時間依存、マップなど）は、この状態にあるときにのみ実行できます。 |
| キーチェーンアクセス   | iOSキーチェーン（つまり、保存されたパスワード）には、デバイスが「ロック解除」状態になった後にのみアクセスできます。 |
| 信頼とペアリング       | 信頼証明書が存在しないデバイスにiPhoneを接続するには、ユーザーによる認証が必要です。 |
#### データ保護クラス

| Data Protection Class                        | 使用例                                                                 | 要求される状態                                                   |
|---------------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------|
| NSFileProtectionNone                         | キャッシュ                                                             | なし – 常にアクセス可能。                                        |
| NSFileProtectionCompleteUnlessOpen           | 音声や動画を再生するアプリ（ロック中でもメディアをストリーミング可能） | ファイルがアンロック状態で開かれている必要があるが、その後はロックされてもアクセス可能。 |
| NSFileProtectionCompleteUntilFirstUserAuthentication | バックグラウンドでのデータ読み書き（例：歩数カウント、通知など）       | 起動後に一度デバイスのロック解除が必要だが、その後はロック状態でもアクセス可能。     |
| NSFileProtectionComplete                     | 資格情報、メッセージ、ヘルスデータ                                     | デバイスのロック解除が必要。                                     |

## 証拠の保全

### iOSロックアウト

iOSは設定されたPINコード（または最近のiOSバージョンでは生体認証を使用したTouch IDまたはFace ID）を使用してデータを暗号化する。iPhoneがロック画面になっている間は、データは完全に暗号化される。

iPhone がロック解除された状態で提示された場合、デバイスが自動的にロックされるのを防ぐために、設定で「自動ロック」機能を無効にすることが不可欠。


### バックアップ

証拠保全と保護のために分析を行う前にiPhoneのバックアップを作成することが重要。  
iTunesやEaseUSなどのツールを使ってバックアップを取得できる。

iTunesの場合、デバイスをiTunesに接続し、デバイス管理ページで「今すぐバックアップ」を選択。

1. 暗号化:アカウントのパスワード、健康データなどのほか、写真、アプリ、メモ、音楽など、デバイス全体をバックアップ。
2. 暗号化なし:写真、アプリ、音楽などのみがバックアップ。

### 物理デバイス

﻿CellebriteのUFEDのような専用ハードウェアが、モバイルデバイスからデータを抽出するために用いられる。

### ファラデーバッグ (Faraday Bags)

特殊な素材と裏地を使用することで、Wi-Fiや電話信号などの電磁信号の通過を防ぐ。

## アーティファクト

var\mobile\Library の中に splite や plist ファイルが多く入っている

### 連絡先

SQlite
- `/HomeDomain/Library/AddressBook`

### 写真

ファイル
- `/CameraRollDomain/Media/DCIM`

### カレンダー

SQLite
- `/HomeDomain/Library/Calendar`

### Wi-Fi

plist
- `/SystemPreferencesDomain`

### ブラウザ (Safari)

SQLite
- `/HomeDomain/Library/Safari`

### ディレクトリ

ユーザーデータとアプリケーションストレージに関するデータ
- `/var/mobile`

パスワード、証明書、暗号化キー
- `/var/keychains`

システムログ、アプリケーションログ、デバッグログ、更新ログ
- `/var/logs`

SQLite データベース ファイルのほとんどがここに保存される
- `/var/db`

## 分析ツール

iFunbox のような書き込み可能なツールを使うと、法的証拠として認められなくなる可能性がある。

### libimobiledevice

```sh
# 確認
ideviceinfo

# 暗号化モードON
idevicebackup2 -i encryption on

# バックアップ作成
idevicebackup2 backup --full ./backup
```

バックアップを読むには ideviceunback などを使う。

### 3uTools

「バックアップ/復元」アイコンをクリック。  
バックアップが完了したら、3uToolsで確認できる。

