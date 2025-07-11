# macOS フォレンジック(アプリケーション)

https://tryhackme.com/room/macosforensicsapplications

## macのエポック

`978307200` を足してUNIXエポックタイム変換できる。

## 共通アプリケーション情報

- `/Applications` ディレクトリが、Windows の`Program Files`に相当する。
- その中の `.app` はディレクトリ。

.app/Contents の内容

| ディレクトリ/ファイル名 | 説明                                                       |
| ----------------------- | ---------------------------------------------------------- |
| Info.plist              | アプリの設定情報を含む必須ファイル。                       |
| MacOS                   | アプリ本体の実行ファイルが入っている。                     |
| Resources               | 言語ファイルや画像など、アプリが使うリソースを格納。       |
| Frameworks              | アプリで使う共有ライブラリを格納。Windows の DLL に相当。  |
| Plugins                 | 機能拡張用のプラグインを格納。                             |
| SharedSupport           | テンプレートやクリップアートなど、補助的なリソースを格納。 |

- `/Library/Receipts/InstallHistory.plist` にはアプリケーションのインストール履歴が含まれる。

```sh
cat InstallHistory.plist 
```

インストール履歴のプロセス名と種類

| Process Name                    | Description                           |
| ------------------------------- | ------------------------------------- |
| macOS installer                 | System/OS installer                   |
| softwareupdated                 | System or Security updates            |
| storedownloadd or appstoreagent | Installed using App Store             |
| installer                       | Installed using an external installer |

- `/private/var/db/receipts/<app-name>.plist` にインストーラプロセスの詳細が含まれる。

```sh
plutil -p com.microsoft.package.Microsoft_Outlook.app.plist
```

```sh
cat /var/log/install.log | grep Installed
```

## 自動起動

### LaunchAgents と LaunchDaemons

- LaunchAgentsはログイン時に実行されるユーザーアプリケーション
- LaunchDaemonsは昇格された権限で実行されるシステムアプリケーション
- macOSはcronジョブもサポートしているが、ほとんど使用されない

場所
- `/System/Library`
- `/Library`
- `~/Library`

```sh
cd ~/Library/LaunchAgents
plutil -p net.tunnelblick.tunnelblick.LaunchAtLogin.plist 
```

### Saved Application State

ユーザーがアプリケーションを何らかの時点で使用した証拠とみなせる。

レガシーアプリケーション
`~/Library/Saved Application State/<application>.savedState`

サンドボックスアプリケーション
`~/Library/Containers/<application>/Data/Library/Application Support/<application>/Saved Application State/<application>.savedState`

```sh
cd ~/Library/Saved\ Application\ State 
```

## 通知と権限

### 通知

`/Users/<user>/Library/Group\ Containers/group.com.apple.usernoted/db2`

- APOLLO の notification_db モジュール
- hex2ascii変換してplistファイルとして保存する

### 権限

```
/Library/Application Support/com.apple.TCC/TCC.db

~/Library/Application Support/com.apple.TCC/TCC.db
```

- APOLLO の tcc_db モジュール
- SERVICE 列にアプリケーションが要求した権限が表示される

値の完全なリスト  
https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#all-services


## 連絡先、通話、メッセージ

### 連絡先

`~/Library/Application Support/AddressBook`  

- よく使われる連絡先アプリケーション
- Metadataディレクトリにはplist
- SourcesディレクトリにはDBファイル

`/private/var/db/CoreDuet/People/interactionC.db`  

- メール、メッセージ、電話などのアプリを使用した連絡先とのやり取りに関するデータが保存されている
- iCloud同期が有効になっている場合、他のデバイスからのやり取りも含まれる
- APOLLO の interaction_contact_interactions モジュール

### 通話

`~/Library/Application Support/CallHistoryDB/CallHistory.storedata`

- 電話とFaceTime通話の両方の情報を含むDB(拡張子がdbではないが、DBブラウザで開ける）
- iCloud同期が有効になっている場合、他のデバイスからのやり取りも含まれる
- APOLLO の call_history モジュール

### メッセージ

`~/Library/Messages/chat.db`

- SMSとiMessageの履歴
- 添付ファイルは` ~/Library/Messages/Attachments`
- iCloud同期が有効になっている場合、他のデバイスからのやり取りも含まれる
- APOLLO の sms_chat モジュール

## 生産性アプリ

### メール

`~/Library/Mail/V#/<UUID>/*.mbox` ディレクトリ

- それぞれ `Info.plist` ファイルが保存されている
```sh
plutil -p ~/Library/Mail/V#/<UUID>/All Mail.mbox/Info.plist 
```
- `Data` ディレクトリの中に `Messages`、`Attachments` ディレクトリが含まれる
- Messagesの中には、.emlx 形式のメールファイル

### カレンダー

`~/Library/Group\ Containers/group.com.apple.calendar/Calendar.sqlitedb`

- `CalendarItem` テーブルが有用

### Notes

`~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite`

- APOLLO モジュールは無い
- mac_apt.py を使える
```sh
python3 mac_apt.py -o <output path> -c DD <path to disk image> NOTES
```

- 添付ファイル  
`~/Library/Group\ Containers/group.com.apple.notes/Accounts/<UUID>/Media`

- サムネイル
`~/Library/Group\ Containers/group.com.apple.notes/Accounts/<UUID>/Previews`

### リマインダー

`~/Library/Group\ Containers/group.com.apple.reminders/Container_v1/Stores`

- `ZREMCDREMINDER` テーブルが有用

### オフィスアプリケーション

`~/Library/Containers/com.microsoft.<app>/Data`

- `~/Library/Containers/com.microsoft.<app>/Data/Library/Preferences` 中の plist に特に役立つ情報が含まれる
- `~/Library/Containers/com.microsoft.<app>/Data/Library/Application\ Support/Microsoft` には、Windowsに似て AppData, Temp ディレクトリが含まれる

## ブラウザ

### Safari

`~/Library/Safari`

- Downloads.plist
- UserNotificationPermissions.plist
- Bookmarks.plist
- History.db (APOLLO safari_history モジュール)

`~/Library/Containers/com.apple.Safari/Data/Library/Caches`

- TabSnapshots （セッション復元情報）
- WebKitCache (ブラウザキャッシュ)

### Chrome

`~/Library/Application\ Support/Google/Chrome/Default`

セッション復元情報  
~/Library/Application\ Support/Google/Chrome/Default/Sessions/

拡張機能  
~/Library/Application\ Support/Google/Chrome/Default/Extensions

## 写真、Apple Pay

### 写真

`~/Pictures/Photos Library.photoslibrary`

HEIC, JPG形式のオリジナル画像  
`original/`

全画像のメタデータ  
`database/Photos.sqlite`

### ウォレット、Apple Pay

`~/Library/Passes`

カードデータ  
`Cards/`

- 各カードは、パッケージ形式のディレクトリに`*.pkpass` ファイルとして保存されている

```sh
umair@Umairs-MacBook-Pro KvqnqUe+9bbxUHo0EePitn1AH5w=.pkpass % cat pass.json
```

完了した取引の詳細  
`passes23.sqlite`

- APOLLO に `passes23_*` というモジュールがいくつかある。新しいバージョンのmacOS場合、`PAYMENT_TRANSACTION.PASS_PID` を `PAYMENT_TRANSACTION.PASS_PID` に変える必要がある。
