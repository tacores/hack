# macOS フォレンジック

https://tryhackme.com/room/macosforensicsbasics

https://tryhackme.com/room/macosforensicsartefacts

## ファイルシステム

### HFS+

- 32bitアドレス
- セクターは通常512バイト
- アロケーションブロックは１つ以上のセクターで構成される
- ブートボリュームはセクター0,1
- セクター2はボリュームヘッダーが含まれる
- ファイル名はUTF-16で、最大255文字

ファイル権限がない、2040年までの日付しかサポートしない、複数のプロセスが同時にファイルシステムにアクセスできない、タイムスタンプの解像度が秒単位、スナップショット機能がないなどの様々な問題があって時代遅れだった。

### APFS

- 2017年に登場
- パーティションテーブルはGPT
- パーティション内に１つ以上のコンテナ
- コンテナ内に複数のボリュームがあり、コンテナ内の空き領域は全ボリュームで共有される

```sh
# ディスクを管理
diskutil

# APFS イメージのオプションを一覧表示
diskutil apfs

# APFS ボリュームを確認
diskutil apfs list
```

## ドメイン

Local, System, User, Network の４つのドメインがある。ファイルの用途に応じて異なるドメインに分類する。

### Localドメイン

ローカルコンピューターの全ユーザーに共通するリソース。/Applications, /Library

### Systemドメイン

Appleが開発・管理するソフトウェアが含まれる。/System  
rootユーザーでも、このドメイン内のファイルを変更・削除できない。

### Userドメイン

ユーザーのデータとファイル。/Users

### Networkドメイン

ネットワークプリンター、SMB共有サーバー、その他のコンピューターなどのネットワークリソース

## ファイル

### .plist

Windowsのレジストリファイルに相当。  
XMLとBLOB形式があり、BLOB形式の読み取りにはplutilやXcodeが必要。

```sh
# mac
plutil -p <file>.plist
```

Linuxで分析する場合は、[plistutil](https://github.com/libimobiledevice/libplist)をインストール。

```sh
# linux
plistutil -p APMExperimentSuiteName.plist 
```

### .app

実行ファイル。

### .dmg

macOSのディスクイメージ。インストーラとしてもよく使われる。

### .kext

Windowsのドライバーに相当。最近のバージョンでは非推奨。

### .dylib

動的ロードされるライブラリ。DLLに相当。

### .xar

アーカイブファイルでインストーラーやブラウザ拡張でよく使われる。以前の.pkgに代わるもの。

### DBファイル

[APOLLO](https://github.com/mac4n6/APOLLO)で抽出。

```sh
umair@Umairs-MacBook-Pro ~ % python3 apollo.py extract -osql_json -pyolo -vyolo modules tmp_apollo
```

moduleのtxtファイルを開いてSQLをコピーし、DBブラウザ上で実行することもできる。

### ログ

#### Apple システムログ (ASL)

`/private/var/log/asl/`  
utmp、wtmp、ログイン情報など

```
open -a Console /private/var/log/asl/<log>.asl
```

[mac_apt](https://github.com/ydkhatri/mac_apt) で分析

```sh
python3 mac_apt.py -h  
```

#### システムログ

`/private/var/log/system.log`

#### 統合ログ

`/private/var/db/diagnostics/*.tracev3`  
`/private/var/db/uuidtext`


mac_apt や [Mandinantの統合ログパーサーユーティリティ](https://github.com/mandiant/macos-UnifiedLogs)で分析

```sh
./unifiedlog_parser -h
```

```sh
# mac
log show --last 1m

log show --predicate 'subsystem=="com.apple.sharing" and category=="AirDrop" and eventMessage contains "Discoverable"'
```


## フォレンジックを困難にする要因

- SSDドライブがマザーボードにはんだ付けされている
- ハードウェアレベルで暗号化されている
- FileFault暗号化されている。キーを得るためにユーザーパスワードが必要
- ライブイメージ取得するには、アプリケーションにフルディスクアクセスを許可する必要がある `Settings > Privacy & Security > Full Disk Access`
- イメージを取得する前にシステム整合性保護（SIP）を無効にする必要があるが、無効にするためにはリカバリモードで起動する必要があり、揮発性データが失われる。`csrutil disable`

逆に言うと、下記でイメージ取得可能

- Magnet AXIOM や Cellebrite などの専用ツールを使用して、フルディスク アクセスを許可し、ライブ システムをイメージ化する
- ユーザーパスワードが分かっており、マシンが物理的に利用可能な場合は、リカバリモードで起動し、セキュリティ機能を無効にして、dd、hdiutil、dc3ddなどのツールを使用してターミナルからディスクイメージを取得する
- （古いシステムの場合）リカバリモードで起動し、ユーザーパスワードを使用してドライブのロックを解除し、MacをMac共有モードまたはターゲットモードに切り替える

## APFSディスクイメージのマウント

[apfs-fuse](https://github.com/sgan81/apfs-fuse) をインストール

```sh
# APFSコンテナ情報の確認
$ apfsutil mac-disk.img 

$ sudo su
# apfs-fuse mac-disk.img mac/

# ls mac/root
Applications  System  Volumes  cores  etc  private  tmp  var
Library       Users   bin      dev    opt  sbin     usr

# ボリュームを指定してマウント
# apfs-fuse -v 4 mac-disk.img mac
```

## システム情報

### OSバージョン

```
cat /System/Library/CoreServices/SystemVersion.plist
```

### macシリアルナンバー

```
/private/var/folders/*/<DARWIN_USER_DIR>/C/locationd/consolidated.db

/private/var/folders/*/<DARWIN_USER_DIR>/C/locationd/cache_encryptedA.db
```

### OSインストール日

```
stat /private/var/db/.AppleSetupDone

cat /private/var/db/softwareupdate/journal.plist
```

### タイムゾーン

```sh
ls -la /etc/localtime

plutil -p /Library/Preferences/.GlobalPreferences.plist

# 位置情報サービスが有効か
plutil -p /Library/Preferences/com.apple.timezone.auto.plist
```

### 起動、再起動、シャットダウン時間

```sh
zgrep BOOT_TIME system.log.* 

zgrep SHUTDOWN_TIME system.log.* 

# 統合ログのキーワード：loginwindow
log show --info --predicate 'eventMessage contains "com.apple.system.loginwindow" and eventMessage contains "SessionAgentNotificationCenter"' 
```

## ネットワーク情報

### ネットワークインターフェイス

```
cat /Library/Preferences/SystemConfiguration/NetworkInterfaces.plist
```

### DHCP

```
sudo cat /private/var/db/dhcpclient/leases/en0.plist
```

### ワイヤレス接続

```
sudo plutil -p /Library/Preferences/com.apple.wifi.known-networks.plist 
```

### ネットワーク使用状況

```
log show --info --predicate 'senderImagePath contains "IPConfiguration" and (eventMessage contains "SSID" or eventMessage contains "Lease" or eventMessage contains "network changed")'

./unifiedlog_parser -i system_logs.logarchive -o logs/output1.csv
```

## アカウントアクティビティ

### ユーザーアカウントとパスワード

```
sudo cat /private/var/db/dslocal/nodes/Default/users/john.plist
```

### 最後にログインしたユーザー履歴

```
plutil -p /Library/Preferences/com.apple.loginwindow.plist
```

### SSH接続

```
cat .ssh/known_hosts
```

### sudoアカウント

```
sudo cat /etc/sudoers
```

### ログイン、ログアウトイベントログ

```
zgrep login system.log*

grep USER_PROCESS asl_ver2.csv
```

### 画面ロック、ロック解除

```sh
grep com.apple.sessionagent.screenIsLocked output.csv 

# com.apple.sessionagent.screenisUnlocked
```

## 実行の証拠

### 端末履歴

```sh
tail /Users/<user>/.zsh_history

# 各ターミナルセッションの履歴
tail /Users/<user>/.zsh_sessions/<GUID>
```

※履歴ファイルはログアウト/セッション終了でファイル保存される。ログアウト前に履歴を確認するには、historyコマンド。

```sh
history
```

### アプリケーションの使用状況

```sh
# ユーザー
/Users/<user>/Library/Application\ Support/Knowledge/knowledgeC.db

# システム
/private/var/db/CoreDuet/Knowledge/knowledgeC.db

/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL
```

dbファイルはそのままDBブラウザで開ける。

## ファイルシステムアクティビティ

### ファイルシステムイベントストアDB

NTFSのUSNジャーナルのように、すべてのファイルシステムの変更を記録する。

```
python3 mac_apt.py -o . -c DMG ~/mac-disk.img FSEVENTS
```

### DSストア

Finderアプリでフォルダにアクセスしたら、「.DS_Store」ファイルが作成される。

[ファイル詳細](https://wiki.mozilla.org/DS_Store_File_Format)  
[.DS_Store-parser](https://github.com/hanwenzhu/.DS_Store-parser)ユーティリティ

```
python3 parse.py ../.DS_Store 
```

### 最近使用したフォルダ

項目0が最新

```sh
plistutil -p /Users/<user>/Library/Preferences/com.apple.finder.plist

# Microsoft アプリケーション
/Users/<user>/Library/Containers/com.microsoft.<app>/Data/Library/Preferences/com.microsoft.<app>.securebookmarks.plist
```

## 接続されたデバイス

### マウントされたボリューム

```sh
plist-util -p /Users/<user>/Library/Preferences/com.apple.finder.plist
```

### 接続されたiデバイス

```sh
plist-util -p /Users/<user/Library/Preferences/com.apple.iPod.plist
```

### Bluetooth接続

```
/Users/<user>/Library/Application\ Support/Knowledge/knowledgeC.db
```

knowledge_audio_bluetooth_connected モジュールのクエリを使える。

### プリンター

```sh
plist-util -p /Users/<user>/Library/Preferences/org.cups.PrintingPrefs.plist
```
