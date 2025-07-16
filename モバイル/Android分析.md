# Android分析

https://tryhackme.com/room/androidanalysis

## ファイルシステム

```
├── system/                  → Android OS system files (read-only in user mode)
│   ├── bin/                 → System binaries
│   ├── lib/                 → Shared libraries
│   └── framework/           → Java framework .jar files
│
├── data/                    → Main user data partition
│   ├── app/                 → Installed APKs
│   ├── data/                → App private data
│   ├── misc/                → Misc system info (e.g., WiFi configs)
│   ├── media/               → Encrypted storage mount point
│   └── system/              → User accounts, settings
│
├── sdcard/ (or /storage/emulated/0) → User files, photos, downloads
│
├── vendor/                 → OEM-specific binaries/libraries
│
└── dev/, proc/, sys/       → Kernel and device interfaces (like Linux)
```

## アーティファクト

### SMS/MMS、通話履歴

- `/data/data/com.android.providers.telephony/databases/mmssms.db`  (SMS/MMS)
- `/data/data/com.android.providers.contacts/databases/calllog.db`  (通話ログ)

### 連絡先、アドレス帳

- `/data/data/com.android.providers.contacts/databases/contacts2.db`

### ブラウザ履歴

- `/data/data/com.android.chrome/app_chrome/Default/History` (Chrome)

### 位置情報

場所
- `/data/data/com.google.android.gms/databases/`

ファイル
- location.db
- networklocations.db
- com.google.android.location

### 写真、動画、メタデータ

- `/sdcard/DCIM/`
- `/sdcard/Pictures/`
- `/sdcard/WhatsApp/Media/`

### インスタントメッセージ

- `/data/data/com.whatsapp/databases/msgstore.db`
- `/sdcard/WhatsApp/Media/` (画像、ボイスノートなど)

### アプリケーションデータ

- `/data/data/[app.package.name]/`

例：
- /data/data/com.instagram.android/
- /data/data/com.snapchat.android/

### ユーザーアカウント、Googleサービス

- `/data/system/users/0/accounts.db`
- `/data/data/com.google.android.gms/databases`

### インストールされているアプリケーション

- `/system/packages.xml`

## ツール

| ツール名                  | 種類 / 機能                   | 使用用途                                                                 |
|--------------------------|------------------------------|--------------------------------------------------------------------------|
| ALEAPP                   | アーティファクトパーサー     | 主要なAndroidアーティファクト（アプリデータ、位置情報、使用統計など）を抽出・解析する。         |
| Autopsy + Android Modules| GUIフォレンジックススイート   | プラグインを使って論理ダンプを調査し、通話履歴、メッセージ、アプリデータなどを解析。               |
| Cellebrite UFED          | 商用モバイルフォレンジックツール | Android（およびiOS）デバイスの物理、ファイルシステム、論理抽出を実行する。                         |
| Magnet AXIOM             | 商用スイート                 | Androidイメージを読み込み、タイムライン、チャット、メディアなどでアーティファクトを分類。         |
| Oxygen Forensic Detective| 商用オールインワンツール       | 削除データの回復、アプリの復号、通信・クラウドデータの解析を行う。                                |
| ADB (Android Debug Bridge)| コマンドラインインターフェース | Androidデバイスと通信し、ログ収集や手動ファイル抽出を行う（root権限が必要な場合あり）。           |
| TWRP Recovery            | カスタムリカバリインターフェース | カスタムリカバリモードにブートして、イメージ取得やデータアクセスを行う。                          |
| LiME (Linux Memory Extractor)| メモリダンプツール           | Androidデバイスの揮発性メモリ（RAM）をキャプチャし、ライブメモリフォレンジックに使用。           |
| Andriller               | デバイス解析 + ロック解除ツール| Androidバックアップからのデータ抽出、PINクラック、レポート生成などを行う。                        |
| ADB-Backup Extractors    | バックアップユーティリティ     | AndroidのADBバックアップ（.abファイル）をアクセス可能な.tarアーカイブに変換する。               |
| Protobuf Parsers         | データフォーマットパーサー     | Protobuf形式で保存されたAndroidの使用統計、アプリイベント、設定などを解析。                       |


## ALEAPP（Android Logs Events and Protobuf Parser）

https://github.com/abrignoni/ALEAPP

Androidデバイスからアーティファクトを抽出、解析、提示するために設計されたデジタルフォレンジックツール

```sh
python aleappGUI.py
```

1. 読み込む zip, tar, gz ファイルを指定
2. 出力ディレクトリを指定
3. Process

HTMLでレポートが出力される。
