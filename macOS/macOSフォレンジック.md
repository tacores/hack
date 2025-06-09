# macOS フォレンジック

https://tryhackme.com/room/macosforensicsapplications

## 構成

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

インストール履歴のプロセス名と種類

| Process Name                    | Description                           |
| ------------------------------- | ------------------------------------- |
| macOS installer                 | System/OS installer                   |
| softwareupdated                 | System or Security updates            |
| storedownloadd or appstoreagent | Installed using App Store             |
| installer                       | Installed using an external installer |

- `/private/var/db/receipts/<app-name>.plist` にインストーラプロセスの詳細が含まれる。
