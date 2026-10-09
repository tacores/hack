# IIS, Exchange攻撃の調査

https://tryhackme.com/room/detectingpublicfacingexploitation

## IIS

### IIS Webサーバーのアクセスログ

`C:\inetpub\logs\LogFiles\W3SVC1\u_ex<YYMMDD>.log`

管理者は IIS の失敗したリクエスト ログを有効にすることができる。

#### 指標

- POSTリクエストのサイズが際立って大きい
- GETリクエストの内容

### 詳細ログ

- IIS Windows Event log: `Applications and Services Logs → Microsoft → Windows → IIS-Logging → Logs`
- FailedReqLogFiles: `C:\inetpub\logs\FailedReqLogFiles\W3SVC1\<fr*.xml> and <freb.xsl>`

### イベント

- Security 4688: プロセス生成
- Sysmon 1: プロセス生成
- Sysmon 11: ファイル作成

#### 指標

- 親プロセスが `w3wp.exe` から、`cmd.exe` 等が実行されている
- `IIS APPPOOL\DefaultAppPool` がプロセスを実行している
- CommandLine の内容

## Exchange

下記のエンドポイントはどちらもIISアプリケーションのため、IIS調査も重要。

- Outlook Web App `/owa`
- Exchangeコントロールパネル `/ecp`

### HTTPプロキシログ

Autodiscover は、メールクライアントを自動的に構成する Exchange サービス。  
クライアントが認証する前にアクセスできるように設計されているため、攻撃対象領域が広い。

`C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Autodiscover\`

### イベント

`Applications and Services Logs → MSExchange Management`

- 1: コマンドレット実行成功
- 6: コマンドレット実行失敗

IISと同じく、プロセス生成とファイル作成。

### HTTPプロキシ OWAログ

`C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Owa\`
