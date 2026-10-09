# Powershell実行の調査

https://tryhackme.com/room/investigatingpowershell

## イベントログ

### Windows Powershell

アプリケーションとサービスログの直下

#### 400: エンジンライフサイクルが開始されました

HostApplication にコマンドラインの全体が出る

#### 403: エンジンライフサイクルが停止しました

400との組み合わせでセッション時間の長さを把握できる

#### 600: プロバイダーライフサイクル

`ProviderName=WSMan` の場合、WinRMアクティビティが続いた可能性を示唆する

#### 500/501: コマンドの開始/停止

コマンドラインが出るが、-NoProfile を指定することで簡単にスキップできる

#### 800: パイプライン実行の詳細

表示される場合、UserIdにPowershellを実行したアカウントが記録される

### Powershell Operation

#### 4104: スクリプトブロックのログ記録

すべてのスクリプトブロックを記録するには、グループ ポリシー エディターで「PowerShell スクリプト ブロックのログ記録を有効にする」（コンピューターの構成 ▸ 管理用テンプレート ▸ Windows コンポーネント ▸ Windows PowerShell）を有効にする。

#### 4103: モジュールログ記録

パイプラインの詳細。すべてのコマンドレット、関数、ワークフロー呼び出しとそのパラメーターが記録される。

コンピューターの構成 ▸ 管理用テンプレート ▸ Windows コンポーネント ▸ Windows PowerShellに移動し、「モジュール ログを有効にする」を開いて「有効」に設定し、ログに記録するモジュール名をリストする (すべてキャプチャするには * を使用する)。

### Sysmon

#### 1: プロセス生成

### Windows Remote Management /Operational

#### 91: リモートシェルが作成されました

WinRM接続が確立され、リモートシェルが開かれたときにログに記録される。認証に使用されたアカウント、送信元IPが記録される。

#### 53504: リモート セッションが確認されました

### Microsoft-Windows-AppLocker

#### 8005: 

AppLockerがローカルのPowerShell（またはMSI）スクリプトの実行を、監査専用モードまたは強制モードのいずれでも許可した場合にログに記録される。

#### 8006:

強制ポリシーが適用されていればブロックされていたはずの実行が許可された。

## アーティファクト

### PSReadLine

`C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

タイムスタンプを取得するには、履歴ファイルへの各追加を、対応する USN Journal のDATA_EXTEND/DATA_ADDEDレコードと関連付ける。  
自動化ツール → [CHParser](https://github.com/TheresAFewConors/CHParser)

### Powershell トランスクリプト

グループ ポリシーを使用して有効にする。コンピューターの構成 ▸ 管理用テンプレート ▸ Windows コンポーネント ▸ Windows PowerShell ▸ PowerShell の文字起こしを有効にする。これを「有効」に設定し、ログを中央共有に保存する場合は出力ディレクトリを選択し、すべてのコマンドの前にタイムスタンプを追加する場合は「呼び出しヘッダーを含める」にチェックを入れる。

### その他

Prefetch、Amcache、AppCompatCache、BAMなど、プロセス実行を証明するアーティファクト全般。

## 予防と緩和

https://tryhackme.com/room/investigatingpowershell?taskNo=5&sharerId=674ed42e2374d1bc93db444c

