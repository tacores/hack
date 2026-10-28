# WMI永続性の検出

https://tryhackme.com/room/detectingwmipersistence

```
wmic, Get-WmiObject は新しいバージョンのWindowsでは削除され、Get-CimInstance が使われる。
```

```ps
# Windows ホストのオペレーティングシステム情報を取得
Get-CimInstance -ClassName Win32_OperatingSystem | Format-List *
```

## イベントサブスクリプション

WMIには、システム上で何らかの事象が発生した際にコードを自動的に実行できるイベント通知システムが組み込まれている。イベントフィルタ、イベントコンシューマー、フィルタとコンシューマーのバインディングという3つのオブジェクトで構成される。

### WMIリポジトリ

C:\Windows\System32\wbem\Repository\OBJECTS.DATA

デフォルトでは、イベントサブスクリプションにかかわるすべてのものは、`root\subscription` 名前空間に格納される。

### 注意すべきコンシューマーの種類

- CommandLineEventConsumer: 任意のコマンドまたはバイナリを実行。
- ActiveScriptEventConsumer: インラインで記述された、またはスクリプトファイルから読み込まれたVBScriptまたはJScriptスクリプトを実行。
- LogFileEventConsumer: 文字列をログファイルに書き込む。
- NTEventLogEventConsumer: Windows イベント ログにエントリを書き込む。
- SMTPEventConsumer: トリガーされるとメールを送信。

## イベントログ

| **ログソース** | **イベントID** | **検知対象・内容** |
| :--- | :--- | :--- |
| Sysmon | 19 | WMIイベントフィルターの作成 |
| Sysmon | 20 | WMIイベントコンシューマーの作成 |
| Sysmon | 21 | WMIフィルターとコンシューマーのバインディングの作成 |
| Microsoft-Windows-WMI-Activity/Operational | 5861 | 新しい永続的なイベントサブスクリプションの登録 |
| Sysmon | 1 | プロセス生成。親プロセスが `scrcons.exe` の場合、`ActiveScriptEventConsumer` を介したスクリプト実行の可能性がある。`scrcons.exe` 自体が VBScript または JScript を実行するため、スクリプトが起動しない限り `cscript.exe` や `wscript.exe` は表示されない点に注意する。 |

## アーティファクト

WMIリポジトリを解析するための専用ツールとして、[python-cim](https://github.com/mandiant/flare-wmi) や [WMI_Forensics](https://github.com/davidpany/WMI_Forensics) などが利用可能。ただしセットアップが複雑とのこと。

### 文字列ベースのトリアージ

```sh
.\strings.exe D:\Walkthrough\wbem\Repository\OBJECTS.DATA | Select-String -Pattern '__EventFilter|EventConsumer|__FilterToConsumerBinding'

.\strings.exe D:\Walkthrough\wbem\Repository\OBJECTS.DATA | Select-String -Pattern 'powershell|cmd'
```

### MOFファイル

MOF ファイルを使用すると、ユーティリティ（mofcomp.exe）を使用して WMI サブスクリプションをリポジトリにコンパイルできる。

`#pragma autorecover`ディレクティブが有効にされている場合、MOFファイルのコピーが `C:\Windows\System32\wbem\AutoRecover\` に保存されている可能性がある。  
またその場合、`HKLM\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs` レジストリにも元の.mofファイルの名前とパスが保存される。

## 予防と緩和

https://tryhackme.com/room/detectingwmipersistence?taskNo=7&sharerId=674ed42e2374d1bc93db444c
