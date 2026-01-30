# Windows EventID

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/security-auditing-overview

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

4698 スケジュールタスクの作成

4657 レジストリ変更

4104 Scriptblock 作成 [（有効化が必要）](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5#enabling-script-block-logging)

1149 リモートデスクトップ認証成功

5001 MS Defender リアルタイム保護を無効化

2004 Firewall ルール追加

2006 Firewall ルール削除

4663 機密文書のアクセス

1102 Windows イベントログの削除

## SECURITY

| イベント ID | 説明         |     |
| ----------- | ------------ | ----- |
| 4624        | ログオン成功 |  タイプ 3, 10 がリモート   |
| 4625        | ログオン失敗 |   |
| 4634        | ログオフ |   |
| 5140        | SMB共有アクセス |   |

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)]]
      and
      *[EventData[Data[@Name='LogonType'] = '3' or Data[@Name='LogonType'] = '10']]
    </Select>
  </Query>
</QueryList>
```

| イベント ID        | 説明                                                |
| ------------------ | --------------------------------------------------- |
| 4720 / 4722 / 4738 | ユーザーアカウントが作成/有効化/変更されました      |
| 4725 / 4726        | ユーザーアカウントが無効化/削除されました           |
| 4723 / 4724        | ユーザーがパスワードを変更 / リセットしました       |
| 4732 / 4733        | ユーザーがセキュリティグループに追加/削除されました |
| 4740        | ログイン試行の繰り返し失敗によりユーザーアカウントがロックされました |

| イベント ID | 説明           | 備考             |
| ----------- | -------------- | ---------------- |
| 4688        | プロセスの作成 | デフォルトで無効 |

| イベント ID        | 説明                                                |
| ------------------ | --------------------------------------------------- |
| 4768 | Kerberos認証チケット( TGT ) が要求されました      |
| 4771       | Kerberos事前認証に失敗しました           |

| イベント ID | 説明         |  備考  |
| ----------- | ------------ |  ------------ |
| 4698        | スケジュールされたタスクが作成されました | 関連するschtasks.exeの起動にも注意  |
| 4702        | スケジュールされたタスクが更新されました |   |

| イベント ID | 説明         |  備考  |
| ----------- | ------------ |  ------------ |
| 4697 | システムにサービスがインストールされました (SECURITY) | 関連するsc.exeの起動にも注意  |
| 7045 | スケジュールされたタスクが作成されました(SYSTEM) |  |

## Sysmon

Sysmon は Sysinternals のツールで設定が必要

https://learn.microsoft.com/ja-jp/sysinternals/downloads/sysmon#events

| イベント ID | 説明                                        |
| ----------- | ------------------------------------------- |
| 1           | プロセスの作成                              |
| 7           | DLLのロード                       |
| 8           | リモートスレッドの作成                       |
| 11          | ファイル作成                                |
| 12 / 13     | レジストリキー作成・削除 / レジストリ値設定 |
| 3 / 22      | ネットワーク接続、DNS クエリ                |

ファイルハッシュは11では出ず、1か7には出る。11で出ないのはパフォーマンス的な理由が大きいと思われる。

## その他ログチャネル

### Powershell

- Event Viewer -> Applications and Services Logs -> Windows PowerShell (600)
- Event Viewer -> Apps and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational (4104)


### RDPログチャネル

Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> TerminalServices-LocalSessionManager -> Operational

ここには接続成功した場合のみ記録される。

| イベント ID | 説明                                        |
| ----------- | ------------------------------------------- |
| 21           | 接続                              |
| 24          | 切断                                |
| 25     | 再接続 |

### タスクスケジューラログチャネル

Event Viewer -> Apps and Services Logs -> Microsoft -> Windows -> TaskScheduler -> Operational

| イベント ID | 説明                                        |
| ----------- | ------------------------------------------- |
| 106           | 作成                              |
| 100          | 開始                                |
| 129     | プロセス作成 |

### Defender

Event Viewer -> Apps and Services Logs -> Microsoft -> Windows -> Windows Defender -> Operational

| イベント ID | 説明                                        |
| ----------- | ------------------------------------------- |
| 1116           | 脅威検出された                              |
| 1117          | 修復された                                |
| 5001     | 防護エンジンが無効化された |
| 5007 / 5013     | 設定変更 / 例外作成された |

その他の検出痕跡
```
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\
```

## メモ

```ps
Get-WinEvent -FilterHashTable @{LogName='Security';ID='4697'} | fl
```
