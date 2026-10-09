# AD認証攻撃の検出

https://tryhackme.com/room/detectingadcredentialattacks

## Kerberoasting

ケルベロスサービスチケット要求イベント。  
デフォルトの暗号方式は AES-256 (0x12)だが、多くのケルベロースティングツールはRC4(0x17)にダウングレードするため強力な指標になる。

```sh
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

統計

```sh
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```

ただし、AES-256を使用して検出を回避するツールもあるので万能ではない。 
https://github.com/trustedsec/orpheus

5分間のうちに異なる6以上のサービスアカウントに対してチケットを要求したアカウントを表示

```sh
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
```

## AS-REP

Kerberoastingと同様、暗号化タイプがRC4(0x17)に注目。

```sh
index=* EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

TGTリクエストの後、同じソースからこのアカウントのログオンイベント（4624）またはTGSリクエスト（4769）が**生成されていれば**、正当な使用である可能性がある。

```sh
index=* (EventCode=4624 OR EventCode=4769)
| search Account_Name="{ACCOUNT_NAME}"
| table _time, EventCode, Account_Name, Client_Address
```

## LSASSダンプ

Sysmonイベント10 (ProcessAccess) は、あるプロセスが別のプロセスへのハンドルを開いたときに発生する。  
sysmon設定で、lsass.exeを明示的にターゲット指定する必要がある。

### GrantedAccessフィールド

| アクセス権 | 16進数値 | 用途 |
|-----------|----------|------|
| PROCESS_QUERY_LIMITED_INFORMATION | 0x1000 | 基本的なプロセス情報の取得 |
| PROCESS_QUERY_INFORMATION | 0x0400 | 詳細なプロセス情報の取得 |
| PROCESS_VM_READ | 0x0010 | プロセスメモリの読み取り |
| PROCESS_ALL_ACCESS | 0x1FFFFF | プロセスへの完全なアクセス |

### 正当なプロセスによるハンドル

| フルプロセスパス | 典型的な GrantedAccess | 理由 |
|------------------|------------------------|------|
| C:\Windows\System32\csrss.exe | 0x1000 または 0x1400 | Windows サブシステムで、プロセス管理を担当 |
| C:\Windows\System32\WerFault.exe | 0x1000 | Windows エラー報告のクラッシュハンドラ |
| C:\Windows\System32\svchost.exe | 0x1010 | 各種サービス機能（このアクセスレベルでは通常の挙動） |
| AV/EDR エージェントのパス | 様々 | セキュリティ製品が LSASS を監視・保護するため |

### 検出

lsass.exe をハンドルした全てのプロセスを列挙

```sh
index=* EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

疑わしいプロセスに絞って詳細を表示

```sh
index=* EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```

## DCSync

DCSync 検出のイベント 4662 (オブジェクトに対して操作が実行された)では、事前に 2 つの設定が必要。

1. グループ ポリシーで「ディレクトリ サービス アクセスの監査」を有効にする。
2. ドメイン パーティションに SACL (システム アクセス コントロール リスト) を設定して、レプリケーション操作を監査する。

どちらもデフォルトでは有効になっていない。これら 2 つが設定されていない場合、DCSync はログに全く表示されない。

### 検出

GUID 1131f6ad(DS-Replication-Get-Changes-All) は、パスワードデータを取得することを可能にする権限。  
攻撃者がマシンアカウントを使う可能性もあることには注意が必要。

```sh
index=* EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

ログオンIDを取得

```sh
index=* EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
| table _time, host, user, Logon_ID
```

ログオンIDから送信元IPを特定

```sh
index=* EventCode=4624 Logon_ID={LOGON_ID}
| table _time, host, user, Source_Network_Address, Logon_Type
```

## NTDS.dit 抽出

### 2つの抽出方法

ボリュームシャドウコピーを使う方法

```ps
C:\Windows\System32> vssadmin create shadow /for=C:
C:\Windows\System32> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
C:\Windows\System32> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
C:\Windows\System32> vssadmin delete shadows /shadow={shadow-id} /quiet
```

Install From Media / ntdsutilを使う方法（ドメイン コントローラーの昇格用に設計された正規の AD 管理ツール）

```ps
C:\Windows\System32> ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q
```

### 検出

#### ntdsutil

```sh
index=* EventCode=1 Image="*\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

```sh
index=* EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

#### shadow copy

```sh
index=* EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
  | table _time, host, User, ParentImage, Image, CommandLine
```

```sh
index=* EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```
