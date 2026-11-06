# LSAダンプの検出

https://tryhackme.com/room/detectinglsasecretsdumping

## 基礎

LSAは、ローカルセキュリティポリシーの適用、認証の処理、およびオペレーティングシステムが必要とする暗号化された秘密情報の保管庫の管理を担当するWindowsのサブシステム。

`HKLM\SECURITY\Policy\Secrets` に格納され、BookKeyで暗号化されている。SECURITYハイブへのアクセスはSYSTEMアカウントに制限されている。

### 格納されているもの

| **キー** | **コンテンツ** |
| :--- | :--- |
| DPAPI_SYSTEM | マシンのDPAPIルートキー |
| NL$KM | キャッシュされたドメインログオン資格情報の復号に使用 |
| `_SC_<ServiceName>` | 特定のアカウントで実行されるサービスの資格情報 |
| $MACHINE.ACC | コンピューターのドメインアカウントのパスワード |

DPAPI_SYSTEM は、SYSTEM シークレットを暗号化するために使用されるマシン ルートキーで、DPAPIとは別。DPAPIは、アプリケーションが自身のデータ（保存されたブラウザのパスワードなど）を保護するために使用する暗号化サービスであり、その鍵はSECURITYハイブではなく、ユーザープロファイルに保存される。

### ダンプ

#### サードパーティツール

```sh
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::secrets
```

```sh
C:\Windows\Tasks>py secretsdump.py DFIRUser@10.144.135.97
```

```sh
C:\Windows\Tasks>nxc smb 10.144.135.97 -u DFIRUser -p "Secure!" --lsa
```

#### LOLBins

SeBackupPrivilege が必要。

```ps
reg save HKLM\SECURITY security
reg save HKLM\SYSTEM system
```

ダウンロードしてオフラインでMimikatzかsecretsdump.pyを使って復号する想定。

### API

- reg コマンドは、Win32 RegSaveKeyExW を呼び出す
-  Secretsdump.py や古い nxc は、RPC の BaseRegSaveKey を呼び出す

## イベントログ

### Sysmon 10: あるプロセスが別のプロセスのハンドルを開いた

`GrantedAccess = 0x40 (PROCESS_DUP_HANDLE)`

SYSTEM に属する lsass.exe のトークン ハンドルを複製するために使用する特定のアクセス権限

### Sysmon 1, Security 4688: プロセス作成

HKLM\SECURITY、SYSTEM、または SAM を含むコマンドライン

### Sysmon 11: ファイル作成

ハイブのファイル書き込み

### リモートレジストリアクティビティ

secretsdump.py, nxc

- System 7036: リモートレジストリサービスが実行状態に移行
- Security 4624、ログオンタイプ3 (SMB認証)
- Security 5140（デフォルトでは無効）：ネットワーク共有へのアクセス。

## アーティファクト

- Prefetchなどのプロセス実行アーティファクト
- C:\Windows\Temp\xxxxxx.tmp の作成、削除履歴（USNジャーナル）

## 耐性強化

https://tryhackme.com/room/detectinglsasecretsdumping?taskNo=5&sharerId=674ed42e2374d1bc93db444c
