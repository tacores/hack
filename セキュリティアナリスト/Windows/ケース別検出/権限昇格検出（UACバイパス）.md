# 権限昇格検出（UACバイパス）

https://tryhackme.com/room/detectinguacbypass

## 基礎

### 整合性レベル

| **Integrity Level** | **Typical Principal**                | **What Runs Here**                         |
| :------------------ | :----------------------------------- | :----------------------------------------- |
| System              | `SYSTEM` および OS の中核サービス    | カーネルに近いサービス、`lsass.exe`         |
| High                | 昇格された管理者                    | 「管理者として実行」されたプログラム       |
| Medium              | 標準ユーザーおよび昇格されていない管理者 | 通常のユーザーアプリ、`explorer.exe`       |
| Low                 | サンドボックス化されたプロセス      | ブラウザーのタブ、保護モードのアプリ       |

### 自動昇格（Auto-Elevation）

自動昇格とは、特定の信頼されたWindowsバイナリが、通常のUAC（ユーザーアカウント制御）プロンプトを表示することなく、高い整合性レベル（High integrity privileges）の権限で自動的に実行される仕組み。

- バイナリが、信頼されたディレクトリ（System32など）に配置されていること。
- Windows発行元の証明書で適切に署名されていること。
- バイナリに埋め込まれたマニフェスト内で「autoElevate」が「true」に設定されていること。これにより、「アプリケーション情報サービス（appinfo）」が、ユーザーへの通知なしに当該プログラムの権限を昇格させる。

#### 本来の目的

Windowsに組み込まれたツールやコントロールパネルのアプレット（fodhelper.exe、ComputerDefaults.exe、sdclt.exeなど）において、ユーザーの利便性を高めるために利用されている。  
攻撃者はこれを利用し、その後に起動するプロセスに昇格後の権限を継承させることが可能。

#### 前提

実行するユーザーがローカル管理者権限を持っていること。

### レジストリハイジャック

| **Binary**             | **Hijacked Class Key**           | **Spawns Via** | 
| :--------------------- | :------------------------------- | :------------- | 
| `fodhelper.exe`        | `ms-settings\Shell\Open\command` | 直接           | 
| `ComputerDefaults.exe` | `ms-settings\Shell\Open\command` | 直接           | 
| `sdclt.exe`            | `Folder\shell\open\command`      | `control.exe`  | 

```ps
# Plant the hijack under the per-user Classes hive (Medium integrity can write here)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /d "C:\Users\Public\payload.exe" /f

reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f

# Trigger the auto-elevating binary, which reads the key and runs the payload at High
start fodhelper.exe
```

手法を網羅したカタログ [UACME](https://github.com/hfiref0x/UACME)


```
(NTUSER.DAT) HKCU\Environment\windir
を
C:\Users\Public に設定し、
C:\Users\Public\system32 に配置した exe をスケジュール実行させるような方法もある。
```

## イベントログ

### Sysmon 1 プロセス作成

- fodhelper.exe, ComputerDefaults.exe, control.exe 等が親プロセス
- folhelper.exe 等が起動されるときに整合性レベルが上がっている
- UACダイアログが表示された場合、consent.exe のプロセスが生成される
- SACLで監査が有効になっている場合、Security 4688 も参照できる

### Sysmon 13: レジストリのハイジャック書き込み

```
ms-settings\Shell\Open\command
Folder\shell\open\command
```

- 共通検索キーワード: `shell\open\command`
- DelegateExecute が Empty。（それ以外のバリエーションもあるので、Emptyでないことがクリーンな証拠にはならない）
- イベント12は、キーと値の削除を記録する
- SACLで監査が有効になっている場合、Security 4657 (レジストリ値が変更された) も参照できる

## アーティファクト

### ハイブ

UsrClass.dat。**NTUSER.DAT ではない。**

```
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

```sh
# recover で削除されたキーも表示できる可能性がある。
RECmd.exe -f "E:\Artifacts\Walkthrough\UsrClass.dat-recoverable" --sd "report.exe" --recover true
```

### MFTのペイロード痕跡

```sh
MFTECmd.exe -f 'E:\Artifacts\Walkthrough\uploads\ntfs\$MFT' --csv "$env:USERPROFILE\Desktop\uac-out" --csvf mft.csv
```

ハッシュはMFTには含まれないが、Sysmon1（プロセス作成）の Hashes に含まれる。

## 封じ込め、予防、緩和

https://tryhackme.com/room/detectinguacbypass?taskNo=5&sharerId=674ed42e2374d1bc93db444c


