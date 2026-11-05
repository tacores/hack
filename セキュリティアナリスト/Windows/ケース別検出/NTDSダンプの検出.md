# NTDSダンプの検出

https://tryhackme.com/room/detectingntdsdatabasedumping

## 基本

```
C:\Windows\NTDS\ntds.dit
```

ドメイン全体のシークレットが保存されている

- すべてのドメインユーザー、コンピューター、およびサービスアカウントのNTハッシュ
- Kerberosキー（ゴールデンチケットの偽造に使用されたkrbtgtハッシュを含む）
- パスワード履歴、グループメンバーシップ、その他のディレクトリ属性

```sh
# 署名付きの組み込み AD 管理ツール
ntdsutil.exe "ac i ntds" "ifm" "create full c:\temp_l0gs" q q
```

```sh
# シャドウコピー
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\system.hive
```

```sh
# DCSync
# ドメインコントローラーにアクセスできるドメイン参加済みデバイスであれば、どのデバイスからでも実行できる。
mimikatz # lsadump::dcsync /user:Administrator
```

```sh
# DSInternals を使用した DCSync
Get-ADReplAccount -SamAccountName krbtgt -Server 'dc-01.victim.local'
```

## 検出

### Ntdsutilの検出

Applicationログ（Source = ESENT）

- イベントID 325：新しいデータベースが作成された。宛先パスが明らかになる。
- イベントID 327：データベースがデタッチされ、コピーが完了したことが確認された。

### シャドウコピーの検出

`C:\Windows\System32\vssvc.exe` を介してシャドウコピーが作成される。

#### 1. VSSの開始と停止（System: 7036）

Volume Shadow Copy service entered the **running** state

数分後に ↓

Volume Shadow Copy service entered the **stopped** state

これは、VSS が実行されたことを示すだけであり、シャドウ コピーの作成だけでなく、シャドウ コピーに対するあらゆる操作を意味する可能性がある。

#### 2. VSSAuditイベント登録（Security 4904）

シャドウコピーが作成されたことを意味する。  
その後に、イベントソースの登録を解除（Security 4905）

`ProcessName=*\VSSVC.exe`、`SourceName=VSSAudit`

#### 3. VSSAuditイベントの詳細（Security 8222）

どのユーザーとプロセスがVSSとやり取りしたか、またはどのディスクがキャプチャされたかを示す。  
GPOを使用してイベントID 8222を有効にし、ソースプロセスや元のボリュームなどの詳細をすべて記録する必要がある。`Advanced Audit Policy → Object Access → Audit Application Generated`

### その他の一般的なイベント

- Sysmon 11: NTDS ダンプの作成
- Security 4663: NTDS ファイルオブジェクトへのアクセス

[参照](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/vssadmin.htm)


## アーティファクト

### 実行アーティファクト

ドメインコントローラーでは、ntdsutil.exe、esentutl.exe、vssadmin.exe の実行はまれなので注意。

### MFT, USNジャーナル

ダンプファイルの作成履歴

- 親パス：（`.\System Volume Information` すべてのシャドウコピーのデフォルト保存場所）
- ファイル名： （VSS固有の`{...}{3808876b-c176-4e48-b7ae-04046e6cc752}`パターン。このGUIDは固定値）

ただし、シャドウコピーは、NTDSダンプだけでなく、他の手法にも使用される可能性がある（ITチームが手動で作成したり、正規のソフトウェアによる定期的な作成）ことに注意が必要。

## DCSyncの検出

DCSync はドメイン コントローラーのファイルシステムには一切アクセスしないため、唯一信頼できるシグナルはログにある。

### オブジェクトアクセス

#### Security 4662: オブジェクトに対して操作が実行された

Properties フィールドの下記値を検索。（レプリケーションリクエスト DS-Replication-Get-Changes* を示す GUID）

- {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
- {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}

4662 イベントは事前に設定が必要。`Local Security Policy > Advanced Audit > DS Access > Audit Directory Service Access` [参照](https://tryhackme.com/room/detectingntdsdatabasedumping?taskNo=5&sharerId=674ed42e2374d1bc93db444c)

#### 4662 以外

- Security 4624(ログオンタイプ3) : DC認証の場合
- Security 5140: SMB経由の場合（secretsdumpなど）

オブジェクト操作に出力されているログオンIDとログオンイベントを関連付けるとIPアドレスを特定できる可能性がある。

## 保護

https://tryhackme.com/room/detectingntdsdatabasedumping?taskNo=6&sharerId=674ed42e2374d1bc93db444c
