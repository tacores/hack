# SAM hive ダンプ検出

https://tryhackme.com/room/detectingsamhivedumping

```
C:\Windows\System32\config\SAM
```

## 基本

SAM には NT ハッシュを含むローカル アカウントのみが格納され、平文のパスワードや Kerberos チケットは格納されない。LSASSメモリと異なり、ログオンされたことがないアカウントも含めすべてのローカルアカウントが含まれる。

Windows は、HKLM\SYSTEM ハイブに格納されている BootKey (SysKey とも呼ばれる) を使用してこれらのハッシュを暗号化するので、NTハッシュをクラックしたい場合は SYSTEMハイブも同時に入手する必要がある。

```sh
# ダンプコマンド
reg save HKLM\SAM C:\ProgramData\sam.save
reg save HKLM\SYSTEM C:\ProgramData\system.save

Get-ChildItem C:\ProgramData\sam.save,C:\ProgramData\system.save |
Compress-Archive -DestinationPath C:\ProgramData\out.zip
```

```sh
mimikatz # lsadump::sam /sam:sam.save /system:system.save
```

```sh
# リモート（impacket）
secretsdump.py Administrator:Secure!@10.144.129.226
```

## 検出

### SAMハンドル

- 4656 (ハンドルが要求されました) 
- 4663 (オブジェクトへのアクセスが試みられました) 

監査を有効にする必要がある。[参照](https://tryhackme.com/room/detectingsamhivedumping?taskNo=3&sharerId=674ed42e2374d1bc93db444c)

### プロセス生成

ダンプコマンド

### ファイル作成

ダンプファイル

### リモートダンプ

- Security 4624：攻撃者のIPアドレスからターゲットへの汎用タイプ3ログオン
- System 7036：リモートレジストリサービスが実行状態に入り、SMB/RPCを使ってリモートで開始された
- Security 4656：svchost.exe によるハンドル要求。
- System 7036：RemoteRegistryサービスが停止状態になりました

## 保護

ローカルアカウントの保護には、LAPS（ローカル管理者パスワードソリューション）が有効。
- [参照](https://tryhackme.com/room/detectingsamhivedumping?taskNo=5&sharerId=674ed42e2374d1bc93db444c)
- [参照２](https://www.recastsoftware.com/resources/how-to-configure-windows-laps-in-active-directory/)
