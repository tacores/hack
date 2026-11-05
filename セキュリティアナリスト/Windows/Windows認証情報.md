# Windows認証情報

https://tryhackme.com/room/windowscredentials

## SID（セキュリティ識別子）

Windows のすべてのユーザー、グループ、またはシステム アカウントに割り当てられる一意の識別子。

| **SIDの構成要素** | **SID内の位置** | **説明** |
| :--- | :--- | :--- |
| リビジョンレベル | `S-`**`1`**`-...` | 常に`1`に設定される。 |
| 識別機関（Identifier Authority） | `S-1-`**`5`**`-...` | SIDを管理する機関を示す。<br><br>**5**：NT Authority（主にオンプレミスの主体）<br>**12**：Entra ID（Azureと同期されたアカウント） |
| サブ機関（Subauthority） | `S-1-5-`**`21`**`-...` | NT Authorityの場合、主体の種類を示す。<br><br>**21**：すべてのドメイン主体に使用される<br>**32**：組み込み（例：Guestsグループ）<br>**18**：Local Systemアカウント |
| ドメインID（Domain ID） | `S-1-5-21-`**`1966530601-3185510712-10604624`**`-...` | `<32bit>-<32bit>-<32bit>`形式の一意なドメインID。<br>サブ機関が`21`の場合のみ存在する。 |
| 相対識別子（RID） | `S-1-5-21-1966530601-3185510712-10604624-`**`500`** | サブ機関内で主体を一意に識別するID。 |

### RID

- S-1-5-18 → Local System account (no RID!)
- S-1-5-32-544 → Local Administrators group
- S-1-5-21-<domain-id>-512 → Domain Admins group
- S-1-5-21-<domain-id>-513 → Domain Users group
- S-1-5-21-<domain-id>-500 → Built-in Administrator
- S-1-5-21-<domain-id>-501 → Built-in Guest account
- S-1-5-21-<domain-id>-1000+ → Custom machine and user accounts

```ps
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Select-Object PSChildName, ProfileImagePath

Get-LocalUser | Select Name,SID

Get-LocalGroup | Select Name,SID
```

## ハッシュ

### LMハッシュ

後方互換性以外では使われないので詳細は省略。弱い。

### NTハッシュ

最新のWindowsシステムで使用される標準的なパスワードハッシュ方式。  
Unicode（UTF-16-LE）でエンコード後、MD4でハッシュ化。

### MS-Cache v2 (DCC2)

キャッシュされたドメイン認証情報に使用される。DCが利用できない場合にドメインが完全にロックアウトされるのを防ぐため、Windowsは最近使用したドメインパスワードをローカルマシンにキャッシュする。PBKDF2レイヤーが追加され、ハッシュラウンド数が10240回（NTでは1回）であるため、LMハッシュやNTハッシュよりも1万倍以上解読が困難。

### 表示フォーマット

`Username:RID:LMHASH:NTHASH`

- ユーザー名 → アカウント名
- RID → 相対識別子
- LMハッシュ → レガシーハッシュ（最初の位置）
- NTハッシュ → 認証に使用（2番目の位置）

## ローカル認証

### LSASS（ローカルセキュリティ機関サブシステムサービス）

ユーザーがローカルログオン、RDP、SMBでパスワードを入力したら、LSASSに転送される。

`C:\Windows\System32\lsass.exe` のダンプファイルには、認証済みユーザーのローカルハッシュとドメインハッシュ、およびチケットなど様々な情報が含まれる。LSASSのダンプには通常、SYSTEMレベルの権限（またはSeDebugPrivilegeを持つAdministrator権限）が必要。

```sh
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
```

### SAMデータベース

SAM は、NT パスワードハッシュを含むローカルユーザーアカウント情報を保存する Windows のコアコンポーネント。レジストリハイブとして実装されている。`C:\Windows\System32\config\SAM`

パスワードハッシュはSysKey または BootKey と呼ばれる別のキーで暗号化されているため、SAMハイブと同時に SYSTEMハイブも取得する必要がある。

```ps
# regeditでSYSTEMとしてSAMハイブにアクセス（Administratorでは見えない）
PsExec64.exe -i -s regedit
```

```ps
# SAMをダンプ
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

## ドメイン認証

### NTDS.dit

Active Directoryがドメイン関連オブジェクト（ユーザーアカウント、グループ、コンピューター、およびそれらに関連付けられたパスワードハッシュなど）を格納するために使用するコアデータベースファイル。各ドメインコントローラーに保存され、C:\Windows\NTDS\NTDS.ditファイルとして実装されている。

SAMと同様に、NTDS.ditのパスワードハッシュはBootKeyで暗号化されているためSYSTEMハイブも必要。

```ps
# 参考。DSInternalsを使用したBootkeyの抽出。
$key = Get-BootKey -SystemHivePath C:\Users\Administrator\Desktop\NTDS\SYSTEM.HIVE
echo $key
```

[DitExplorer](https://github.com/trustedsec/DitExplorer) でデータベースファイルを閲覧できる。（BookKeyの入力が必要）

```ps
# DSInternals を使ってダンプ
Get-ADDBAccount -DBPath 'C:\Users\Administrator\Desktop\NTDS\NTDS.dit' -BootKey $key -SamAccountName Administrator

# 件数
Get-ADDBAccount -DBPath 'C:\Users\Administrator\Desktop\NTDS\NTDS.dit' -BootKey $key -All | Measure-Object
```

### キャッシュされた資格情報

キャッシュされた資格情報はローカルに保存されるため、ドメインコントローラーが利用できない場合でもユーザーはログインできる。Windows は一定時間経過後もキャッシュされたレコードを期限切れにせず、直近に認証されたドメインユーザー 10 人の資格情報を保存する。

`C:\Windows\System32\config\SECURITY` の `HKLM\Security\Cache`

SAMやNTDS.ditと同様に、キャッシュされた認証情報はブートキーで暗号化されるが、さらにいくつかの手順が必要。

1. BootKey は HKLM\SYSTEM から取得 
2. HKLM\SECURITY\Policy\PolEKListBootKey を使用してLSAキーを復号
3. HKLM\SECURITY\Policy\Secrets\NL$KM\CurrValLSA キーで復号化
4. `HKLM\SECURITY\Cache\NL$*` NL$KM 値を使用してエントリを復号化

```ps
mimikatz # lsadump::cache
```

## その他の認証情報

### LSAシークレット

LSA シークレットは、Windows ローカル セキュリティ オーソリティ (LSA) が SECURITY ハイブに格納する機密性の高い認証情報

- 位置：HKLM\SECURITY\Policy\Secrets
- 内容：暗号化されたパスワードとハッシュのさまざまな種類
- MITREマッピング：OS認証情報ダンプ：LSAシークレット（T1003.004）
- 必要な権限: SYSTEM

```ps
mimikatz # lsadump::secrets
```

### DPAPIシークレット

DPAPI (データ保護 API) は、アプリケーションがデータを簡単に暗号化および復号化できるようにする Windows コンポーネント。

- 暗号化キーの場所：スコープによって異なる
- 暗号化データの保存場所：アプリケーションの選択による
- 内容：ブラウザのシークレット、Wi-Fiプロファイル、スケジュールされたタスクで使用されるアカウントなど。
- MITREマッピング：パスワードストアからの認証情報（T1555）
- 必要な権限: SYSTEM

```
LSAシークレットは、OSレベルおよびサービス認証情報を保護する。
DPAPIはエンドユーザーとそのアプリケーションのデータを保護する。
```

```ps
# DPAPIシークレットを復号
mimikatz # vault::cred /patch
```

### 平文認証情報

`C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
