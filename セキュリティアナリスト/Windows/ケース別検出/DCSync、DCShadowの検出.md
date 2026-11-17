# DCSync、DCShadowの検出

https://tryhackme.com/room/dcsyncshadow

## 基礎

各ドメインコントローラーは、アカウントのパスワードハッシュを含む、不足している情報を他のドメインコントローラーに要求できる。この仕組みをレプリケーションという。  
[ディレクトリレプリケーションサービスリモートプロトコル（MS-DRSR）の仕様](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)  
このインターフェースへのアクセスは、ドメインコントローラーであるかどうかではなく、適切なアクセス許可を持っているかどうかによって制御される。適切なアクセス許可を持つものはすべてレプリケーションを実行でき、Active Directoryが応答する。

### DCSync と DCShadow の違い

DCSync はドメインコントローラーになりすまして、ドメインのパスワードハッシュを要求する。  
DCShadow はドメインコントローラーになりすまして、ディレクトリに記録されない変更を書き込む。

DCSync はプル方式を採用しており、実際のドメインコントローラに機密情報の引き渡しを要求する。  
DCShadow はプッシュ方式を採用しており、実際のドメインコントローラに、あたかも別のドメインコントローラが変更を行ったかのように変更を受け入れるよう説得する。

プルはリクエストであり、リクエストはログに記録できる。  
プッシュはレプリケーションとして届き、レプリケートされた変更はそれを受信したドメインコントローラーによって書き込まれないため、通常の変更監査では記録するものがない。

### DCSync

`DRSGetNCChanges`呼び出しでアカウントの複製を要求する。  
応答にはそのアカウントの秘密情報（現在の NTLM ハッシュ、Kerberos キー、パスワード履歴、可逆暗号化が有効になっている場合の平文パスワード）が含まれる。

| **Right**                                    | **GUID**                               | **What it grants**                                      |
| :------------------------------------------- | :------------------------------------- | :------------------------------------------------------ |
| `DS-Replication-Get-Changes`                 | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | 通常のオブジェクト属性を複製する権限                    |
| `DS-Replication-Get-Changes-All`             | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | 機密情報を複製する権限。パスワードハッシュを取得する権限 |
| `DS-Replication-Get-Changes-In-Filtered-Set` | `89e95b76-444d-4c62-991a-0facbeda640c` | RODC のフィルター対象属性セットを複製する権限            |

**上２つの権限が必要。** 3つ目は読み取り専用のドメインコントローラーが存在する環境でのみ重要だが、攻撃者が機会を伺って要求するため、検出結果には表示される。

デフォルトでは、Domain Admins、Enterprise Admins、Administrators、ドメインコントローラー自身のコンピューターアカウント、Entra Connectによって作成された`MSOL_`アカウントなどのディレクトリ同期アカウントといった、少数の予測可能なグループに属する。

```ps
# Checking which principals can replicate the domain
PS C:\> Get-DomainObjectAcl -Identity "DC=lunarbank,DC=thm" -ResolveGUIDs | ? { $_.ObjectAceType -match "Replication-Get" } | select SecurityIdentifier, ObjectAceType

SecurityIdentifier                              ObjectAceType
------------------                              -------------
S-1-5-21-1004336348-1177238915-682003330-1147   DS-Replication-Get-Changes
S-1-5-21-1004336348-1177238915-682003330-1147   DS-Replication-Get-Changes-All
```

mimikatz の例

```ps
# Replicating the KRBTGT account from a legitimate Domain Controller
mimikatz # lsadump::dcsync /domain:lunarbank.thm /user:krbtgt
```

impacket の例

```sh
# The same replication request from an attacker's Linux host
user@attacker$ secretsdump.py lunarbank.thm/n.lopes:'<password>'@LB-DC01.lunarbank.thm -just-dc-user krbtgt
```

### DCShadow

攻撃者はドメインコントローラーにデータを要求するのではなく、自身のマシンを数秒間ドメインコントローラーとして登録し、レプリケーションを通じて選択した属性値をディレクトリにプッシュした後、登録を解除する。

DCShadowは、不正なドメインコントローラーとして機能するホスト上でSYSTEM権限を持ち、さらにディレクトリを登録するのに十分な権限を持っている必要がある。実際には、これは通常Domain Adminを意味する。ただし、一度Domain Admin権限を取得した攻撃者は、その権限セットを通常のアカウントに委任し、後で権限なしで復帰することができる。

通常、ディレクトリを編集するDomain Adminは監査され、属性が記録されるが、レプリケーションによって到着した変更は、受信側のドメインコントローラーが変更を発信していないため、記録されない。また、レプリケーションは、通常のクライアントでは実行できない書き込みも受け入れるため、通常のDomain Adminセッションではアクセスできない属性にまでこの手法が到達する。**そのため、DCShadow は権限昇格ではなく、永続化と防御回避のための手法である。**

変更をステージングし待機

```ps
# Staging a primaryGroupID of Domain Admins (RID 512) onto a low-privilege account
mimikatz # lsadump::dcshadow /object:adam.walker /attribute:primaryGroupID /value:512
```

レプリケーションをトリガー

```ps
# Registering the rogue DC, pushing the change, then removing the evidence of the DC
mimikatz # lsadump::dcshadow /push
```

プライマリグループのメンバーシップはグループのメンバーリストではなくユーザーオブジェクトに存在するため、グループの属性にこのアカウントが表示されることはない。

## イベントログ

| **Subcategory**                            | **Gives you**    | **Used in** | **The catch**                                                                                       |
| :----------------------------------------- | :--------------- | :---------- | :-------------------------------------------------------------------------------------------------- |
| **Directory Service Access**               | 4662（ADオブジェクトに対して操作が実行された）             | DCSync      | **Success** の監査が必要。さらに、ドメインオブジェクトに SACL を設定する必要がある |
| **Directory Service Changes**               | 5136, 5137, 5141（オブジェクトの変更、作成、削除） | DCShadow    | SACL の設定が必要。ドメインコントローラーでのみ記録される |
| **Detailed Directory Service Replication** | 4928, 4929（レプリカソースのネーミングコンテキストが確立された、削除された）       | DCShadow    | デフォルトでは無効で、イベント量も非常に多い。4928 は記録されないが、4929 には登録解除時の不正なホスト名が記録される |

ドメインコントローラーは、自身が行った変更に対してのみ、ログに5136を書き込む。レプリケーションによって別のドメインコントローラーから変更が届いた場合、受信側のドメインコントローラーは新しい値を受け入れ、何もログに記録しない。なぜなら、受信側のドメインコントローラーにとっては、ローカルで何も変更されていないため。

効果的に監査されている設定

```ps
# The effective DS Access audit policy on the Domain Controller
PS C:\> auditpol /get /category:"DS Access"

System audit policy
Category/Subcategory                        Setting
DS Access
  Directory Service Access                  Success and Failure
  Directory Service Changes                 Success
  Directory Service Replication             Success
  Detailed Directory Service Replication    Success
```

下記の結果が空の場合、ドメインオブジェクトがレプリケーションアクセスを報告していないことを意味し、適切な監査ポリシーを設定しても、DCSync に対して 4662 は発生しない。

```ps
# Is the domain object actually auditing the replication rights?
PS C:\> Import-Module ActiveDirectory
PS C:\> (Get-Acl "AD:\DC=lunarbank,DC=thm" -Audit).Audit | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }

IdentityReference     : Everyone
AuditFlags            : Success
ActiveDirectoryRights : ExtendedRight
ObjectType            : 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

```ps
# Proving the log is capable of holding the event you are looking for
PS C:\> Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} -MaxEvents 5 | Select-Object TimeCreated
```

## DCSync検出

### Security 4662イベント

#### 見るべきポイント（例）

| **Field**           | **Value here**                         | **Why it matters**                                           |
| :------------------ | :------------------------------------- | :----------------------------------------------------------- |
| **SubjectUserName** | `n.lopes`                              | ドメインコントローラーではなく一般ユーザーアカウント。これが検出のポイント |
| **ObjectType**      | `19195a5b-6da0-11d0-afd3-00c04fd930c9` | `domainDNS` クラスを示すため、対象はドメインそのもの |
| **ObjectName**      | `e5b50a99-3e2b-4486-ba73-e1461d28fcdb` | 名前ではなく GUID。対応するオブジェクトを解決する必要がある |
| **AccessMask**      | `0x100`                                | Control Access。拡張権限を行使する際に使用される |
| **Properties**      | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All 権限 |
| **SubjectLogonId**  | `0x315f904`                            | 4624 と照合することで、接続元ホストを特定できる |

GUIDが何のオブジェクトか

```ps
# Turning the object GUID into something you can reason about
PS C:\> Get-ADObject -Identity 'e5b50a99-3e2b-4486-ba73-e1461d28fcdb'

DistinguishedName : DC=lunarbank,DC=thm
Name              : lunarbank
ObjectClass       : domainDNS
```

| **Signal**      | **正規のレプリケーション**                                      | **悪意のあるレプリケーションの例**                     |
| :-------------- | :-------------------------------------------------------------- | :--------------------------------------------- |
| **Identity**    | `$` で終わるコンピューターアカウント、または `MSOL_4c81b7` などの同期アカウント | `n.lopes`（対話型ユーザーアカウント） |
| **Source host** | 別のドメインコントローラー、または固定の Entra Connect サーバー | `LB-WS14`（メンバーサーバー）                  |
| **Cadence**     | ドメインコントローラー間では常時、同期アカウントではスケジュールに従う | 数秒間隔で2回、単一のバーストとして発生 |
| **Object Name** | `DC=lunarbank,DC=thm`                                            | `DC=lunarbank,DC=thm`（対象範囲からは判断できない） |
| **Access Mask** | `0x100`                                                          | `0x100`（アクセスマスクからも判断できない）    |

### Security 4624 （ログオン）

```ps
# Pivoting from the 4662 Logon ID to the network logon that opened the session
PS C:\> Import-Csv C:\Cases\dc01-security.csv | Where-Object { $_.EventId -eq 4624 -and $_.Payload -match "0x315f904" } | Select-Object TimeCreated, RemoteHost
```

### アーティファクト

ワークステーション側の実行痕跡調査

```ps
# The attacker's own commands, recovered off disk
PS C:\> Select-String -Pattern "dcsync|secretsdump|mimikatz" `
          -Path "$c\LB-WS14\C\Users\n.lopes\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

## DCSyadow検出

DCの作成と削除

```ps
# Directory service objects created and deleted, newest first
PS C:\> Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5137,5141} |
          Select-Object TimeCreated, Id, @{n="Object"; e={$_.Properties[8].Value}}
```

ADでの削除はオブジェクト削除ではなく、名前が変更され、削除済みオブジェクトコンテナーに移動される。  
削除されたnTDSDSAオブジェクトを表示。

```ps
# Every nTDSDSA object, live and deleted; each deleted one (DEL: in its name) is a Domain Controller that went away
PS C:\> Get-ADObject -IncludeDeletedObjects -LDAPFilter "(objectClass=nTDSDSA)" `
          -SearchBase "CN=Configuration,DC=lunarbank,DC=thm" `
          -Properties whenCreated, whenChanged, lastKnownParent |
          Select-Object Name, whenCreated, whenChanged, lastKnownParent

Name             : NTDS Settings
                   DEL:15c44b67-fd6d-48a9-8ee1-c1414924ee81
whenCreated      : 02/09/2026 17:00:17
whenChanged      : 02/09/2026 17:00:17
lastKnownParent  : CN=LB-APP03\0ADEL:08285c6a-2104-4fc6-834e-2ae1a5019847,CN=Servers,
                   CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lunarbank,DC=thm
```

Active Directory は、すべての属性のレプリケーションメタデータを保存している。  
特定アカウントのメタデータを表示。

```ps
# Per-attribute metadata for the backdoored account
C:\> repadmin /showobjmeta LB-DC01 "CN=Rita Peter,OU=Finance,DC=lunarbank,DC=thm"

Loc.USN  Originating DSA                        Org.USN  Org.Time/Date        Ver Attribute
=======  ===============                        =======  =============        === =========
  12783  Default-First-Site-Name\LB-DC01          12783  2026-08-26 18:03:46    1 objectClass
  12783  Default-First-Site-Name\LB-DC01          12783  2026-08-26 18:03:46    1 sAMAccountName
  12784  Default-First-Site-Name\LB-DC01          12784  2026-08-26 18:03:46    1 primaryGroupID
  17299  Default-First-Site-Name\LB-DC01          17287  2026-09-02 17:00:17    1 sIDHistory
```

- 発生元（Originating DSA）は偽装されるので証拠にならない。
- タイムスタンプの不自然なずれに注目。
- Loc.USN と Org.USN の不一致が最大の決め手。ローカルUSNは受信側のDCが変更を適用する瞬間に、自身のカウンターから独自に採番する番号であり、攻撃者は制御不可。


## 封じ込め、予防、緩和

https://tryhackme.com/room/dcsyncshadow?taskNo=7&sharerId=674ed42e2374d1bc93db444c

```ps
# Hunting for siblings of the change you already found
PS C:\> Get-ADObject -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory
PS C:\> Get-ADUser -LDAPFilter "(primaryGroupID=512)" -Properties primaryGroupID
PS C:\> Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount, memberOf
```
