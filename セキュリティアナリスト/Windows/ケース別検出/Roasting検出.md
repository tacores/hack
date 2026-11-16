# Roasting検出

Kerberoasting と AS-REP Roasting の検出

https://tryhackme.com/room/asrepkrb

## 基礎

### Kerberoasting

TGSは、SPNを所有するアカウントのキーで暗号化される。TGSはドメイン内の認証済みユーザーであれば誰でもそれを要求できる。管理者権限も、特別なグループも、サービス自体へのアクセス権も必要ない。
アカウントのパスワードが脆弱であればオフラインで解読が可能。

```ps
# Listing user accounts that carry an SPN
PS C:\> Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
         Select-Object SamAccountName, ServicePrincipalName
```

```ps
# Requesting service tickets and formatting them for offline cracking
PS C:\> .\Rubeus.exe kerberoast /outfile:roasted.txt
```

このハッシュファイルは、Hashcatのモード13100（Kerberos 5、etype 23、TGS-REP）に対応する。

### AS-REP Roasting

ユーザーが最初のチケット（AS-REQ）を要求すると、Kerberosは通常、現在のタイムスタンプをユーザー自身のパスワードから生成された鍵で暗号化することで、ユーザーが誰であるかを証明することを要求する。これを事前認証という。鍵配布センターがそのタイムスタンプを復号できない場合、パスワードが間違っているため、チケットではなくエラーが返される。

```ps
# Listing accounts with pre-authentication disabled
PS C:\> Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol |
         Format-Table Name
```

```sh
# Requesting AS-REPs for accounts that do not require pre-authentication
$ impacket-GetNPUsers lunarbank.thm/ -dc-ip 10.10.10.5 -usersfile users.txt -request
```

このハッシュファイルは、Hashcatのモード18200（Kerberos 5、etype 23、AS-REP）に対応する。

## イベントログ

全てはドメインコントローラーで発生するイベント。

- 4768: A Kerberos authentication ticket (TGT) was requested
- 4769: A Kerberos service ticket was requested
- 4770: A Kerberos service ticket was renewed
- 4771: Kerberos pre-authentication failed

### オンにする必要がある2つのサブカテゴリ

「アカウントログオン」カテゴリの下にある2つの監査サブカテゴリ

| **Subcategory**                    | **Events it produces**                           | **Expected volume** | **Recommended setting** |
| :--------------------------------- | :----------------------------------------------- | :------------------ | :---------------------- |
| Kerberos Authentication Service    | 4768, 4771（4772 は定義されているが、生成されない） | 多い                | 成功と失敗              |
| Kerberos Service Ticket Operations | 4769, 4770（4773 は定義されているが、生成されない） | 非常に多い          | 成功と失敗              |

```ps
# Confirming the two Kerberos subcategories are logging on a DC
C:\> auditpol /get /category:"Account Logon"

System audit policy
Category/Subcategory                    Setting
Account Logon
  Credential Validation                 Success and Failure
  Kerberos Authentication Service       Success and Failure
  Kerberos Service Ticket Operations    Success and Failure
  Other Account Logon Events            No Auditing
```

### 注目すべき値

#### チケット暗号化タイプ

| **Value** | **Algorithm**           | **What it means here**                         |
| :-------- | :---------------------- | :--------------------------------------------- |
| 0x1 / 0x3 | DES                     | レガシー方式。デフォルトで無効化されており、通常は出現しない |
| 0x11      | AES128-CTS-HMAC-SHA1-96 | このドメインでは通常使用される方式              |
| 0x12      | AES256-CTS-HMAC-SHA1-96 | このドメインでは通常使用される方式              |
| 0x17      | RC4-HMAC                | 監視すべき値                                   |
| 0x18      | RC4-HMAC-EXP            | レガシーの RC4 方式                            |

#### 事前認証タイプ

4768: A Kerberos authentication ticket (TGT) was requested

| **Value**    | **Meaning**                         |
| :----------- | :---------------------------------- |
| 0            | 事前認証が実行されなかった          |
| 2            | PA-ENC-TIMESTAMP（標準的なパスワード認証） |
| 15 / 16 / 17 | スマートカード認証                  |
| 138          | Kerberos Armoring（FAST）           |

### Kerberoasting の検出

SPN, パスワード更新日、グループ、暗号化タイプ
```ps
Get-ADUser -Filter "ServicePrincipalName -like '*'" -Properties ServicePrincipalName, PasswordLastSet, MemberOf, msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, MemberOf, msDS-SupportedEncryptionTypes |
    Format-Table -AutoSize
```

| **Signal**           | **AN0444 parameter**            | **Field it reads**                                              | **What defeats it**           | **Works on an unpatched DC** |
| :------------------- | :------------------------------ | :-------------------------------------------------------------- | :---------------------------- | :--------------------------- |
| 暗号化方式のダウングレード | AllowedEncryptionTypes          | チケットの暗号化方式と MSDS-SupportedEncryptionTypes             | 攻撃者が AES を要求する        | RC4 のみを許可するベースラインの場合のみ |
| 大量リクエストの検出 | TGSRequestThreshold, TimeWindow | アカウント名、サービス名                                         | 単一アカウントへのロースト     | はい                         |
| ロースト可能なアカウントのベースライン | ServiceAccountBaselines | エクスポート情報：SPN、パスワードの経過期間、グループ、msDS-SupportedEncryptionTypes | なし（これが基準となる情報） | はい |
| ハニーポット SPN    | 帯域外のデコイ                  | サービス名                                                       | デコイを回避するロースト       | はい                         |

### AS-REP Roasting の検出

```ps
# Listing accounts with pre-authentication disabled
PS C:\> Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table Name
```

4768: A Kerberos authentication ticket (TGT) was requested イベントを列挙。

| **時間**   | **イベント** | **アカウント**      | **事前認証タイプ** | **エンコードタイプ** | **結果** | **クライアントアドレス**      |
| :------- | :------- | :------------- | :---------- | :----------- | :----- | :------------------ |
| 09:42:02 | 4768 エラー | バックアップ         | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:03 | 4768 エラー | itadmin        | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:04 | 4768 エラー | svc_sql        | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:05 | 4768 エラー | ヘルプデスク         | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:06 | 4768 エラー | 金融             | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:08 | 4768 エラー | hr.admin       | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:09 | 4768 エラー | jsmith         | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:10 | 4768 エラー | テンポラリ          | -           | -            | 0x6    | ::ffff:10.81.83.103 |
| 09:42:11 | 4768     | j.hartley      | 0           | 0x17         | 0x0    | ::ffff:10.81.83.103 |
| 06:00:03 | 4768     | svc_unixbridge | 0           | 0x17         | 0x0    | ::ffff:10.10.9.20   |

## 封じ込め、予防、緩和

https://tryhackme.com/room/asrepkrb?taskNo=7&sharerId=674ed42e2374d1bc93db444c

永続的な解決策は、人間が選択したパスワードを完全に削除すること。各SPNをグループ管理サービスアカウント（gMSA）に移動する。
