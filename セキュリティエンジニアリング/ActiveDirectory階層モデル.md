# ActiveDirectory 階層モデル

https://tryhackme.com/room/adtiermodel

## 階層型アクセスモデル

- Tier0：ドメイン コントローラーと、Exchange サーバー、 CAサーバー、ID 管理ソリューションなど、Windows ドメインに対する管理制御権を持つその他のすべてのサーバーが含まれます。
- Tier1：アプリケーション サーバー、データベース サーバー、ファイル共有サーバーなど、企業にサービスを提供するものの、Windows ドメインに対する管理制御権を持たないすべてのサーバーが含まれます。
- Tier2：通常のユーザーのワークステーションとその他のエンドユーザー デバイスが含まれます。

それぞれの階層のみにアクセスできる管理者資格情報を作成する（例：t2_bob、t1_bob など）。パスワードは異なるものにしないと意味がない。

### 層間制限の原則

1. 上位層の資産は、同じ層または下位層の他の資産を制御できる（下位層のマシンを管理する権限ではなく、Active Directory内の資産を変更する権限を意味する）
1. ユーザーは、下位​​層のマシンに決してログインしない。下位層のマシンに資格情報がキャッシュされるため。

## 階層型ADの実装

### OU定義

1. Admin と呼ばれる基本OUを定義
1. 基本OUに Tier0, Tier1, Tier2 を定義
1. 各OUに次のサブOUを定義

- Users: 層の管理ユーザーが含まれます。
- Groups: ティアに定義されたグループが含まれます。これにより、必要に応じてサブロールを作成できます。
- Devices: その層に対応するマシンが含まれます。
- Service Accounts: （特定のシナリオに応じて）この層で動作するすべてのサービスアカウント。

### 階層化グループの作成

1. 階層化グループの作成（例：T0-Admins、T1-Adminsなど）

### テストユーザーの作成

1. 各階層にテストユーザーを作成（t0_bobなど）

### グループポリシーによるアクセス制限の実装

1. グループポリシー管理エディターで、GPOを作成（T0-RestrictAccessなど）

2. グループポリシー管理エディターを開いてGPOを編集。T1,T2AdminがT0にログインできないようになど、原則に従って設定。

`Computer Configuration-> Policies-> Windows Settings-> Security Settings-> Local Policies->User Rights Assignment`

- Deny log on as a batch job: denies users from logging into the machine as a scheduled task.
- Deny log on as a service: denies users from logging into the device as a service.
-Deny log on locally: restricts users from logging into the machine physically.
- Deny log on through Terminal Services: denies users logging into the machine via RDP.
- Deny access to this computer from the network: denies access to network services like SMB, NetBIOS, CIFS and others.

3. 「Group Policy Management」で、GPOを、各層の Devices サブOU にリンクする。T0-RestrictAccessには、ドメインコントローラもリンクすることに注意。

### 管理者権限の設定

Tx-AdminsグループをローカルAdministratorsグループに追加し、RDP経由で階層内のデバイスに接続できるようにするためのGPOを追加作成する。

GPOの制限されたグループ機能を使用して、AdministratorsおよびRemote Desktop Usersグループのメンバーシップを上書きする。これらのグループに現在所属しているユーザーは削除され、このGPOに所属するユーザーのみが残ることに注意。

T0-AllowAdmins GPOを作成。

グループポリシー管理エディターで `Computer Configuration-> Policies-> Windows Settings-> Security Settings->Restricted Groups`

「Administrators」「Remote Desktop Users」グループを追加。メンバーに「Administrator」「T0-Admins」を追加。

さらに、 他のユーザーがここに含まれないように、T0-Adminsデフォルトの管理者アカウントを「Allow log on through Remote Desktop Services」権限に追加。

`Computer Configuration-> Policies-> Windows Settings-> Security Settings-> Local Policies->User Rights Assignment`

T1-AllowAdminsには、T1-Adminsだけ追加する形。T2も同じ。

Tx-AllowAdmins を、各階層のDevices OU にリンクする。

## 権限の委任

サブOUごとに制御の委任を実行。詳細はTHMを参照。

## デフォルトユーザーとグループのセキュリティ保護

高い権限を持つデフォルトのグループへのメンバーシップは最小限に。

- Domain Admins
- Enterprise Admins
- Schema Admins
- Domain Controllers
- Read-only Domain Controllers
- Group Policy Creator Owners

新規インストール時、Domain Admins以外は空になる。  

### ベストプラクティス

- Domain Adminsは ドメインAdministrator のみを永続メンバーとして保持し、ドメインのセットアップ時または緊急時にのみ使用する。  
- Domain Admins以外で権限を持つユーザーが必要になった場合は、一時的に追加し、必要なタスクが完了したらすぐに削除する。

### Domain Admins と Enterprise Admins のセキュリティ保護

- T1マシンとT2マシンにおいて、これら2つのグループのアカウントからのログインを一切許可しない。

`T1-RestrictAccess`, `T2-RestrictAccess` のDenyポリシーに、この2グループを追加する。

### デフォルトのローカルグループ

- Account Operators
- Backup Operators
- Print Operators
- Server Operators
- Cryptographic Operators

ベースライン構成では、これらのグループにはどの層にもメンバーが存在しないようにする。追加対策として、これらのグループに対しては、全層においてあらゆるログインタイプを拒否する。

### 管理者アカウントのセキュリティ保護

- ドメイン内の各マシンには、ローカルの管理者アカウントが組み込まれる。このアカウントは、ネットワーク認証が不可能な場合にドメインコントローラーを介さずにマシンにアクセスできるため、非常に重要。このアカウントは、GPO内では Administrator として参照される。
- デフォルトでは、各ドメインはドメイン全体の管理者アカウントを作成する。このアカウントは、ドメイン名をプレフィックスとして持つGPOで参照される。（例：THM\Administrator）

Tx-RestrictAccess

- バッチジョブとしてログオンを拒否する
- サービスとしてログオンを拒否する
- ターミナルサービス経由のログオンを拒否する
- ネットワークからこのコンピュータへのアクセスを拒否する

ローカルログインは拒否していないことに注意。これにより緊急時にオンサイトのマシンにログインできる。  
オンサイトサーバーへのアクセスが不可能な場合は、ローカル管理者アカウントでRDPアクセスを有効にすることを検討する。ただし、サーバーごとに異なるパスワードを管理するのが適切。

Tx-AllowAdmins

- Administratorsグループに、THM\Administrator; Administrator を追加
