# AD初期アクセスの検出

https://tryhackme.com/room/detectingadinitialaccess

## IISログ

`C:\inetpub\logs\LogFiles\W3SVC1`

### splunk

ディレクトリスキャンの検出

```
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

そのIPがアクセスしたパス

```
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

Webシェルリクエストの詳細

```
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

sysmonイベントで w3wp.exe の子プロセスの検出（基本的にw3wp.exeは子プロセスを作らない。csc.exe 等は例外的に子プロセスになることがある）

```
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

## Exchange, Outlook, OWA

Exchangeはサーバー、Outlookはデスクトップアプリケーション、OWA（Outlook Web Access）はWebアプリケーション。

### ログイン

- ログイン成功時、/owa/auth.owa へのPOSTレスポンスで /owa/ に302リダイレクトされる。
- ログイン失敗時、/owa/auth.owa へのPOSTレスポンスで /owa/auth/login.aspx に302リダイレクトされる。

POSTリクエストにはユーザー名が出ないが、セキュリティログで確認できる。イベント 4624 (ログイン成功) と 4625 (ログイン失敗) 。

### Exchange 仮想ディレクトリ

- `/owa` はOWAのログインページ
- `/ecp` は管理インターフェース（Exchange Control Panel）。厳重な監視が必要

### splunk

ブルートフォース

```
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

対象ユーザー名を確認

```
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

対象ユーザーがログイン成功したか？

```
index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, EventCode, user, Process_Name, Logon_Type
| sort _time
```

認証後アクティビティ

```
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

## VPN

### NPSサーバー

ほとんどのエンタープライズ環境では、VPNゲートウェイはADと直接通信せず、RADIUSプロトコルを仲介として利用する。Windowsでは、RADIUSサーバーはNPS（ネットワークポリシーサーバー）と呼ばれる。

#### NPSイベントID

| イベントID | 意味 | セキュリティの関連性 |
|---|---|---|
| 6272 | ネットワークポリシーサーバーにアクセスを許可 | VPN認証に成功しました |
| 6273 | ネットワークポリシーサーバーがアクセスを拒否しました | VPN認証に失敗しました |
| 6274 | ネットワークポリシーサーバーは要求を破棄しました | 不正な形式または拒否されたリクエスト |

イベント 6273 に含まれる Reason Codeフィールド

| コード | 意味 | 教えてくれること |
|---|---|---|
| 16 | 不明なユーザー名または間違ったパスワード | 認証情報攻撃の兆候 |
| 48 | 一致するネットワークポリシーがありません | アカウントが VPN に承認されていない（攻撃ではない） |
| 65 | RADIUS共有秘密の不一致 | 誤った設定（攻撃ではない） |

### splunk

NPS拒否イベント

```
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

対象ユーザーが認証されたか？

```
index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
```

セキュリティログオンイベントとの関連

```
index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
| table _time, host, user, EventCode, Logon_Type
| sort _time
```
