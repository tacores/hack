# ADポストエクスプロイトの検出

https://tryhackme.com/room/detectingadpostexploitation


## 永続性

- ユーザー作成 4720
- セキュリティグループ追加 4732
- パスワードリセット 4723, 4724

## ランサムウェア

### 暗号化前

#### ボリュームシャドウコピーの削除

プロセス作成イベントで捕捉（Systemon 1, Security 4688）

```ps
vsadmin.exe delete Shadows /all /quiet

wmic shadowcopy delete /nointeractive
```

#### Windows回復無効化

```ps
reagentc.exe /disable
```

#### バックアップ削除

```ps
wbadmin.exe delete catalog -quiet
```

#### ログ削除

```ps
Clear-EventLog-LogName Security

wevtutil cl System
```

監査ログクリアイベント

```sh
EventCode=1102
```

### 展開と暗号化

#### GPOによる展開

GPOは組織単位全体にわたって特定のアクションを実行できるため、攻撃者がランサムウェアを拡散するのに非常に便利。

1. SYSVOL共有へのアップロード

- SYSVOL へのファイル作成（Systemon 11）
- 共有アクセス（Security 5145）

2. GPO作成

- ディレクトリサービスオブジェクトの作成、変更（5137, 5136）

3. Startupアプローチ

- ファイル作成（Systemon 11）、ディレクトリサービスオブジェクト変更（Security 5136）
```
C:\Windows\SYSVOL\domain\Policies\XXXXXXXXX\Machine\Scripts\Startup\Office364.exe
```
- 複数の端末でレジストリ値設定（Sysmon 13）

#### WMIによる展開

wmic のプロセス作成イベント

#### タスクスケジューラによる展開

schtasks のプロセス作成イベント。展開するホストの数だけ schtasks が実行される形になる。

```sh
schtasks /create /s <hostname> ......
```

#### RMMソリューションによる展開

RMM管理コンソールを取得できれば、ADドメインを侵害する必要がなくなる。
