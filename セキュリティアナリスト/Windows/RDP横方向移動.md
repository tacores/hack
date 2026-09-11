# RDP横方向移動

https://tryhackme.com/room/rdplateralmovementanalysis

## 基礎

デフォルトポートは 3389

### 主要コンポーネント

- ソースホストはクライアント mstsc.exe を実行 
- 接続が成功すると、宛先ホストはリモートデスクトップサービス（svchost.exe 内部でホストされている TermService）と、セッションが作成されるたびに開始されるセッションサポートプロセス rdpclip.exe、tstheme.exe（クリップボード共有とテーマレンダリング）を実行。

## イベントログ

### 接続元

- SysmonイベントID 1（mstsc.exeプロセスの作成）
- SysmonイベントID 3（送信TCP 3389）
- TerminalServices-RDPClient イベント ID 1024/1025 (RDP クライアント接続)

### 接続先

- セキュリティイベントID 4624（タイプ10）対話型RDPログオン成功
- TS-RemoteConnectionManager イベント ID 1149
- TS-LocalSessionManager イベントID21、22、23、24、25

## イベントログ以外のアーティファクト

### 接続元

#### ユーザーがどのワークステーションに RDP 接続したか？

`NTUSER.DAT -> Software\Microsoft\Terminal Server Client\Default -> MRU0`

#### どのターゲットに対してどのユーザーアカウントが使用されたか

`NTUSER.DAT -> Software\Microsoft\Terminal Server Client\Servers\<host>\ -> UsernameHint`

#### ビットマップキャッシュ

`C:\Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache\`

[bmc-tool](https://github.com/anssi-fr/bmc-tools)

```sh
mkdir "C:\Users\DFIRUser\Desktop\bmc-output"

python "C:\Users\DFIRUser\DFIR Tools\bmc-tools\bmc-tools.py" -s "D:\Walkthrough\THM-MKT-WS\uploads\auto\C%3A\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache" -d "C:\Users\DFIRUser\Desktop\bmc-output"
```

[RdpCacheStitcher](https://github.com/BSI-Bund/RdpCacheStitcher) で出力ディレクトリを指定することでタイルをつなぎ合わせることができる。

### Prefetch

mstsc.exe が実行された痕跡を調べる。

```sh
C:\Users\DFIRUser\DFIR Tools\EZ Tools> .\PECmd.exe -d "D:\Walkthrough\THM-MKT-WS\uploads\auto\C%3A\Windows\Prefetch" --csv "C:\Users\DFIRUser\Desktop" --csvf THM-MKT-WS-prefetch.csv
```

## 予防・緩和戦略

https://tryhackme.com/room/rdplateralmovementanalysis?taskNo=7&sharerId=674ed42e2374d1bc93db444c
