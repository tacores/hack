# 権限昇格検出（DLLハイジャック）

https://tryhackme.com/room/privilegeescalationviadllsoh


## 基礎

### ロード順について

DLLを名前のみでロードする場合、System32 ディレクトリよりも先にアプリケーション自身のディレクトリが検索される。完全修飾パス（フルパス）で指定して要求すると、通常のディレクトリ検索はバイパスされるのでDLLハイジャックは成立しない。

#### 1. セーフDLL検索モード（Safe DLL Search Mode）

セーフDLL検索モードは、次のレジストリ値によって制御される。

`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode`

- 有効な場合（デフォルト）: カレントワーキングディレクトリ（CWD）の検索順位が後ろから2番目（PATHディレクトリの直前）になり、比較的安全。

- 無効な場合（値が 0）: カレントワーキングディレクトリの検索順位がアプリケーションディレクトリの直後に上がる。そのため、攻撃者がプロセスの作業ディレクトリを操作できる環境であれば、任意のプロセスがDLLハイジャックのターゲットになる。

#### 2. KnownDLLs（既知のDLL）

KnownDLLs は、kernel32.dll や ole32.dll といったコアライブラリのリスト。Windowsローダーはディスク内を検索せず、常に System32 から直接これらのライブラリをマッピングする。

Windowsの起動時に、レジストリ `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`  と、それらが静的にインポートするすべてのDLLからリストが構築される。そのため、実際の保護対象はレジストリのリスト単体よりも広範囲になる。

攻撃者は、保護されていない、あまり一般的でない、アプリケーション固有、またはオプショナルなDLLをターゲットにする。

### 攻撃のバリエーション

#### 1. DLL検索順序のハイジャック

最も一般的な方法。正規の名前を装った悪意のあるDLLが、本来のコピーよりも先に検索されるディレクトリ（通常はアプリケーション自身のフォルダ）に配置される。

#### 2. ファントムDLLハイジャック

特権プロセスが、クリーンなシステムには存在しないオプションまたはレガシーDLLを要求すると、通常は検索が失敗する。攻撃者は検索対象の場所にその正確な名前のDLLを配置し、競合する正当なコピーが存在しない状態で成功する。

#### 3. DLLサイドローディング

正規の署名付き実行ファイルと、想定される名前の悪意のあるDLLが一緒にステージングされ、両方とも同じディレクトリに書き込まれた後、署名付き実行ファイルがローダーとして実行される。つまり、署名済みのベンダーバイナリが、インストールされたことのないディレクトリから実行される。

#### 比較表

| **Fingerprint question** | **Search Order Hijacking** | **Phantom Hijacking** | **Side-Loading** |
| :--- | :--- | :--- | :--- |
| System32 に正規の同名ファイルが存在するか？ | はい。System32 に同じ名前の署名済みファイルが存在する | いいえ。クリーンなシステムにはその名前のファイルが存在しない | 決定的な判断材料ではない。悪用された名前のファイルが System32 に存在する場合と存在しない場合がある。見分けるポイントは、本来の場所から外れたローダー EXE |
| DLL はどこから読み込まれるか？ | アプリケーションまたはサービスのインストールディレクトリ（System32 より先に検索される場所） | 本来その名前のファイルが存在しない、DLL の検索対象ディレクトリ | 攻撃者が制御するステージングディレクトリ |
| DLL を読み込むアプリケーション／サービスは本来の場所にあるか？ | はい。通常の場所にインストールされた EXE | はい。通常の場所にインストールされたサービスホスト | いいえ。本来とは異なるディレクトリに配置された署名済みのベンダー製 EXE |
| DLL に対する Sysmon Event ID 7 の Signed | `false` | `false` | `false`（ただし、DLL を読み込む EXE には署名がある） |
| 判断の目安 | 悪意のある DLL が、実在する正規の System32 内の同名ファイルを横取りする | 悪意のある DLL が、本来存在しない名前の DLL として読み込まれる | 署名済みの正規 EXE と未署名 DLL が、EXE の本来のインストール先以外の場所に一緒に配置されている |

## イベントログ

### Sysmon

- Sysmon 7 イメージの読み込み
- Sysmon 11 ファイル作成
- Sysmon 22 DNSクエリ

## アーティファクト

### ファイル作成履歴

MFT、USNジャーナル

### サービスレジストリ

```ps
RECmd.exe -f 'D:\Logs\uploads\auto\C%3A\Windows\System32\config\SYSTEM' --kn "ControlSet001\Services\CheckMkService"
```

### 実行証拠

Amcache、Shimcache、Prefetch

### メモリ

```ps
$mem = 'D:\Memory\THM-DEV-WS-C.73616be6c212b784-F.D9HSTKT184OC0\uploads\auto\PhysicalMemory.dd'

volatility.exe -f $mem windows.pslist

volatility.exe -f $mem windows.malware.ldrmodules.LdrModules | Select-String secur32

volatility.exe -f $mem windows.mftscan.MFTScan | Select-String secur32

volatility.exe -f $mem windows.malware.ldrmodules.LdrModules | Select-String wptsextensions

volatility.exe -f $mem windows.mftscan.MFTScan | Select-String 'mpclient|mpcmdrun'

volatility.exe -f $mem windows.getsids --pid 6080
```

## 封じ込め、回避、軽減

https://tryhackme.com/room/privilegeescalationviadllsoh?taskNo=6&sharerId=674ed42e2374d1bc93db444c
