# Sysinternals

https://learn.microsoft.com/en-us/sysinternals/

https://tryhackme.com/room/btsysinternalssg

起動時に、-accepteula オプションを付けるとソフトウェアライセンス条項に自動的に同意したことになる。

Sysinternals Suite は全体から厳選されたツールのみ含まれる。全体は公式ページ参照。

## Systeinternals Live

Web から直接実行できるサービス。  
ただし、WebDAV クライアントのインストールが必要。

```shell
# 例
\\live.sysinternals.com\tools\procmon.exe
```

## ファイルとディスクユーティリティ

### Sigcheck

https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck

ファイルのバージョン番号、タイムスタンプ情報、証明書チェーンを含むデジタル署名の詳細を表示するコマンドライン ユーティリティ。

```shell
# 署名されていないファイルを確認
sigcheck -u -e C:\Windows\System32
```

### streams

https://learn.microsoft.com/en-us/sysinternals/downloads/streams

Streams は、指定したファイルとディレクトリ (ディレクトリには代替データストリームが存在する場合もあることに注意) を調べ、それらのファイル内で検出された名前付きストリームの名前とサイズを通知する。

```shell
# ファイルに含まれるADSを確認
C:\Users\Administrator\Desktop\file.txt:
         :ads.txt:$DATA 26

# ADSの内容を表示（typeコマンド等では表示できないことに注意）
C:\Users\Administrator\Desktop>notepad file.txt:ads.txt
```

### SDelete

https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete

SDelete は、多数のオプションを取るコマンド ライン ユーティリティ。任意の使用方法で、1 つ以上のファイルやディレクトリを削除したり、論理ディスクの空き領域を消去したりできる。

## ネットワークユーティリティ

https://learn.microsoft.com/en-us/sysinternals/downloads/networking-utilities

### TCPView

TCPView は、ローカル アドレスとリモート アドレス、TCP 接続の状態など、システム上のすべての TCP および UDP エンドポイントの詳細なリストを表示する GUI プログラム。  
Tcpvcon はコマンドラインバージョン。

- 緑フラッグのボタンから表示する状態をフィルタリングできる

## プロセスユーティリティ

### Autoruns

このユーティリティは、あらゆるスタートアップ モニターの自動起動場所に関する最も包括的な知識を備えており、システムの起動時またはログイン時、および Internet Explorer、Explorer、メディア プレーヤーなどのさまざまな組み込み Windows アプリケーションの起動時に実行されるように設定されているプログラムを表示する。

永続化によって作成された悪意のあるエントリを見つけるのに適している。

### ProcDump

アプリケーションの CPU スパイクを監視し、スパイク発生時にクラッシュ ダンプを生成することを主な目的とするコマンド ライン ユーティリティ。

### ProcExp

- プロセス エクスプローラーの表示は 2 つのサブウィンドウで構成される。
- 上部のウィンドウには常に、現在アクティブなプロセスのリストと、そのプロセスを所有するアカウントの名前が表示される。
- 下部のウィンドウに表示される情報は、プロセス エクスプローラーのモードによって異なる。
- ハンドル モードの場合は、上部のウィンドウで選択したプロセスが開いたハンドルが表示され、プロセス エクスプローラーが DLL モードの場合は、プロセスがロードした DLL とメモリ マップ ファイルが表示される。
- ログオン時に実行したり、タスクマネージャと置き換えるオプションがある。

### ProcMon

リアルタイムのファイル システム、レジストリ、プロセス/スレッド アクティビティを表示する Windows 用の高度な監視ツール。

設定ガイド  
https://adamtheautomator.com/procmon/

### PsExec

https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

https://adamtheautomator.com/psexec/

他のシステムでプロセスを実行できる軽量の Telnet 代替品。PsExec の最も強力な用途には、リモート システムで対話型のコマンド プロンプトを起動することや、リモート システムに関する情報を表示できない IpConfig などのリモート対応ツールを起動することなどがある。

## セキュリティユーティリティ

https://learn.microsoft.com/en-us/sysinternals/downloads/security-utilities

### Sysmon

Windows システム サービスおよびデバイス ドライバーであり、システムにインストールされると、システムの再起動後も常駐し、システム アクティビティを監視して Windows イベント ログに記録する。

プロセスの作成、ネットワーク接続、ファイル作成時間の変更に関する詳細な情報を提供する。Windows イベント コレクションまたは SIEM エージェントを使用して生成されたイベントを収集し、その後分析することで、悪意のあるアクティビティや異常なアクティビティを識別し、侵入者やマルウェアがネットワーク上でどのように動作するかを理解できる。

## システム情報

https://learn.microsoft.com/en-us/sysinternals/downloads/system-information

### WinObj

ネイティブ Windows NT API ( NTDLL.DLL によって提供) を使用して NT オブジェクト マネージャーの名前空間にアクセスし、その情報を表示する。

## その他

https://learn.microsoft.com/en-us/sysinternals/downloads/misc-utilities

### BgInfo

https://learn.microsoft.com/en-us/sysinternals/downloads/bginfo

コンピュータ名、IP アドレス、サービス パックのバージョンなど、Windows コンピュータに関する関連情報をデスクトップの背景に自動的に表示する。

### RegJump

レジストリ パスを取得し、そのパスに対して Regedit を開く。ルート キーを標準形式 (例: HKEY_LOCAL_MACHINE) および省略形式 (例: HKLM) で受け入れる。

### Strings

渡されたファイルをスキャンして、デフォルトの長さが 3 文字以上の UNICODE (または ASCII) 文字の UNICODE (または ASCII) 文字列を探す。
