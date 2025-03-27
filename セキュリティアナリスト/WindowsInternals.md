# Windows Internals

## コアプロセス

### System

- システムプロセス (プロセス ID 4) は、カーネルモードでのみ実行される特別な種類のスレッド、つまりカーネル モードシステムスレッドのホーム。
- システムスレッドには、通常のユーザーモードスレッドのすべての属性とコンテキスト (ハードウェアコンテキスト、優先順位など) があるが、システム空間 (Ntoskrnl.exe 内か、その他のロードされたデバイスドライバー内かに関係なく)にロードされたコードを実行するカーネルモードでのみ実行されるという点で異なる。
- さらに、システムスレッドにはユーザープロセスのアドレス空間がないため、ページプールや非ページ プールなどのオペレーティング システム メモリ ヒープから動的ストレージを割り当てる必要がある。

#### ベースライン

- System プロセスの PID は常に 4
- 親プロセスなし
- インスタンスは 1 つだけ
- セッション 0 では実行されない

### smss.exe（セッションマネージャーサブシステム）

- カーネルによって開始される最初のユーザーモードプロセス
- OS 用の分離された Windows セッションであるセッション 0 で csrss.exe (Windows サブシステム) と wininit.exe を起動
- ユーザー セッションであるセッション 1 で csrss.exe と winlogon.exe を起動
- 最初の子インスタンスは、新しいセッションに子インスタンスを作成します。これは、smss.exe が自分自身を新しいセッションにコピーして自己終了することによって行われる。  
  https://en.wikipedia.org/wiki/Session_Manager_Subsystem
- HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems の Required にリストされている他のサブシステムも起動される
- 環境変数、仮想メモリ ページング ファイルの作成、winlogon.exe (Windows ログオン マネージャー) の起動も担当する。

#### ベースライン

- 親プロセスは System(4)
- イメージパスは C:\Windows\System32
- 実行中のプロセスは１つ
- 実行中のユーザーは SYSTEM
- レジストリエントリに予期しない値

### csrss.exe （クライアント サーバー ランタイム プロセス）

https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem

- Windows サブシステムのユーザーモード側
- Win32 コンソール ウィンドウとプロセス スレッドの作成と削除を担当
- Windows API を他のプロセスで利用できるようにしたり、ドライブ文字をマッピングしたり、Windows のシャットダウン プロセスを処理したりする役割も担う。
- 各インスタンスでは、csrsrv. dll、basesrv. dll、winsrv. dll が (他のものと共に) 読み込まれる。

#### ベースライン

- 親プロセスは存在しない（smss.exe はこのプロセスを呼び出して自己終了する）
- イメージパスは C:\Windows\System32
- 実行中のユーザーは SYSTEM

### wininit.exe （Windows 初期化プロセス）

- セッション 0 内で services.exe (サービス コントロール マネージャー)、lsass.exe (ローカル セキュリティ機関)、および lsaiso.exe を起動する役割を担う。
- エンドポイントで Credential Guard が有効になっている場合、lsaiso.exe が実行される。

#### ベースライン

- 親プロセスは存在しない（smss.exe はこのプロセスを呼び出して自己終了する）
- イメージパスは C:\Windows\System32
- インスタンスは１つ
- 実行中のユーザーは SYSTEM

### services.exe （サービス コントロール マネージャー(SCM)）

- システム サービスの処理、つまりサービスの読み込み、サービスとのやり取り、サービスの開始または終了が役割。
- sc.exe で照会できるデータベースを維持する。
- サービスに関する情報は「HKLM\System\CurrentControlSet\Services」に保存される。
- 自動起動としてマークされたデバイスドライバーもメモリにロードされる。
- ユーザーがマシンに正常にログインすると、「HKLM\System\Select\LastKnownGood」の値を CurrentControlSet の値に設定する。
- svchost.exe、spoolsv.exe、msmpeng.exe、dllhost.exe など、他のいくつかの重要なプロセスの親  
  https://en.wikipedia.org/wiki/Service_Control_Manager

#### ベースライン

- 親プロセスは wininit.exe
- イメージパスは C:\Windows\System32
- インスタンスは１つ
- 実行中のユーザーは SYSTEM

### svchost.exe （Windows サービスのホストプロセス）

https://en.wikipedia.org/wiki/Svchost.exe

- このプロセスで実行されるサービスは、DLL として実装される。
- DLL は「HKLM\SYSTEM\CurrentControlSet\Services\（サービス名）\Parameters」の ServiceDLL に保存される。
- -k オプションを使うのが正当な svchost.exe プロセスの呼び出し方法。

```shell
C:\Windows\System32\svchost.exe -k AppReadiness -p
```

- 常に複数インスタンスが存在するため、マルウェアはこのプロセスを装うことがよくある。

#### ベースライン

- 親プロセスは services.exe
- イメージパスは C:\Windows\System32
- -k パラメータが無い

### lsass.exe （ローカルセキュリティ機関サブシステムサービス）

- セキュリティポリシーを適用する役割。
- ログオンするユーザーを検証し、パスワード変更を処理し、アクセストークンを作成する。
- SAM (セキュリティ アカウント マネージャー)、AD (Active Directory)、および NETLOGON のセキュリティ トークンを作成する。
- Windows セキュリティログに書き込む。
- 「HKLM\System\CurrentControlSet\Control\Lsa」で指定された認証パッケージを使用する。
- svchost.exe と同様、このプロセスも攻撃者が装うことが多い。

#### ベースライン

- 親プロセスは wininit.exe
- イメージパスは C:\Windows\System32
- インスタンスは１つ
- 実行中のユーザーは SYSTEM

### winlogon.exe （Windows ログオン）

- Secure Attention Sequence (SAS)の処理を ​ 担当。つまり ALT+CTRL+DELETE の処理。
- ユーザープロファイルの読み込みも担当。ユーザーの NTUSER.DAT を HKCU に読み込み、userinit.exe がユーザーシェルを読み込む。  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc939862(v=technet.10)?redirectedfrom=MSDN
- 画面ロック、スクリーンセーバーを実行する機能も担当。  
  https://en.wikipedia.org/wiki/Winlogon
- smss.exe がセッション 1 内で csrss.exe のコピーとともにこのプロセスを起動する。

#### ベースライン

- 親プロセスは存在しない（smss.exe はこのプロセスを呼び出して自己終了する）
- イメージパスは C:\Windows\System32
- 実行中のユーザーは SYSTEM
- レジストリ内のシェル値は、explorer.exe

### explorer.exe

- ユーザーがフォルダやファイルにアクセスするためのプロセス。
- winlogon.exe が userinit.exe を実行し、「HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell」で指定されたシェルを起動する。
- userinit.exe は explorer.exe を生成した後に終了するため、親プロセスは存在しない。
- 多くの子プロセスが存在する。

#### ベースライン

- 親プロセスは存在しない（userinit.exe はこのプロセスを呼び出して自己終了する）
- イメージパスは C:\Windows
- ユーザー名が疑わしくないこと
- 送信 TCP/IP 接続が無いこと

### その他

- RuntimeBroker.exe
- taskhostw.exe（以前の taskhost.exe と taskhostex.exe）
