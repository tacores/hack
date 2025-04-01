# Windows フォレンジック１（レジストリ）

https://tryhackme.com/room/windowsforensics1

どの Windows システムにも、5 つのルートキーが含まれる。

1. HKEY_CURRENT_USER
1. HKEY_USERS
1. HKEY_LOCAL_MACHINE
1. HKEY_CLASSES_ROOT
1. HKEY_CURRENT_CONFIG

`HKEY_CLASSES_ROOT` は、`HKEY_LOCAL_MACHINE\Software\Classes` と `HKEY_CURRENT_USER\Software\Classes` をマージしたビュー。

## オフライン

ディスクイメージにしかアクセスできない場合にアクセスするファイル

`C:\Windows\System32\Config`

1. DEFAULT (mounted on HKEY_USERS\DEFAULT)
1. SAM (mounted on HKEY_LOCAL_MACHINE\SAM)
1. SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)
1. SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)
1. SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)

### ユーザー情報を含むハイブ

1. `C:\Users\<username>\NTUSER.DAT`  
   (ユーザーがログインすると HKEY_CURRENT_USER にマウント)
1. `C:\Users\<username>\AppData\Local\Microsoft\Windows\USRCLASS.DAT`  
   (HKEY_CURRENT_USER\Software\CLASSES にマウント)

### AmCache

システムで最近実行されたプログラムに関する情報を保存

`C:\Windows\AppCompat\Programs\Amcache.hve`

### トランザクションログ

- トランザクションログは、レジストリハイブの変更ログのジャーナル。
- トランザクションログには、レジストリハイブ自体には反映されていないレジストリの最新の変更が含まれることがよくある。
- 各ハイブのトランザクション ログは、ハイブ自体と同じディレクトリに .LOG ファイルとして保存される。
- トランザクション ログが複数ある場合もある。その場合、拡張子は .LOG1、.LOG2 などになる。

### バックアップ

- `C:\Windows\System32\Config` にあるレジストリファイルのバックアップ。
- 10 日ごとに `C:\Windows\System32\Config\RegBack` ディレクトリにコピーされる。
- Windows10 以降では、デフォルトで OFF になっている。

```shell
# バックアップをONにするコマンド
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 1 /f
shutdown /r /t 0
```

## 収集ツール

レジストリファイルは通常の方法ではコピーできないためツールを使う。

### KAPE

https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

### Autospy

https://www.autopsy.com/

### FTK Imager

https://www.exterro.com/digital-forensics-software/ftk-imager-temp

## 調査ツール

レジストリエディタはライブシステムでのみ機能するため、保存したレジストリを調査するにはツールが必要。

### Zimmerman's Registry Explorer

https://ericzimmerman.github.io/#!index.md

### RegRipper

https://github.com/keydet89/RegRipper3.0

## レジストリ情報

### OS バージョン

`SOFTWARE\Microsoft\Windows NT\CurrentVersion`

### コントロールセット

マシンの起動に使用されたコントロールセット  
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001`  
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002`

`HKEY_LOCAL_MACHINE\SYSTEM\Select` を見ると、現在の設定や Last Known Good などが分かる。

`HKLM\SYSTEM\CurrentControlSet` は揮発性だが最も正確な情報になる。

### コンピューター名

`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName  `

### タイムゾーン

`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`

### ネットワークインターフェイスと過去のネットワーク

ネットワークインターフェイス一覧  
`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

過去に接続されていたネットワーク  
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`  
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`

### 自動起動

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### サービス

`SYSTEM\CurrentControlSet\Services`

※ start キーが 0x02 に設定されている場合、自動起動に設定されている。

### SAM ハイブとユーザー情報

`SAM\Domains\Account\Users`

### 最近開いたファイル

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

拡張子ごとに最後に開いたファイルが管理される。  
（例）最後に開いた PDF
`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`

Office365  
`NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU`

### エクスプローラー履歴

- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`
- `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`

### ファイル名を指定して実行

Powershell や cmd の履歴が残っている可能性がある

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

### 共有フォルダ

- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`

### Last Visited

「保存」や「開く」でアプリケーションごとに記憶しているフォルダ

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

### エクスプローラーのアドレス、検索バー

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

### User Assists

ユーザーがエクスプローラーで起動したアプリケーションの履歴
`NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`

### Shim Cache

OS とのアプリケーションの互換性を追跡するために使用されるメカニズム。詳細は THM 参照。  
`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

### AmCache

最後に実行されたプログラム  
`Amcache.hve\Root\File\{Volume GUID}\`

### BAM/DAM

バックグラウンド アクティビティ モニター (BAM) は、バックグラウンド アプリケーションのアクティビティを監視する。  
デスクトップ アクティビティ モデレーター (DAM) は、、デバイスの電力消費を最適化する Microsoft Windows の一部。

`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`  
`SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`

## 外部デバイス

### システムに接続された USB キー

`SYSTEM\CurrentControlSet\Enum\USBSTOR`  
`SYSTEM\CurrentControlSet\Enum\USB`

### デバイスが最初に接続された時刻、最後に接続された時刻、システムから最後に削除された時刻

`SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####`

- 0064 初回接続時間
- 00066 最終接続時間
- 0067 最終削除時間

### 接続されているデバイスのボリューム名

`SOFTWARE\Microsoft\Windows Portable Devices\Devices`
