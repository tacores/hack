# Volatility

https://tryhackme.com/room/volatility

https://volatilityfoundation.org/

揮発性メモリ ( RAM ) サンプルからデジタル アーティファクトを抽出するための世界で最も広く使用されているフレームワーク。

Volatility2 と Volatility3 がある。Volatility2 は手動でプロファイルを指定する必要があるという欠点はあるものの、現状では Volatility2 の方が安定度、プラグインの種類ともに優れていて使い勝手が良い。

このページで、vol というコマンドが使われているときは Volatility3、volatility というコマンドが使われているときは volatility2 を意味している。

## メモリ抽出ツール

多くの場合（Redline 以外）、.raw ファイルで出力される

- FTK Imager
- Redline
- DumpIt.exe
- win32dd.exe / win64dd.exe
- Memoryze
- FastDump

### VM

- VMWare - .vmem
- Hyper-V - .bin
- Parallels - .mem
- VirtualBox - .sav file \*this is only a partial memory file

## install

```sh
pip install volatility3
```

## 例

```shell
# オプション表示
vol -h

# Windowsとメモリの基本情報
vol -f ./Investigation-1.vmem windows.info
```

### プロセスプラグイン

https://volatility3.readthedocs.io/en/stable/volatility3.plugins.html

```shell
# プロセスリスト
vol -f <file> windows.pslist

# ルートキットによる回避対策になるが誤検知の可能性もある
vol -f <file> windows.psscan

# 親プロセスを考慮
vol -f <file> windows.pstree

# ネットワーク
vol -f <file> windows.netstat

# DLL
vol -f <file> windows.dlllist
```

netstat は不安定なので、bulk-extractor で pcap を抽出することも考慮。  
https://www.kali.org/tools/bulk-extractor/

```shell
# パスワードハッシュ
vol -f <file> windows.hashdump
```

### ハンティングと検出

```shell
# コードインジェクション検出
vol -f <file> windows.malfind

# YARAルール
vol -f <file> windows.yarascan --yara-file=<yara file>

# 仮想メモリ記述子の詳細情報を表示し、疑わしいメモリ領域やヒープ割り当てを調査
vol -f <file> windows.vadinfo
```

コードインジェクションの特徴として、`PAGE_EXECUTE_READWRITE` と `VadS or VadX` の組み合わせは疑わしいプロセスとして注目すべき。

```sh
$ cat vadinfo | grep -i EXECUTE_READ       
1860    explorer.exe    0xfffffa80033286e0      0x3ee0000       0x3ee0fff       VadS    PAGE_EXECUTE_READWRITE  1       1       0xfa80032b33e0  N/A     Disabled
1860    explorer.exe    0xfffffa8002fe72c0      0x3f90000       0x400ffff       VadS    PAGE_EXECUTE_READWRITE  2       1       0xfa8003329e00  N/A     Disabled
1820    svchost.exe     0xfffffa800136b1e0      0x24f0000       0x256ffff       VadS    PAGE_EXECUTE_READWRITE  128     1       0xfa800136b230  N/A     Disabled
1820    svchost.exe     0xfffffa800136b190      0x4d90000       0x4e8ffff       VadS    PAGE_EXECUTE_READWRITE  256     1       0xfa800136b010  N/A     Disabled
2464    wmpnetwk.exe    0xfffffa8002f1cda0      0x280000        0x28ffff        VadS    PAGE_EXECUTE_READWRITE  16      1       0xfa80033cf8c0  N/A     Disabled
```

#### メモリダンプ

```shell
# PID指定してメモリダンプ
vol -f <file> windows.memmap.Memmap --pid <pid> --dump

# この他にも環境変数なども含まれる
strings foo.dmp | grep User-Agent

# ハンドル
vol -f <file> windows.handles | grep <pid>
```

ちなみに、pid 抽出前のメモリイメージに対して strings を実行するのも有効。

## 高度なフォレンジック

マルウェアが使用する回避テクニック

### Hooking

- SSDT フック
- IRP フック
- IAT フック
- EAT フック
- インラインフック

```shell
vol -f <file> windows.ssdt
```

### ドライバーファイル

```shell
vol -f <file> windows.modules

vol -f <file> windows.driverscan
```

その他

- modscan
- driverirp
- callbacks
- idt
- apihooks
- moddump
- handles

## Volatility2

古いバージョンだが、プラグインが 3 よりも豊富で使い勝手が良い。

### インストール

```shell
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip

unzip ./volatility_2.6_lin64_standalone.zip

sudo cp ./volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone /usr/local/bin/volatility

sudo chmod +rx /usr/local/bin/volatility
```

```shell
# プラグインリスト等を表示
volatility --info

# イメージの情報（推奨プロファイル等を確認できる）
volatility -f <file> imageinfo
```

```shell
# シャットダウン時刻
volatility -f <file> --profile Win7SP1x64 shutdowntime

# コマンド履歴などが出る（かもしれない）
volatility -f <file> --profile Win7SP1x64 consoles

# truecrypt パスフレーズ
volatility -f <file> truecryptpassphrase --profile Win7SP1x64
```

## Windows

https://tryhackme.com/room/windowsmemoryandprocs

### プロセスとスレッドの構造

| 名前     | モード         | 説明                                             |
| -------- | -------------- | ------------------------------------------------ |
| EPROCESS | カーネルモード | プロセスに関する情報を保持する構造体             |
| ETHREAD  | カーネルモード | スレッドに関する情報を保持する構造体             |
| PEB      | ユーザーモード | プロセスの基本情報を格納するユーザーモード構造体 |
| TEB      | ユーザーモード | スレッド固有の情報を格納する構造体               |

- EPROCESS には PEB へのポインタが含まれている
- ETHREAD には TEB へのポインタが含まれている
- TEB には PEB への冗長ポインタが含まれている

### EPROCESS から情報を抽出するプラグイン

```
pslist, pstree, psscan, malfind, getsids, handles, dlllist, cmdline, envars, ldrmodules
```

全部ではない。抜粋。以下同様。

```c
struct _EPROCESS {
    HANDLE UniqueProcessId; // PID (Process ID)
    LIST_ENTRY ActiveProcessLinks; // Link in active process list (Used to keep track of all active processes)
    UCHAR ImageFileName[15]; // Short process name LARGE_INTEGER CreateTime; // Process creation time
    LARGE_INTEGER ExitTime; // Exit time if terminated
    PPEB Peb; // Pointer to user-mode PEB
    HANDLE InheritedFromUniqueProcessId; // Parent PID
    LIST_ENTRY ThreadListHead; // List of ETHREADs
    PHANDLE_TABLE ObjectTable; // Handle table (points to opened files)
    PVOID SectionObject; // Executable image mapping
    PVOID VadRoot; // VAD tree for memory mapping PACCESS_TOKEN Token; // Security information
}
```

### ファイル

#### ファイルハンドル

```sh
vol -f THM-WIN-001_071528_07052025.mem windows.handles > handles.txt
```

#### ファイルオブジェクト

```c
typedef struct _SECTION_OBJECT_POINTERS {
  PVOID DataSectionObject;
  PVOID SharedCacheMap;
  PVOID ImageSectionObject;
} SECTION_OBJECT_POINTERS;
```

```sh
# ファイルオブジェクトダンプ
vol -f THM-WIN-001_071528_07052025.mem -o 5252/ windows.dumpfiles --pid 5252
```

### ETHREAD から情報を抽出するプラグイン

```
threads, ldrmodules, apihooks, malfind
```

```c
struct _ETHREAD {
    CLIENT_ID Cid; // Thread and Process IDs
    LARGE_INTEGER CreateTime; // Thread creation time
    LARGE_INTEGER ExitTime; // Thread exit time
    PVOID StartAddress; // Kernel-level entry point
    PVOID Win32StartAddress; // User-mode entry point
    LIST_ENTRY ThreadListEntry; // Link in EPROCESS's thread list
    PTEB Teb; // Pointer to TEB
    ULONG ThreadState; // Thread execution state
    ULONG WaitReason; // Reason for being blocked
}
```

### PEB から情報を抽出するプラグイン

```
cmdline, envars, ldrmodules, malfind
```

```c
struct _PEB {
    BOOLEAN BeingDebugged; // Debug flag
    PVOID ImageBaseAddress; // Base address of executable
    PPEB_LDR_DATA Ldr; // Loader data (DLLs)
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;// Command-line, environment variables
    ULONG NtGlobalFlag; // Debugging heap flags
    PVOID ProcessHeap; // Default process heap
}

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine; // This is the string it reads
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

```sh
vol -f THM-WIN-001_071528_07052025.mem windows.cmdline  > cmdline.txt
```

### TEB から情報を抽出するプラグイン

```
threads, malfind
```

```c
struct _TEB {
    PVOID EnvironmentPointer; // Pointer to env block
    CLIENT_ID ClientId; // Thread + Process IDs
    PVOID ThreadLocalStoragePointer; // TLS base
    PPEB ProcessEnvironmentBlock; // Pointer to PEB
    ULONG LastErrorValue; // Last error value
    PVOID StackBase; // Upper bound of thread stack
    PVOID StackLimit; // Lower bound of thread stack
    PVOID Win32ThreadInfo; // GUI subsystem data
}
```

### SESSION から情報を抽出するプラグイン

```
sessions, Voltage
```

セッション ID、ユーザー SID、ログオンの種類（コンソール、RDP など）、ログオンタイムスタンプといった詳細情報を抽出

```c
  struct SESSION{
  ACTION    act;
  HFILELIST hflist;
  BOOL      fAllCabinets;
  BOOL      fOverwrite;
  BOOL      fNoLineFeed;
  BOOL      fSelfExtract;
  long      cbSelfExtractSize;
  long      cbSelfExtractSize;
  int       ahfSelf[cMAX_CAB_FILE_OPEN];
  int       cErrors;
  HFDI      hfdi;
  ERF       erf;
  long      cFiles;
  long      cbTotalBytes;
  PERROR    perr;
  SPILLERR  se;
  long      cbSpill;
  char      achSelf[cbFILE_NAME_MAX];
  char      achMsg[cbMAX_LINE*2];
  char      achLine;
  char      achLocation;
  char      achFile;
  char      achDest;
  char      achCabPath;
  BOOL      fContinuationCabinet;
  BOOL      fShowReserveInfo;
  BOOL      fNextCabCalled;
  CABINET   acab[2];
  char      achZap[cbFILE_NAME_MAX];
  char      achCabinetFile[cbFILE_NAME_MAX];
  int       cArgv;
  char      **pArgv;
  int       fDestructive;
  USHORT    iCurrentFolder;
} SESSION, *PSESSION;
```

```sh
vol -f THM-WIN-001_071528_07052025.mem windows.sessions > sessions.txt
```

### レジストリ

```sh
vol -f THM-WIN-001_071528_07052025.mem windows.registry.hivelist > hivelist.txt

# Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
# 各エントリはROT13エンコードされており、アプリケーションパス、実行カウンタ、最終起動時のタイムスタンプなどの詳細が含まれる。
vol -f THM-WIN-001_071528_07052025.mem windows.registry.userassist > userassist.txt
```

hivelistからレジストリを読む

```sh
$ cat hivelist.txt
Volatility 3 Framework 2.27.0

Offset  FileFullPath    File output

0xf8a00000f010          Disabled
0xf8a000024010  \REGISTRY\MACHINE\SYSTEM        Disabled
0xf8a00004e1f0  \REGISTRY\MACHINE\HARDWARE      Disabled
0xf8a00078b010  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xf8a000a91010  \SystemRoot\System32\Config\SECURITY    Disabled
0xf8a000afd010  \SystemRoot\System32\Config\SAM Disabled
0xf8a000b2e410  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT        Disabled
0xf8a000c28010  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT  Disabled
0xf8a000fe7010  \??\C:\Users\victim\ntuser.dat  Disabled
0xf8a00104e010  \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat        Disabled
0xf8a002044010  \??\C:\System Volume Information\Syscache.hve   Disabled
0xf8a003b4e410  \SystemRoot\System32\Config\DEFAULT     Disabled
0xf8a0051bf010  \Device\HarddiskVolume1\Boot\BCD        Disabled
```

例として次のような出力があった場合、

```sh
$ vol -f victim.raw windows.registry.printkey --offset 0xf8a00104e010 --key "Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
Volatility 3 Framework 2.27.0
Progress:  100.00               PDB scanning finished                        
Last Write Time Hive Offset     Type    Key     Name    Data    Volatile

2019-04-27 10:34:04.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 0       N/A     False
2019-05-02 06:57:13.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 1       N/A     False
2019-04-13 05:57:11.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 2       N/A     False
2019-04-13 07:40:16.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 3       N/A     False
2019-04-13 07:46:43.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 4       N/A     False
2019-04-23 06:54:48.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 5       N/A     False
2019-05-02 06:53:38.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU 6       N/A     False
...
```

このように階層を深堀していって値にたどり着くことができる。

```sh
$ vol -f victim.raw windows.registry.printkey --offset 0xf8a00104e010 --key "Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0"
Volatility 3 Framework 2.27.0
Progress:  100.00               PDB scanning finished                        
Last Write Time Hive Offset     Type    Key     Name    Data    Volatile

2019-04-27 10:48:33.000000 UTC  0xf8a00104e010  Key     \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0   0       N/A     False
2019-04-27 10:48:33.000000 UTC  0xf8a00104e010  REG_DWORD       \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0   NodeSlot        64      False
2019-04-27 10:48:33.000000 UTC  0xf8a00104e010  REG_BINARY      \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0   MRUListEx
00 00 00 00 ff ff ff ff                         ........                False
2019-04-27 10:48:33.000000 UTC  0xf8a00104e010  REG_BINARY      \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0   0
64 00 31 00 00 00 00 00 9b 4e cd 53 10 20 64 65 d.1......N.S. de
6c 65 74 65 64 5f 66 69 6c 65 73 00 48 00 08 00 leted_files.H...
04 00 ef be 9b 4e cc 54 9b 4e cc 54 2a 00 00 00 .....N.T.N.T*...
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00 00 00 00 00 00 64 00 65 00 6c 00 65 00 74 00 ......d.e.l.e.t.
65 00 64 00 5f 00 66 00 69 00 6c 00 65 00 73 00 e.d._.f.i.l.e.s.
00 00 1c 00 00 00                               ......                  False
```

### ネットワーク

https://tryhackme.com/room/windowsmemoryandnetwork

```sh
# ソケットオブジェクトの痕跡（既に閉じている場合でも機能する）
vol -f THM-WIN-001_071528_07052025.mem windows.netscan >  netscan.txt

grep ESTABLISHED netscan.txt

grep LISTENING netscan.txt
```

一般的な Windows ポートと比較する。  
https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements

### 分析手法

#### ベースラインのプロセスリストと種類を比較する

```sh
awk 'NR >3{print $2}' baseline/baseline.txt | sort | uniq > baseline_procs.txt
awk 'NR >3{print $3}' pslist.txt | sort | uniq > current_procs.txt

# current_procs.txt にしか含まれないプロセスを表示
comm -13 baseline_procs.txt current_procs.txt
```

#### アクティブリストに含まれていないプロセスを発見する

```sh
# アクティブリストに含まれていないプロセスを含める
vol3 -f THM-WIN-001_071528_07052025.mem windows.psscan > psscan.txt

awk '{print $1,$3}' pslist.txt | sort > pslist_processed.txt
awk '{print $1,$3}' psscan.txt | sort > psscan_processed.txt

# psscan.txt にのみ含まれるプロセスを表示
comm -23 psscan_processed.txt pslist_processed.txt
```

その後、

- image のパスを確認
- このプロセスにロードされた DLL を確認
- プロセスにアクティブなスレッドが残っているかどうかを確認。アクティブなスレッドがあるにもかかわらず pslist 結果に表示されない場合は、疑わしい状況。
- アクティブなプロセスにスレッドが 1 つもない場合は、疑わしいプロセスとみなされる。すべてのアクティブなプロセスには少なくとも 1 つのスレッドが必要。
- Exit Time を確認。プロセスが実際に終了している場合は、 Exit Time が表示される。そのプロセスにリンクされたアクティブなスレッドや孤立したスレッドがまだ残っている場合は、疑わしい状況。
- プロセスメモリをダンプしてさらに分析する

上記のチェックを、psxview で一度に実行することもできる。

```sh
vol3 -f THM-WIN-001_071528_07052025.mem windows.psxview > psxview.txt

# 3行目（ヘッダー）と、pllist が false の行のみ表示
awk 'NR==3 || $4 == "False"' psxview.txt
Offset(Virtual) Name            PID     pslist  psscan  thrdscan  csrss   Exit Time
0xac80001ca080  svchost.exe     5828    False   True    False     False
0xac8000083080  svchost.exe     5592    False   True    False     False
0xac80000b90c0  vmtoolsd.exe    9040    False   True    False     False
0xac8000084080  svchost.exe     5748    False   True    False     False
0xac80001c6080  svchost.exe     5908    False   True    False     False
0xac80001d2080  ctfmon.exe      5972    False   True    False     False
0xac8000030080  svchost.exe     5736    False   True    False     False
0xac80000a1080  sihost.exe      5548    False   True    False     False
0x990b29bef080  svchost.exe     8708    False   True    False     False   2025-05-07 07:13:16+00:00
0xac8000031080  taskhostw.exe   5752    False   True    False     False
```

### プロセスダンプ

```sh
# プロセスイメージと、DLLのパス等を確認できる
vol3 -f THM-WIN-001_071528_07052025.mem windows.dlllist --pid 5252 > 5252_dlllist.txt

cat 5252_dlllist.txt
```

```sh
# プロセスメモリのダンプ
mkdir 5252
cd 5252
vol3 -f ../THM-WIN-001_071528_07052025.mem windows.dumpfiles --pid 5252
```

2 種類のファイルが大量に生成される。

- file.StartAddress.EndAddress.ImageSectionObject.filename.img
- file.StartAddress.EndAddress.DataSectionObject.filename.dat

前者は exe や dll ファイル、後者は構成、ログ、展開されたペイロードなど。

```sh
# Word のマクロファイルを見つける
ubuntu@tryhackme:~/5252$ ls | grep -E ".docm|.dotm" -i
file.0x990b2ae077d0.0x990b2a3f5d70.SharedCacheMap.Normal.dotm.vacb
file.0x990b2ae077d0.0x990b2b916cd0.DataSectionObject.Normal.dotm.dat
file.0x990b2ae0ab60.0x990b28043a00.SharedCacheMap.cv-resume-test.docm.vacb
file.0x990b2ae0ab60.0x990b2a8b4b30.DataSectionObject.cv-resume-test.docm.dat

# 実行可能ファイルを見つける
ls 3392 10084 10032 | grep -E ".exe|.dat" -i
```

## Linux

https://tryhackme.com/room/linuxmemoryanalysis

| 機能                      | Linux                                                                                          | Windows                                            |
| ------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| スワップ管理              | スワップパーティションまたはスワップファイルを設定可能                                         | ページファイル（pagefile.sys）を使用               |
| プロセスのメモリ構造      | `/proc/<pid>/maps` でメモリ領域を確認可能。スタック、ヒープ、mmap などに分かれている           | 各プロセスに対して VAD（仮想アドレス記述子）を使用 |
| カーネル/ユーザ領域の分離 | （32 ビット環境で）3GB/1GB または 2GB/2GB に分離。カーネルとユーザメモリは厳密に分離されている | 同様に分離されているが、異なるページング構造を使用 |
| 使用ツール                | `top`、`free`、`vmstat`、`/proc` ディレクトリなど                                              | タスクマネージャー、RAMMap、WinDbg など            |

### /proc 疑似ファイルシステム

- `/proc/<pid>/cmdline` コマンドライン引数を提供します。
- `/proc/<pid>/statusUID` メモリ使用量、スレッド数などのメタデータを表示します。
- `/proc/<pid>/exe` 実行されたバイナリへのシンボリックリンクです。
- `/proc/<pid>/maps` メモリレイアウトを明らかにします。
- `/proc/<pid>/fd/` 開いているファイル記述子を一覧表示します。

### プラグイン

```sh
# Linuxプラグイン
vol3 --help | grep linux
```

Volatility 3 では、メモリダンプの構造を理解するために OS のシンボルテーブルが必要。

```sh
# Linuxバナーを識別
vol3 -f FS-01.mem banners.Banners
```

### プロセス

```sh
# プロセス一覧
vol3 -f FS-01.mem linux.pslist.PsList > ps_output

# PsList が見逃した隠しプロセスを取得できる可能性がある
vol3 -f FS-01.mem linux.pslist.PsList > ps_output

# 引数を表示
vol3 -f FS-01.mem linux.psaux.PsAux

# メモリマッピング
vol3 -f FS-01.mem linux.proc.Maps
```

### ネットワーク

```sh
# IPアドレスとインターフェイス
vol3 -f FS-01.mem linux.ip.Addr

# ネットワークインターフェイス情報
vol3 -f FS-01.mem linux.ip.Link

# ソケットの詳細
vol3 -f FS-01.mem linux.sockstat.Sockstat
```

### ヒストリー

```sh
# Bashの履歴
vol3 -f FS-01.mem linux.bash.Bash

# 環境変数
vol3 -f FS-01.mem linux.envars.Envars
```
