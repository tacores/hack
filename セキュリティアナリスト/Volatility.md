# Volatility

https://tryhackme.com/room/volatility

https://volatilityfoundation.org/

揮発性メモリ ( RAM ) サンプルからデジタル アーティファクトを抽出するための世界で最も広く使用されているフレームワーク。

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

## 例

```shell
# オプション表示
vol -h

# Windowsとメモリの基本情報
vol -f ./Investigation-1.vmem windows.info
```

### プロセスプラグイン

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

### ハンティングと検出

```shell
# コードインジェクション検出
vol -f <file> windows.malfind

# YARAルール
vol -f <file> windows.yarascan --yara-file=<yara file>
```

```shell
# PID指定してメモリダンプ
vol -f <file> windows.memmap.Memmap --pid <pid> --dump

strings foo.dmp | grep User-Agent

# ハンドル
vol -f <file> windows.handles | grep <pid>
```

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
