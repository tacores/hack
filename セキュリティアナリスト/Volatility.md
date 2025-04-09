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
```

```shell
# PID指定してメモリダンプ
vol -f <file> windows.memmap.Memmap --pid <pid> --dump

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
