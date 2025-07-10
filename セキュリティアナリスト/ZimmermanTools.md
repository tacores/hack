# ZimmermanTools

https://ericzimmerman.github.io/#!index.md

### Timeline Explorer

他のツールで出力した様々な CSV ファイルを時系列で表示する GUI ツール。

### EvtxECmd

Windows イベントログの解析

```ps
# --csvは出力フォルダ、--csvfは出力ファイル名
EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```

```ps
C:\Tools\EvtxECmd\EvtxECmd.exe -f C:\Windows\System32\winevt\Logs\Security.evtx --inc 4624,4625 --csv .
```

### LECmd

リンクファイルの解析

```shell
# リンクファイルを解析してCSV出力する
.\LECmd.exe -d C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent --csvf Parsed-LNK.csv --csv C:\Users\Administrator\Desktop
```

### PECmd

プリフェッチファイルの解析

```shell
.\PECmd.exe -d "C:\Windows\Prefetch" --csv C:\Users\Administrator\Desktop --csvf Prefetch-Parsed.csv
```

### MFTECmd

NTFS ファイルシステム情報抽出

```sh
# MFTファイルから情報抽出（MFTファイルはFTK Imagerでエクスポートできる）
MFTECmd.exe -f ..\Evidence\$MFT --csv ..\Evidence --csvf ..\Evidence\MFT_record.csv

# USNジャーナル
MFTECmd.exe -f ..\Evidence\$J --csv ..\Evidence --csvf USNJrnl.csv

# $I30
MFTECmd.exe -f ..\Evidence\$I30 --csv ..\Evidence\ --csvf i30.csv
```

### Amcache Parser

```shell
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv
```

### AppCompatCacheParser

```shell
C:\Tools\AppCompatCacheParser\AppCompatCacheParser.exe --csv .
```