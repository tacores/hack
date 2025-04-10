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

### Amcache Parser

```shell
.\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv
```
