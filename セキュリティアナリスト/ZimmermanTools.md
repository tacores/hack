# ZimmermanTools

https://ericzimmerman.github.io/#!index.md

### EvtxECmd

EvtxEcmd は、Windows イベント ログを CSV、 JSON、XML などのさまざまな形式に解析するコマンド ライン ツール。  
出力したファイルは、TimelineExplorer.exe で取り込める。

```ps
# --csvは出力フォルダ、--csvfは出力ファイル名
EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```
