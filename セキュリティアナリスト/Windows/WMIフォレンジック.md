# WMIフォレンジック

https://netsecninja.github.io/dfir-notes/wmi-forensics/

## 一例

https://tryhackme.com/room/hh-afterhours-b090d1f0/congratulations?step=records

https://www.youtube.com/watch?v=0Kn_lToGcNA

```sh
strings -a ./OBJECTS.DATA > strings-ascii.txt
strings -a -el ./OBJECTS.DATA > strings-utf16.txt

grep -Ei '__EventFilter|FilterToConsumerBinding|CommandLineEventConsumer|ActiveScriptEventConsumer|CommandLineTemplate|ScriptText|powershell|cmd\.exe|wscript|base64|https?://' strings-*.txt
```

```sh
grep -C3 'Win32_HardwareTelemetry' ./strings-*.txt
```

Base64デコード、Raw Infrate で exe 保存。  
[ILSpy](https://github.com/icsharpcode/ILSpy/releases) で逆コンパイル。
