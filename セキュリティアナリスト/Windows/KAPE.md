# KAPE (Kroll Artifact Parser and Extractor)

https://tryhackme.com/room/kape

https://tryhackme.com/room/kapedatatriage

https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

Windows フォレンジック アーティファクトを解析して抽出するツール。  
インストール無しで使用できる。CLI と GUI がある。

## ターゲットオプション

Targets はシステムまたはイメージから収集し、指定された宛先にコピーする必要がある成果物。

成果物の種類ごとに、Targets フォルダの `*.tkape` ファイルに定義されている。（例：Prefetch.tkape）  
tkape ファイルの Documentaion リンクだけでも情報の宝庫。

### Compound Targets（複合ターゲット）

目的ごとに複数の tkape ファイルが列挙されたもの。  
例えば、実行の証拠のアーティファクトを収集したい場合は、`Compound\EvidenceOfExecution.tkape` があり、その中で `Prefetch.tkape` や `AmCache.tkape` 等が参照されている。

### !Disabled

このディレクトリには、KAPETargets インスタンスに保持したいが、アクティブなターゲット リストには表示したくないものが含まれる。

### !Local

KAPE Github リポジトリと同期したくないものを作成した場合は、このディレクトリに配置できる。  
同様に、 KAPE を 更新したときに Github リポジトリに存在しないものはすべて、このディレクトリに移動される。

## モジュールオプション

提供されたファイル セットに対して特定のツールを実行する。その目的は、ある場所から別の場所にファイルをコピーすることではなく、何らかのコマンドを実行して出力を保存すること。通常、出力は CSV または TXT ファイル形式。

（例）Windows_IPConfig.mkape

```
Processors:
    -
        Executable: C:\Windows\System32\ipconfig.exe
        CommandLine: /all
        ExportFormat: txt
        ExportFile: ipconfig.txt
```

### bin ディレクトリ

システムで実行したいが、ほとんどのシステムにはネイティブに存在しない実行ファイルが含まれる。Eric Zimmerman ツール等。

## gkape.exe

### Target

（例）

```
Target Src：C:\
Target Dest：Desktop\kape
```

- `Flush` を ON にすると、Dest の内容をすべて削除するので注意
- `Add %d` を ON にすると、ディレクトリ名に時刻情報が追加される
- `Add %m` を ON にすると、ディレクトリ名にマシン情報が追加される
- `Process VSCs` ボリュームシャドウコピーを処理するかどうか。（収集した成果物を SFTP サーバーまたは S3 バケット 経由で転送する場合は ON にする。また、その場合はコンテナーを None 以外にする）

### Module

ターゲットとモジュールの両方のオプションを使用する場合、モジュール ソース指定は不要。選択したモジュールは、ターゲットの宛先をソースとして使用する。

## リモート収集方法

https://tryhackme.com/room/kapedatatriage?taskNo=7&sharerId=674ed42e2374d1bc93db444c

```ps
# ターゲットホストを信頼する
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM
```

```ps
# リモートセッションを開く
$cred = New-Object System.Management.Automation.PSCredential(
    "ServiceUser",
    (ConvertTo-SecureString "DcG3w4b8" -AsPlainText -Force)
)
$session = New-PSSession -ComputerName 10.146.155.146 -Credential $cred
```

```ps
# kapeをターゲットにコピー
Copy-Item -Path "C:\Users\DFIRUser\Desktop\DFIR Tools\Artifact Collection\Kape" -Destination "C:\Temp\KAPE" -ToSession $session -Recurse
```

```ps
# kapeを実行
Invoke-Command -Session $session -ScriptBlock {
    C:\Temp\KAPE\kape.exe --tsource C: --tdest "C:\Temp\Out\KAPE Target Output" --tflush --target !SANS_Triage --mdest "C:\Temp\Out\KAPE Module Results" --mflush --module !EZParser --mef csv
}
```

出力フォルダをファイルごとにコピーするのではなく、まずターゲット上で圧縮してから、単一のアーカイブを取得する。

```ps
# 結果の取得
mkdir C:\Evidence

Invoke-Command -Session $session -ScriptBlock {
    Compress-Archive -Path "C:\Temp\Out\*" -DestinationPath "C:\Temp\Out.zip" -Force
}

Copy-Item -Path "C:\Temp\Out.zip" -Destination "C:\Evidence\Target.zip" -FromSession $session

Expand-Archive -Path "C:\Evidence\Target.zip" -DestinationPath "C:\Evidence\Target" -Force
```
