# Sysmon

https://tryhackme.com/room/sysmon

ダウンロードできる高品質な構成ファイル  
https://github.com/SwiftOnSecurity/sysmon-config

```ps
# 構成ファイルを指定して起動
Sysmon.exe -accepteula -i ..\Configuration\swift.xml
```

sysmon で保存したイベントログは、EventViewr 上、下記の場所に表示される。

```
Applications and Services Logs/Microsoft/Windows/Sysmon/Operational
```

## ベストプラクティス

- include よりも exclude を優先する
- CLI でより細かい制御が可能
- 実装前に環境を把握する

## 設定例

ポート番号（Metasploit）

```xml
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">4444</DestinationPort>
		<DestinationPort condition="is">5555</DestinationPort>
	</NetworkConnect>
</RuleGroup>
```

ファイル作成（mimikatz）  
※普通はこういうことはやらないが、あくまで例として。

```xml
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>
```

lsass.exe プロセスへのアクセス

```xml
<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="image">svchost.exe</SourceImage>
	</ProcessAccess>
	<ProcessAccess onmatch="include">
		<TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
```

レジストリアクセス（永続性）

```xml
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
		<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
		<TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
		<TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
	</RegistryEvent>
</RuleGroup>
```

代替データストリーム

```xml
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
		<TargetFilename condition="contains">Downloads</TargetFilename>
		<TargetFilename condition="contains">Temp\7z</TargetFilename>
		<TargetFilename condition="ends with">.hta</TargetFilename>
		<TargetFilename condition="ends with">.bat</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup>
```
