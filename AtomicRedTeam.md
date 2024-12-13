# Atomic Red Team

ヘルプ

```powershell
Get-Help Invoke-Atomictest
```

エミュレートの詳細

```powershell
Invoke-AtomicTest T1566.001 -ShowDetails
```

依存関係が満たされているかをチェック

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1 -CheckPrereq
```

エミュレーションの開始

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1
```

クリーンアップ

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1 -cleanup
```
