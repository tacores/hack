# LSASSメモリダンプの検出

https://tryhackme.com/room/detectinglsassmemorydumping

LSASSダンプに含まれる情報

- ログインしているユーザー（ローカルユーザーとドメインユーザーの両方）のNTハッシュ
- リクエストされたKerberosチケット（TGTおよびサービスチケット）

どんな情報が含まれるかは、klist でおおよそ推測できる。

```sh
klist sessions
```

## ダンプ方法

LSA保護機能とのイタチごっこになるため、数か月単位で新しい方法が出てくる可能性がある。

### 1. procdump

```ps
PS C:> c:\windows\temp\procdump -accepteula -ma lsass.exe C:\windows\temp\lsass
```

### 2. タスクマネージャ

タスクマネージャを管理者として開きLSASSプロセスを右クリックしてメモリダンプ（要GUI）

### 3. comsvc​​s.dll などの LOLBinsバイナリ

https://lolbas-project.github.io/#t1003.001:%20lsass%20memory

```ps
rundll32 C:\windows\system32\comsvcs.dll,MiniDump LSASS_PID lsass.dmp full
```

### 4. Windows API を利用

Mimikatz、PowerSploit、Nanodump、Cobalt Strikeなどの攻撃ツールは、デフォルトでこの方法を使用する。

```ps
# Note: mi.exe is a renamed Mimikatz binary
C:\mi.exe "privilege::debug" "sekurlsa::logonpasswords full" exit >> C:\log.tx
```

## LSASSダンプの検出

### LSASSプロセスアクセスの検出

- Sysmon 10 (ProcessAccess)
- Security 4656 (オブジェクトへのハンドルが要求された)
- `GrantedAccess 0x1FFFFF = PROCESS_ALL_ACCESS` [-> プロセスアクセスマスク](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

[elastic rule repository](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_lsass_memdump_handle_access)

```eql
host.os.type:"windows" and event.code:"4656" and
  (
    winlog.event_data.AccessMask : ("0x1fffff" or "0x1010" or "0x120089" or "0x1F3FFF") or
    winlog.event_data.AccessMaskDescription : ("READ_CONTROL" or "Read from process memory")
  ) and
  winlog.event_data.ObjectType : "Process" and
  winlog.event_data.ObjectName : *\\Windows\\System32\\lsass.exe and
  not winlog.event_data.ProcessName : (
      "C:\Windows\System32\wbem\WmiPrvSE.exe" or
      "C:\Windows\SysWOW64\wbem\WmiPrvSE.exe" or
      "C:\Windows\System32\dllhost.exe" or
      "C:\Windows\System32\svchost.exe" or
      "C:\Windows\System32\msiexec.exe" or
      "C:\Windows\explorer.exe" or
      "C:\\Windows\\Sysmon64.exe" or
      "C:\\Windows\\BTPass\\x64\\BTPassSvc.exe" or
      "C:\\Windows\\Sysmon.exe" or
      "C:\\Windows\\System32\\RtkAudUService64.exe" or
      "C:\\Windows\\System32\\RtkAudUService64.exe" or
       C\:\\Windows\\System32\\DriverStore\\FileRepository\\fn.inf_amd64_*\\driver\\tphkload.exe
  )
```

### プロセス生成による検出

- Sysmon 1
- Security 4688
- PowerShell/Operational Event ID  4104 (ScriptBlock)

ProcDump や comsvc​​s.dll をロードする rundll32 などを確認。ロードするDLLは、コピーして名前変更される可能性があることに注意。

### ファイル作成による検出

- Sysmon 11
- Security 4663

## LSASSダンプの痕跡

- Amcacheの UnassociatedFileEntriesアーティファクトは、ドロップされたバイナリの SHA1 ハッシュを保存する。
- myeasylog.log は、ProcDumpが使用されたことがある痕跡。
- MFT レコードは絶対パスを含む
- USN ジャーナルはファイル履歴

## 耐性強化

### LSA保護（RunAsPPL）

Windows設定画面の「ローカルセキュリティ機関の保護」をONにする。MimikatzやProcdumpは失敗する。

#### レジストリ経由

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` で新しい DWORD 値を作成（RunAsPPL）  
(0 = 無効、1 = 有効、2 = UEFI ロック付きで有効)

#### GPO経由

1. `Computer Configuration > Administrative Templates > System > Local Security Authority`
2. `Configure LSASS to run as a protected process` を有効にする。

### 脆弱なドライバーのブロックリスト

署名済みの脆弱性のあるドライバーをダウンロードし、カーネルにロードして、カーネル空間からLSA保護を改ざんするために悪用する手法を防ぐ。  
Windows 11 22H2 / Server 2022以降、Defenderに統合されている。

### Credential Guard

RunAsPPLがLSASSプロセスがダンプされるのを防ぐのに対し、Credential Guard は LSASSから認証情報を完全に削除する。  
Windows 11 22H2およびWindows Server 2025以降はデフォルトで有効。

ただし、
- ドメインに参加しているマシンでのみ動作します。
- 設計上、ドメインコントローラーでは動作しません。
- Windows Enterprise エディションでのみ利用可能です。
- ハードウェアおよび仮想化に関する前提条件があります。
- 従来のプロトコルやアプリケーションに影響を与える可能性があります
（例えば、Exchange Serverでは動作しません）。
