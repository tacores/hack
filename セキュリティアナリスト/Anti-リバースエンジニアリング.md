# Anti-リバースエンジニアリング

https://tryhackme.com/room/antireverseengineering

## アンチデバッグ

Windows API の IsDebuggerPresent 関数でデバッガの存在をチェック可能。

### サスペンドスレッド

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread

```c
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD g_dwDebuggerProcessId = -1;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM dwProcessId)
{
    DWORD dwWindowProcessId;
    GetWindowThreadProcessId(hwnd, &dwWindowProcessId);

    if (dwProcessId == dwWindowProcessId)
    {
		int windowTitleSize = GetWindowTextLengthW(hwnd);
		if ( windowTitleSize <= 0 )
		{
			return TRUE;
		}
		wchar_t* windowTitle = (wchar_t*)malloc((windowTitleSize + 1) * sizeof(wchar_t));

        GetWindowTextW(hwnd, windowTitle, windowTitleSize + 1);

		if (wcsstr(windowTitle, L"dbg") != 0 ||
			wcsstr(windowTitle, L"debugger") != 0 )
		{
            g_dwDebuggerProcessId = dwProcessId;
			return FALSE;
		}

       return FALSE;
    }

    return TRUE;
}

DWORD IsDebuggerProcess(DWORD dwProcessId)
{
    EnumWindows(EnumWindowsProc, (LPARAM)dwProcessId);
    return g_dwDebuggerProcessId == dwProcessId;
}

DWORD SuspendDebuggerThread()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
	{
        printf("Failed to create snapshot\n");
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
	{
        printf("Failed to get first thread\n");
        CloseHandle(hSnapshot);
        return 1;
    }

    do
	{
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
        if (hThread != NULL)
		{
            DWORD dwProcessId = GetProcessIdOfThread(hThread);
			if ( IsDebuggerProcess(dwProcessId) )
			{
				printf("Debugger found with pid %i! Suspending!\n", dwProcessId);
				DWORD result = SuspendThread(hThread);
 				if ( result == -1 )
				{
					printf("Last error: %i\n", GetLastError());
				}
			}
            CloseHandle(hThread);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);

    return 0;
}

int main(void)
{
	SuspendDebuggerThread();

	printf("Continuing malicious operation...");
	getchar();
}
```

## アンチ VM

マルウェアは、次のような点で VM かどうかを判断する。

- 実行中プロセス
- インストールされているソフトウェア
- VM 固有の MAC アドレス、ネットワークアドレス
- マシンのリソース（RAM、CPU）
- 周辺機器
- ドメインメンバーシップ
- 特定の命令の実行時間や特定のリソースへのアクセス時間を計測
- Win32_TemperatureProbe による温度測定の可否

## Packer

パッカーは、実行ファイルを圧縮・暗号化するツール。対象となる実行ファイルを圧縮し、ラッパーまたはコンテナとして機能する新しい実行ファイルに埋め込む。これによりファイルサイズが大幅に削減されるため、配布やインストールが容易になる。また、一部のパッカーは、コード難読化、ランタイムパッキング、アンチデバッグ技術などの追加機能を備えている。

- Alternate EXE Packer
- ASPack
- ExeStealth
- hXOR-Packer
- Milfuscator
- MPress
- PELock
- Themida
- UPX: the Ultimate Packer for eXecutables
- VMProtect

### 識別

使用されているパッカーを特定するために、DetectItEasy (DIE) や PEStudio が使える。

DetectItEasy は、既知のパッカーの署名のコレクションを使用して、選択したファイルで使用されているパッカーを識別するツール。

PEStudio では、PE ファイルのセクション名に注目する。（それで必ず特定できるとは限らない）

### アンパック

- Themida
- Enigma Protector
- Mpress unpacker

オンラインサービス

https://www.unpac.me/
