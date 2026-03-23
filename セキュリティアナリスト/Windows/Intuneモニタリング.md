# Intune モニタリング

https://tryhackme.com/room/msintunemonitoring

Microsoft Intuneは、企業で最も広く使用されているモバイルデバイス管理（MDM）プラットフォームの1つ。

## リモートワイプ

「一括デバイス消去」のイベントを検出したときには既に削除されている状態で手遅れなので、その前段階で異常を検知する必要がある。

管理対象外デバイスからのIntuneログイン

```sh
index=intune sourcetype=azure:aad:signin appDisplayName=*Intune* deviceDetail.displayName=""
| rename deviceDetail.* as dvc.*
| table _time appDisplayName ipAddress dvc.isManaged dvc.isCompliant dvc.displayName user
```

リモートワイパーを検出（ソースタイプはカスタム）

```sh
index=intune sourcetype="o365:graph:intune" wipe
| eval deviceid=mvindex('resources{}.modifiedProperties{}.newValue', 0)
| table _time activityType actor.userPrincipalName deviceid
```

## アプリとスクリプト

プラットフォームスクリプトを検出（ソースタイプはカスタム）

```sh
index=intune sourcetype="o365:graph:intune" activityType=*DeviceManagementScript*
| eval action=mvindex(split(activityType, " "), 0)
| eval script='resources{}.resourceId'
| eval target=mvindex('resources{}.modifiedProperties{}.newValue', 0)
| eval target=if(action="assignDeviceManagementScript", target, "N/A")
| table _time actor.userPrincipalName action script target
````

ホストアーティファクトの例

```ps
C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe
└── C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe
    └── ...\powershell.exe" -NoProfile -executionPolicy bypass -file `
        "C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\<random-uuid>.ps1
```

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log
```


アプリケーションイベントを検出（ソースタイプはカスタム）

```sh
index=intune sourcetype="o365:graph:intune" activityType=*MobileApp*
```
