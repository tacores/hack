# AD横方向移動の検出

https://tryhackme.com/room/detectingadlateralmovement

## Recon

### コマンド

```sh
index=win EventCode=1
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

### ScriptBlock

```sh
index=win EventCode=4104
| search Message IN ("*Get-ADUser*", "*Get-ADGroupMember*", "*Get-ADComputer*")
| table _time, Message
| sort _time
```

## SMB

### 5140イベントはネットワーク共有へのアクセス

```sh
index=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time
```

### 特定のユーザーがどの共有にアクセスしたか

```sh
index=win EventCode=5140 user={USER_ACCOUNT}
| table _time, Source_Address, Share_Name, host
| sort _time
```

### 送信元マシンアカウントの特定

```sh
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```

### 特定のホスト(マシンアカウントの$の前の部分)で実行されたプロセス

```sh
index=win EventCode=1 host={SOURCE_HOST} CommandLine="*ADMIN$*"
| table _time, User, Image, CommandLine
| sort _time
```

## PsExec

攻撃者が `net user` により SMB セッションを持っている状態で `PsExec.exe \\target cmd.exe` を実行すると、次のことが起こる。

1. SMB を介してターゲットの ADMIN$ 共有に接続する  
2. サービス用バイナリ（PSEXESVC.exe）をターゲットの C:\Windows ディレクトリにコピーする  
3. ターゲット上に新しい Windows サービスを作成して起動する（System Event 7045）  
4. サービスは stdin / stdout / stderr 通信用の名前付きパイプを作成する（Sysmon Event 17）  
5. サービスは攻撃者が指定したコマンドを実行する  
6. セッション終了時に、サービスを削除しバイナリをクリーンアップする  

### イベント7045はサービスのインストール

```sh
index=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```

注意点として、バイナリ名とサービス名は変更できる。

```sh
PsExec -r renamed_psexec \\target cmd
```

探すべきパターンは、次の両方の値を持つイベント。

- Service_Type = user mode service
- Service_Start_Type = demand start

### PsExec により実行したコマンド

```sh
index=win EventCode=1 host={DESTINATION_HOST} ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

### イベント17はパイプ作成

```sh
index=win EventCode=17 Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
```

### イベント5145は共有を通じてアクセスされた特定のファイルとオブジェクト

```sh
index=win EventCode=5145 host={DESTINATION_HOST} Relative_Target_Name="*PSEXE*"
| table _time, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

### ソース側のプロセス作成

```sh
index=win EventCode=1 host={SOURCE_HOST}
| search Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
```

## RDP

疑わしいコマンドが実行されたというアラートがあったとして、LogonID を調べる。

```sh
index=win EventCode=1 host=THM-DC
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*")
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```

### ログオン種別

10はRDP

```sh
index=win EventCode=4624 host=THM-DC Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
```

### ソースホスト名

```sh
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```

### ソース側のRDP接続の確認

このログオンIDをもとに同様に接続を辿っていく

```sh
index=win EventCode=1 host={SOURCE_SERVER} Image="*mstsc.exe*"
| table _time, User, Image, CommandLine, LogonId
| sort _time
```
