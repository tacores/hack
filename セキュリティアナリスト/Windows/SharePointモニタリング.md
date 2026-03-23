# SharePoint モニタリング

https://tryhackme.com/room/sharepointonlinemonitoring

## データ漏洩

ファイル共有のリンクが作成されたイベント

```sh
index=* Workload=SharePoint Operation IN(AddedToSecureLink, AnonymousLinkCreated)
```

リンクが使われたイベント

```sh
index=* Workload=SharePoint Operation IN(SecureLinkUsed, AnonymousLinkUsed)
```

rclone を使ったダウンロード

```sh
index=* rclone Operation=FileDownloaded
| table _time UserId Operation ApplicationDisplayName ApplicationId UserAgent
```

## 不正利用

悪意のあるファイルがアップロードされて、外部にメール共有されたという想定。

アップロードしたユーザーIDの特定

```sh
index=m365 Operation IN(FileUploaded, FileCreated) ObjectId=*BADFILE*
| table _time UserId Operation ObjectId
```

共有されたユーザーの特定

```sh
index=m365 Operation IN(AddedToSecureLink, SharingSet) ObjectId=*BADFILE*
| table _time UserId TargetUserOrGroupName ObjectId
```

実際にメールを開いたユーザーの特定

```sh
index=m365 Operation IN(*LinkUsed, FileAccessed) ObjectId=*BADFILE*
| stats values(UserId)
```
