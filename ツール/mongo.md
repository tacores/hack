# mongo

CTFでは単に `mongo`とコマンド実行すると接続されることが多い。

DB選択

```sh
> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB

> use backup
```

テーブル一覧

```sh
> show collections
posts
users
whatcouldthisbes
```

find

```sh
> db.users.find()
```

```sh
> db.users.find().pretty()
```
