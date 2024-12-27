# NFS (Network File System)

### 共有一覧表示

```shell
showmount -e $TARGET
```

### マウント

```shell
mkdir /tmp/mount
sudo mount -t nfs $TARGET:/<:share> /tmp/mount/ -nolock
```

### no_root_squash

設定されていたら、その中のコマンドに SUID を付けることができる

```shell
cat /etc/exports
```
