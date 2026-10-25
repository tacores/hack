# Linuxディスクイメージ

## The Sleuth Kit（TSK）mmls, fls, icat

```sh
# パーティションオフセット
mmls image.img
```

```sh
# ファイルシステム内の一覧表示
fls -o [スタートセクタ] image.img

# 再帰的に
fls -o [スタートセクタ] -r image.img
```

```sh
# 特定のディレクトリ階層だけ表示
fls -o 2048 image.img [親ディレクトリのインノード番号]
```

```sh
# ファイル抽出
icat -o [スタートセクタ] image.img [インノード番号] > extracted_access.log
```
