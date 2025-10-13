# mona

```sh
# 結果を保存するフォルダ設定
!mona config -set workingfolder c:\mona\%p
```

```sh
# モジュール情報
!mona modules
```

```sh
# 2000バイトパターンを生成
!mona pattern_create 2000

# オフセット位置特定
!mona pattern_offset EIP値
```

```sh
# \x00 以外の全バイトを含む配列を生成
!mona bytearray -b "\x00"

# 
!mona compare -f c:\mona\<exe>\bytearray.bin -a ESPの値
```


パターン検索

```sh
# JMP ESP を検索
!mona jmp -r esp -cpb "\x00"

!mona jmp -r eax
!mona jmp -r edi
!mona seh
```


```sh
# 指定モジュールから ROP ガジェットを自動収集
!mona rop -m <モジュール名> -cpb "\x00"

# 5命令以内のガジェットを探す
!mona rop -m "kernel32.dll" -cpb "\x00" -n 5
```

```sh
# スタックの状態
!mona stack

# レジスタ
!mona regs

# ret命令を検索
!mona find -s "\xff\xe4" -m <モジュール>
```
