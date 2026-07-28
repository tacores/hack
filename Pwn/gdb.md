# gdb

pwndbg 前提。

## 基本

```shell
gdb <exe-file>

gdb <exe-file> core
```

与えられた ライブラリファイルをロードする方法。  
※下記の場合、precision プログラムファイルを書き換える。（それによって関数アドレスやオフセットがずれる心配は無いらしい）

```sh
patchelf --set-interpreter /home/kali/ctf/tmp/ld-linux-x86-64.so.2 ./precision
patchelf --set-rpath /home/kali/ctf/tmp ./precision
```

```shell
# ブレーク
b main

b *0x000xxx

info address main

info symbol <address>

search <address>

# 逆アセンブリ
disas

# vuln関数を逆アセンブリ
disassemble vuln

# レジスタ
info registers

x/32xb $rsp

x/10 $rsp

x $rbp

# コールスタック
bt

vmmap

vmmap libc

info proc mapping
```

```shell
hexdump <addr> <N-bytes>
```

何十個もまとめてブレークポイントを設定したいとき

```sh
$ head break.gdb
b *0x7ffff7db3e80
b *0x7ffff7dafca0
b *0x7ffff7c28030
b *0x7ffff7d9b930
b *0x7ffff7c28050
b *0x7ffff7da6900
b *0x7ffff7da7110
b *0x7ffff7c28080
b *0x7ffff7d98990
b *0x7ffff7dae680

pwndbg> source break.gdb
```
