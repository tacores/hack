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
# helloという文字列を引数として渡す
run hello
starti hello

# 標準入力からリダイレクト
run < /path/to/input

# ブレーク
b main

b *0x000xxx

# 関数やラベルを一覧表示
info functions

info address main

info symbol <address>

search <address>

# intel構文で逆アセンブリ
set disassembly-flavor intel
disas

# vuln関数を逆アセンブリ
disassemble vuln

# レジスタ
info registers

print $rdi

set $rax = 42

# コールスタック
bt

vmmap

vmmap libc

info proc mapping
```

## メモリ表示

### xコマンド

```sh
x コマンドの構文：x/nfu <address>

n : 表示する個数
f : 表示フォーマット（下表）
u : データサイズ（b, h, w, g）
```

| フォーマット | 意味                               | 例          | 用途                                |
| ------ | -------------------------------- | ---------- | --------------------------------- |
| `x`    | 16進数 (Hexadecimal)               | `x/x $rsp` | 最もよく使うメモリ表示                       |
| `d`    | 符号付き10進数 (Signed Decimal)        | `x/d addr` | 整数値の確認                            |
| `u`    | 符号なし10進数 (Unsigned Decimal)      | `x/u addr` | サイズやカウンタなど                        |
| `o`    | 8進数 (Octal)                      | `x/o addr` | Unix系の古いデータ確認                     |
| `t`    | 2進数 (Binary)                     | `x/t addr` | ビットフラグの解析                         |
| `a`    | アドレス表示                           | `x/a addr` | シンボル名付きでアドレス表示                    |
| `c`    | 文字 (Character)                   | `x/c addr` | ASCII文字の確認                        |
| `f`    | 浮動小数点数 (Float)                   | `x/f addr` | float値の表示                         |
| `s`    | C文字列 (String)                    | `x/s addr` | NULL終端文字列の表示                      |
| `i`    | 機械語命令 (Instruction)              | `x/i $rip` | 逆アセンブル表示                          |
| `m`    | メモリタグ (Memory Tag) ※AArch64 MTE等 | `x/m addr` | メモリタグ表示（対応環境のみ） ([Sourceware][1]) |

よく使う例

| コマンド          | 説明                |
| ------------- | ----------------- |
| `x/16gx $rsp` | スタックを64bit値で16個表示 |
| `x/32bx addr` | 32バイトを16進数表示      |
| `x/20i $rip`  | 現在位置から20命令逆アセンブル  |
| `x/s $rdi`    | RDIが指す文字列を表示      |
| `x/8cw addr`  | 文字として8個表示         |
| `x/10dw addr` | 32bit整数を10個表示     |

文字列ポインタの先の文字列を表示する例

```sh
x/s *(char **)($rsp+16)
```

### hexdump

```shell
hexdump <addr> <N-bytes>
```

## tips

何十個もまとめてブレークポイントを設定したいとき

```sh
$ head break.gdb
b *0x7ffff7db3e80
b *0x7ffff7dafca0
b *0x7ffff7c28030
...

pwndbg> source break.gdb
```
