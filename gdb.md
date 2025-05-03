# gdb

pwndbg 前提。

## 基本

```shell
gdb <exe-file>

gdb <exe-file> core
```

```shell
# ブレーク
b main

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
```

```shell
hexdump <addr> <N-bytes>
```
