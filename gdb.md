# gdb

## 基本

```shell
gdb <exe-file>
```

```shell
# ブレーク
b main

info address main

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
```
