# strace

tcpdumpによるパケットキャプチャはroot権限が必要だが、straceを使えば自分で実行したプロセスの送受信データは確認できる。

```sh
# 送受信したデータの全体が表示されるように
strace -f -s 65536 -e trace=read,write,sendto,recvfrom <exe-file> 2>./output.txt
```
