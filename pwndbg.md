# pwndbg

https://github.com/pwndbg/pwndbg

https://pwndbg.re/CheatSheet.pdf

GDB に直接ロードされる Python モジュール。

```shell
# インストール
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# gdb起動時に自動的にロードする
echo 'source /home/kali/Downloads/pwndbg/gdbinit.py' >> /home/kali/.gdbinit
```
