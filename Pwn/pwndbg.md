# pwndbg

https://github.com/pwndbg/pwndbg

https://pwndbg.re/CheatSheet.pdf

GDB に直接ロードされる Python モジュール。

```shell
# インストール
cd /home/kali/tools
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# setup.sh が既に追加していたら不要。
# gdb起動時に自動的にロードする
echo 'source /home/kali/tools/pwndbg/gdbinit.py' >> /home/kali/.gdbinit
```

setup.sh でバージョン不整合が発生する場合、追加で実行する。（エラーメッセージを確認して）

```sh
sudo apt install python3.14-venv
```
