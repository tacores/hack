# Tips

## リモートデスクトップ接続

```shell
xfreerdp /u:<user> /p:<password> /v:<ip>
```

## ファイル共有

Linux の共有フォルダに、Windows からアクセスする

```shell
python3 -m pipx install impacket
```

```shell
# kali側で共有設定。user,passwordはWindows側の認証情報。
$ mkdir share
$ python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username <user> -password <password> public share

# Windows側からコピー
copy <file> \\<ip>\public\
```
