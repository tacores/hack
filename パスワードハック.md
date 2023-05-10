# パスワードハック

## zipファイルのパスワード
### ブルートフォース
`fcrackzip -b -c 'a1' -v -u ./pw.zip`
### ディクショナリ
`fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u ./pw.zip`
## rarファイルのパスワード
`rar2john pw.rar > pw.hash`

`john pw.hash --wordlist /usr/share/wordlists/`

または

`john pw.hash --wordlist /usr/share/wordlists/rockyou.txt`




