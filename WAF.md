# Web Application Firewall

https://tryhackme.com/room/wafintroduction

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
